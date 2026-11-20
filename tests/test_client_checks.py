import asyncio
import json
from pathlib import Path
import subprocess
import threading
import time
import types
import unittest
from unittest.mock import patch

import test_accounting
from hy2bridge.client_checks import ClientChecks, CheckError, sanitized_result
from hy2bridge.operations import Operations
from hy2bridge.reachability import Reachability
from hy2bridge.registry import Registry


class ClientCheckTests(unittest.TestCase):
    def setUp(self):
        test_accounting.AccountingTests.setUp(self)
        self.ops = Operations(self.store)
        self.nodes = ['n' + str(index) for index in range(10)]
        for node in self.nodes:
            self.ops.ensure_node(node, address='198.51.100.9')
        Registry(self.store)
        self.reachability = Reachability(self.store, [
            {'id': 'matryoshka-rf', 'label': 'Matryoshka (РФ)', 'nodes': self.nodes, 'token': 's' * 32}])
        self.config = Path(self.tmp.name) / 'client.json'
        self.config.write_text(json.dumps({'id': 'matryoshka-rf', 'token': 'hidden-panel-token',
            'direct_targets': ['192.0.2.1'], 'targets': [self.target(node) for node in self.nodes]}))
        self.settings = {'client_probe_config': str(self.config), 'probe_origin': 'Matryoshka (РФ)'}
        self.instances = []
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()
        for instance in self.instances:
            instance.close()
            instance.pool.shutdown(wait=True)
        test_accounting.AccountingTests.tearDown(self)

    @staticmethod
    def target(node):
        return {'node': node, 'expected_ip': '192.0.2.1',
                'config': {'_hostname': 'fixed.lab.invalid', 'uuid': 'hidden-user-uuid'}}

    @staticmethod
    def observation(passed=True, stage='payload'):
        return {'passed': passed, 'stage': stage, 'checked_at': time.time(),
                'target_ip': '192.0.2.1', 'latency_ms': 12, 'error': 'OSError'}

    def create(self, runner=None, managed=None):
        instance = ClientChecks(self.store, self.settings, self.reachability, managed,
                                runner or (lambda *_: self.observation()))
        self.instances.append(instance)
        return instance

    def finished(self, checks, ident):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            value = checks.status(ident)
            if value['state'] not in ('queued', 'running'):
                return value
            time.sleep(.01)
        self.fail('Check did not complete')

    def test_static_target_is_preserved_and_results_never_return_credentials(self):
        received = []
        def runner(target, settings, timeout):
            received.append((target, settings, timeout))
            return {**self.observation(), 'config': target['config'], 'token': 'hidden-panel-token'}
        checks = self.create(runner)
        result = self.finished(checks, checks.request('n1')['id'])
        self.assertEqual(result['state'], 'passed')
        self.assertEqual(result['source'], {'id': 'matryoshka-rf', 'origin': 'Matryoshka (РФ)'})
        self.assertEqual(received[0][0]['expected_ip'], '192.0.2.1')
        self.assertEqual(received[0][1]['direct_targets'], ['192.0.2.1'])
        self.assertNotIn('hidden', json.dumps(result))
        self.assertEqual(result['target']['expected_ip'], '192.0.2.1')

    def test_failure_opens_incident_and_real_recovery_closes_it(self):
        failed = [True]
        checks = self.create(lambda *_: self.observation(not failed[0], 'connect' if failed[0] else 'payload'))
        first = self.finished(checks, checks.request('n1')['id'])
        self.assertEqual(first['state'], 'failed')
        with self.store.connection() as db:
            self.assertIsNone(db.execute("SELECT resolved_at FROM fleet_events WHERE code='client_unreachable'").fetchone()[0])
        failed[0] = False
        self.assertEqual(self.finished(checks, checks.request('n1')['id'])['state'], 'passed')
        with self.store.connection() as db:
            self.assertIsNotNone(db.execute("SELECT resolved_at FROM fleet_events WHERE code='client_unreachable'").fetchone()[0])

    def test_changed_or_recreated_registration_cannot_publish_old_green(self):
        started = threading.Event()
        def runner(*_):
            started.set()
            self.release.wait(3)
            return self.observation()
        checks = self.create(runner)
        job = checks.request('n1')
        self.assertTrue(started.wait(2))
        with self.store.connection(write=True) as db:
            db.execute("DELETE FROM fleet_inventory WHERE id='n1'")
        self.ops.ensure_node('n1', address='198.51.100.9')
        self.release.set()
        self.assertEqual(self.finished(checks, job['id'])['state'], 'stale')
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM fleet_client_probes').fetchone()[0], 0)

    def test_modified_probe_credentials_or_scope_invalidate_inflight_job(self):
        started = threading.Event()
        def runner(*_):
            started.set()
            self.release.wait(3)
            return self.observation()
        checks = self.create(runner)
        job = checks.request('n1')
        self.assertTrue(started.wait(2))
        config = json.loads(self.config.read_text())
        config['targets'][1]['config']['uuid'] = 'replacement-uuid'
        self.config.write_text(json.dumps(config))
        self.release.set()
        self.assertEqual(self.finished(checks, job['id'])['state'], 'stale')

    def test_native_resource_observer_node_uses_real_client_check(self):
        with self.store.connection(write=True) as db:
            db.executescript('''CREATE TABLE nodes(id INTEGER PRIMARY KEY,address TEXT,port INTEGER,api_port INTEGER);
                                INSERT INTO nodes VALUES(1,'198.51.100.9',62050,62051);''')
        self.reachability.entries['matryoshka-rf']['nodes'].append('xray:1')
        config = json.loads(self.config.read_text())
        config['targets'].append(self.target('xray:1'))
        self.config.write_text(json.dumps(config))
        checks = self.create()
        self.assertEqual(self.finished(checks, checks.request('xray:1')['id'])['state'], 'passed')
        with self.store.connection() as db:
            self.assertEqual(self.reachability.summary(db, 'xray:1')['state'], 'available')

    def test_coalescing_bounded_queue_and_two_workers(self):
        count = [0, 0]
        lock = threading.Lock()
        both_started = threading.Event()
        def runner(*_):
            with lock:
                count[0] += 1
                count[1] = max(count)
                if count[0] == 2:
                    both_started.set()
            self.release.wait(3)
            with lock:
                count[0] -= 1
            return self.observation()
        checks = self.create(runner)
        job = checks.request('n0')
        self.assertEqual(checks.request('n0')['id'], job['id'])
        for node in self.nodes[1:8]:
            checks.request(node)
        with self.assertRaises(CheckError):
            checks.request('n8')
        self.assertTrue(both_started.wait(2))
        self.release.set()
        self.finished(checks, job['id'])
        checks.pool.shutdown(wait=True)
        self.assertEqual(count[1], 2)

    def test_deadline_replaces_old_green_with_unknown_without_false_incident(self):
        expired = [False]
        def runner(*_):
            if expired[0]:
                return {**self.observation(False, 'configuration'), 'target_ip': None, 'error': 'ProbeDeadline'}
            return self.observation()
        checks = self.create(runner)
        self.finished(checks, checks.request('n1')['id'])
        expired[0] = True
        self.assertEqual(self.finished(checks, checks.request('n1')['id'])['result']['error'], 'ProbeDeadline')
        with self.store.connection() as db:
            self.assertEqual(self.reachability.summary(db, 'n1')['state'], 'unknown')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM fleet_events').fetchone()[0], 0)

    def test_managed_callback_uses_trusted_registration_and_strict_owner(self):
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_managed(id,protocol,name,domain,port,active) VALUES('n1','hysteria2','lab','fixed.lab.invalid',443,1)")
        called = []
        def managed(job, data):
            called.append((job, data))
            return self.target('n1')
        checks = self.create(managed=managed)
        self.assertEqual(self.finished(checks, checks.request('n1')['id'])['state'], 'passed')
        self.assertEqual(called[0][0], 'n1')
        self.assertEqual(called[0][1]['address'], '198.51.100.9')
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT probe FROM fleet_client_probes').fetchone()[0], 'panel-managed')

    def test_unconfigured_or_unknown_node_has_no_arbitrary_target_fallback(self):
        checks = self.create()
        with self.assertRaises(CheckError):
            checks.request('unknown')
        self.config.unlink()
        with self.assertRaises(CheckError):
            checks.request('n1')

    def test_wrong_target_or_runner_failure_replaces_old_success_with_unknown(self):
        mode = ['ok']
        def runner(*_):
            if mode[0] == 'error':
                raise RuntimeError('hidden-user-uuid')
            value = self.observation()
            if mode[0] == 'wrong-target':
                value['target_ip'] = '192.0.2.2'
            return value
        checks = self.create(runner)
        self.finished(checks, checks.request('n1')['id'])
        for current in ['wrong-target', 'error']:
            mode[0] = current
            job = self.finished(checks, checks.request('n1')['id'])
            self.assertEqual(job['state'], 'failed')
            self.assertNotIn('hidden', json.dumps(job))
            with self.store.connection() as db:
                self.assertEqual(self.reachability.summary(db, 'n1')['state'], 'unknown')

    def test_subprocess_deadline_kills_group_and_removes_parent_owned_private_tmp(self):
        checks = self.create()
        locations = []
        class Process:
            pid = 12345
            returncode = None
            calls = 0
            def poll(self):
                return None
            def communicate(self, *args, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired('synthetic', 1)
                return '', ''
        def opened(*args, **kwargs):
            folder = Path(kwargs['env']['TMPDIR'])
            locations.append(folder)
            (folder / 'synthetic-credentials').write_text('hidden-user-uuid')
            return Process()
        with patch('hy2bridge.client_checks.subprocess.Popen', opened), patch('hy2bridge.client_checks.os.killpg', create=True) as killed, patch('hy2bridge.client_checks.signal.SIGKILL', 9, create=True):
            value = checks._probe(self.target('n1'), {}, 1)
        self.assertEqual(value['error'], 'ProbeDeadline')
        self.assertTrue(killed.called)
        self.assertFalse(locations[0].exists())

    def test_invalid_success_or_unknown_error_text_cannot_escape_sanitizer(self):
        with self.assertRaises(ValueError):
            sanitized_result(self.observation(True, 'connect'))
        value = sanitized_result({**self.observation(False), 'error': 'hidden-user-uuid'})
        self.assertEqual(value['error'], 'ProbeError')

    def test_api_requires_sudo_for_start_and_job_status(self):
        from fastapi import FastAPI, Header, HTTPException
        from hy2bridge.client_checks import install
        def sudo(authorization: str | None = Header(None)):
            if authorization != 'Bearer synthetic-sudo':
                raise HTTPException(403, 'Forbidden')
            return object()
        module = types.ModuleType('app.models.admin')
        module.Admin = types.SimpleNamespace(check_sudo_admin=sudo)
        app = FastAPI()
        with patch.dict('sys.modules', {'app.models.admin': module}):
            checks = install(app, self.store, self.settings, self.reachability)
        self.instances.append(checks)
        checks.probe_runner = lambda *_: self.observation()
        def request(path, method='GET', authorized=False, payload=None):
            async def execute():
                messages = []
                async def receive():
                    return {'type': 'http.request', 'body': json.dumps(payload).encode() if payload is not None else b'', 'more_body': False}
                async def send(value):
                    messages.append(value)
                headers = [(b'authorization', b'Bearer synthetic-sudo')] if authorized else []
                if payload is not None:
                    headers.append((b'content-type', b'application/json'))
                await app({'type': 'http', 'http_version': '1.1', 'method': method, 'path': path,
                           'scheme': 'http', 'query_string': b'', 'root_path': '', 'headers': headers}, receive, send)
                return messages
            messages = asyncio.run(execute())
            return messages[0]['status'], dict(messages[0]['headers']), json.loads(b''.join(value.get('body', b'') for value in messages[1:]))
        self.assertEqual(request('/api/fleet/nodes/n1/client-check', 'POST')[0], 403)
        self.assertEqual(request('/api/fleet/client-checks/unknown')[0], 403)
        self.assertEqual(request('/api/fleet/nodes/n1/client-check', 'POST', True, {'host': 'untrusted.invalid'})[0], 422)
        status, headers, response = request('/api/fleet/nodes/n1/client-check', 'POST', True)
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.finished(checks, response['id'])
        self.assertEqual(request('/api/fleet/client-checks/' + response['id'], authorized=True)[0], 200)
