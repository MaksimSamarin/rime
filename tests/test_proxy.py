import json
from pathlib import Path
import time
import unittest
from unittest.mock import MagicMock, patch

import bcrypt
from pydantic import ValidationError
import test_accounting

from hy2bridge.operations import Operations
from hy2bridge.provision import Provisioner, ProvisionError
from hy2bridge.proxy_install import main as install_proxy
from hy2bridge.proxy_probe import read_headers
from hy2bridge.proxy_service import ProxyRequest, ProxyService, squid_configuration


class ProxyTests(unittest.TestCase):
    setUp = test_accounting.AccountingTests.setUp
    tearDown = test_accounting.AccountingTests.tearDown

    def configure(self):
        operations = Operations(self.store)
        operations.ensure_node('test-node', address='node.lab.invalid')
        bundle = Path(self.tmp.name) / 'image.tar.gz'
        bundle.write_bytes(b'synthetic-image')
        settings = {'allowed_hosts': ['node.lab.invalid'], 'proxy': {
            'image': 'sha256:' + '1' * 64, 'image_bundle': str(bundle), 'image_bundle_sha256': '2' * 64}}
        provision = Provisioner(self.store, settings, None, None, None)
        provision.resolve = MagicMock(return_value=['8.8.8.8'])
        return ProxyService(self.store, provision)

    def request(self, **changes):
        values = {'node': 'test-node', 'host': 'node.lab.invalid', 'username': 'root', 'ssh_port': 22,
                  'password': 'synthetic-ssh-secret', 'fingerprint': 'SHA256:' + 'a' * 43,
                  'http_port': 3128, 'https_port': None, 'proxy_username': 'proxy_user',
                  'proxy_password': 'synthetic-proxy-secret'}
        values.update(changes)
        return ProxyRequest(**values).model_dump()

    def test_modes_ports_and_bcrypt_length_are_validated(self):
        for changes in [{'http_port': None}, {'https_port': 3128}, {'http_port': True},
                        {'proxy_username': 'user:other'}, {'proxy_username': 'user\nother'},
                        {'proxy_password': 'short'}, {'proxy_password': 'x\ny' * 8},
                        {'proxy_password': 'я' * 40}]:
            with self.subTest(changes=changes):
                with self.assertRaises(ValidationError):
                    self.request(**changes)

    def test_header_progress_cannot_extend_probe_deadline(self):
        connection = MagicMock()
        connection.recv.return_value = b'x'
        with patch('hy2bridge.proxy_probe.time.monotonic', side_effect=[0, 1, 3]):
            with self.assertRaises(TimeoutError):
                read_headers(connection, deadline=2)
        self.assertEqual(connection.recv.call_count, 2)

    def test_squid_requires_auth_and_disables_traffic_logging(self):
        data = self.request(https_port=8443)
        config = squid_configuration(data, {})
        self.assertIn('http_access deny !authenticated', config)
        self.assertTrue(config.rstrip().endswith('https_port 8443 tls-cert=/state/cert.pem tls-key=/state/key.pem'))
        self.assertIn('http_access deny private_dst', config)
        self.assertIn('http_access deny all', config)
        self.assertIn('access_log none', config)
        self.assertIn('cache deny all', config)
        self.assertIn('forwarded_for delete', config)
        self.assertIn('via off', config)
        self.assertNotIn('synthetic-proxy-secret', config)

    def test_lab_destination_exception_is_configuration_only(self):
        config = squid_configuration(self.request(), {'lab_destinations': ['172.21.0.12/32']})
        self.assertIn('acl lab_destinations dst 172.21.0.12/32', config)
        self.assertLess(config.index('http_access deny !authenticated'), config.index('http_access allow authenticated lab_destinations'))
        with self.assertRaises(ValueError):
            squid_configuration(self.request(), {'lab_destinations': ['anywhere\nhttp_access allow all']})

    def test_new_proxy_cannot_target_a_different_server(self):
        service = self.configure()
        service.provision.resolve.side_effect = [['8.8.8.8'], ['1.1.1.1']]
        with self.assertRaises(ProvisionError):
            service.validate(self.request())

    def test_panel_role_is_rejected(self):
        service = self.configure()
        with self.assertRaises(ProvisionError):
            service.node_host('xray:local')

    def test_configuration_contains_only_password_hash(self):
        service = self.configure()
        data = self.request()
        data['domain'] = '8.8.8.8'
        config, hashed = service.configuration('a' * 32, data)
        self.assertTrue(bcrypt.checkpw(data['proxy_password'].encode(), hashed.encode()))
        self.assertNotIn(data['proxy_password'], json.dumps(config))
        self.assertNotIn(data['password'], json.dumps(config))
        self.assertEqual(config['files']['passwd'], 'proxy_user:' + hashed + '\n')
        self.assertEqual(config['publish'], [(3128, 3128)])

    def test_preflight_and_job_metadata_exclude_credentials(self):
        service = self.configure()
        service.provision.connect = MagicMock()
        service.remote = MagicMock(return_value={'home': '/root', 'checks': [{'passed': True}]})
        runtime = {'python_available': True, 'bootstrap_required': False}
        data = self.request()
        with patch('hy2bridge.proxy_service.bootstrap.inspect', return_value=runtime), patch('threading.Timer'):
            plan = service.preflight(data)
        self.assertTrue(plan['ready'])
        self.assertNotIn(data['password'], json.dumps(plan))
        self.assertNotIn(data['proxy_password'], json.dumps(plan))
        with patch('threading.Thread'):
            service.deploy(plan['id'])
        state = service.job(plan['id'])
        self.assertNotIn(data['password'], json.dumps(state))
        self.assertNotIn(data['proxy_password'], json.dumps(state))
        self.assertEqual(state['context']['proxy_username'], 'proxy_user')

    def test_expired_plan_forgets_both_passwords(self):
        service = self.configure()
        data = self.request()
        service.plans['a' * 32] = {'data': data, 'plan': {'expires_at': time.time() - 1, 'ready': True}}
        with self.assertRaises(ProvisionError):
            service.deploy('a' * 32)
        self.assertEqual(data, {})
        self.assertEqual(service.provision.running, set())

    def test_proxy_and_node_installation_share_the_target_lock(self):
        service = self.configure()
        data = self.request(address='8.8.8.8')
        service.plans['a' * 32] = {'data': data, 'plan': {'expires_at': time.time() + 60, 'ready': True}}
        service.provision.running.add('8.8.8.8')
        with self.assertRaises(ProvisionError):
            service.deploy('a' * 32)
        self.assertIn('a' * 32, service.plans)

    def test_success_publishes_only_after_payload_and_keeps_existing_users(self):
        service = self.configure()
        service.provision.connect = MagicMock()
        service.remote = MagicMock(return_value={'checks': [{'passed': True}], 'running': True})
        service.upload_image = MagicMock()
        service.check = MagicMock(return_value={'passed': True, 'checks': []})
        data = self.request(address='8.8.8.8', domain='8.8.8.8')
        with self.store.connection() as db:
            before = [tuple(row) for row in db.execute('SELECT * FROM users')]
        record = {'data': data, 'plan': {'id': 'a' * 32}, 'remote': {'bootstrap_required': False}}
        service.worker(record)
        self.assertEqual(service.job('a' * 32)['state'], 'succeeded')
        published = service.list('test-node')
        self.assertEqual(len(published), 1)
        self.assertTrue(published[0]['result']['passed'])
        self.assertNotIn('password_hash', published[0])
        self.assertNotIn('synthetic-proxy-secret', json.dumps(published))
        with self.store.connection() as db:
            self.assertEqual(before, [tuple(row) for row in db.execute('SELECT * FROM users')])
        self.assertEqual(data, {})

    def test_failed_payload_removes_only_its_proxy(self):
        service = self.configure()
        service.provision.connect = MagicMock()
        service.remote = MagicMock(return_value={'checks': [{'passed': True}], 'running': True})
        service.upload_image = MagicMock()
        service.check = MagicMock(return_value={'passed': False, 'checks': []})
        data = self.request(address='8.8.8.8', domain='8.8.8.8')
        service.worker({'data': data, 'plan': {'id': 'b' * 32}, 'remote': {'bootstrap_required': False}})
        self.assertEqual(service.job('b' * 32)['state'], 'rolled_back')
        self.assertEqual(service.remote.call_args.args[1], {'id': 'b' * 32, 'action': 'rollback'})
        self.assertEqual(service.list('test-node'), [])

    def test_lost_ssh_rollback_stays_failed_for_explicit_cleanup(self):
        service = self.configure()
        service.provision.connect = MagicMock()
        service.remote = MagicMock(side_effect=[{'checks': [{'passed': True}]}, {'running': True}, RuntimeError('synthetic disconnect')])
        service.upload_image = MagicMock()
        service.check = MagicMock(return_value={'passed': False, 'checks': []})
        data = self.request(address='8.8.8.8', domain='8.8.8.8')
        service.worker({'data': data, 'plan': {'id': 'c' * 32}, 'remote': {'bootstrap_required': False}})
        self.assertEqual(service.job('c' * 32)['state'], 'failed')
        self.assertEqual(service.list('test-node'), [])

    def test_foreign_container_is_never_removed(self):
        foreign = {'Config': {'Labels': {'rime.proxy.job': 'other-job'}}}
        with patch('hy2bridge.proxy_install.inspect_container', return_value=foreign), patch('hy2bridge.proxy_install.command') as command:
            with self.assertRaises(RuntimeError):
                install_proxy({'id': 'd' * 32, 'action': 'rollback'})
            command.assert_not_called()

    def test_proxy_history_pruning_preserves_running_jobs(self):
        service = self.configure()
        for job, state in [('a' * 32, 'running'), ('b' * 32, 'rolled_back'), ('c' * 32,'failed'),('d'*32,'succeeded')]:
            service.update(job, 'test-node', state, 'synthetic')
        with self.store.connection(write=True) as db:
            db.execute('UPDATE fleet_proxy_jobs SET created_at=?', (time.time() - 100 * 86400,))
        service.prune()
        self.assertEqual(service.job('a' * 32)['state'], 'running')
        self.assertEqual(service.job('c' * 32)['state'], 'failed')
        with self.assertRaises(ProvisionError):
            service.job('b' * 32)
        with self.assertRaises(ProvisionError):
            service.job('d' * 32)

    def test_reused_inventory_id_gets_a_different_generation(self):
        service = self.configure()
        _, before = service.node_identity('test-node')
        with self.store.connection(write=True) as db:
            old = dict(db.execute("SELECT * FROM fleet_inventory WHERE id='test-node'").fetchone())
            db.execute("DELETE FROM fleet_inventory WHERE id='test-node'")
            db.execute('INSERT INTO fleet_inventory VALUES(?,?,?,?,?,?)', tuple(old.values()))
        _, after = service.node_identity('test-node')
        self.assertNotEqual(before, after)

    def test_reused_native_id_gets_a_different_generation(self):
        with self.store.connection(write=True) as db:
            db.execute('CREATE TABLE nodes(id INTEGER PRIMARY KEY,address TEXT,created_at TEXT)')
            db.execute("INSERT INTO nodes VALUES(7,'8.8.8.8','2026-11-06 00:00:00')")
        service = self.configure()
        _, before = service.node_identity('xray:7')
        with self.store.connection(write=True) as db:
            db.execute('DELETE FROM nodes WHERE id=7')
            db.execute("INSERT INTO nodes VALUES(7,'8.8.8.8','2026-11-06 00:00:00')")
        _, after = service.node_identity('xray:7')
        self.assertNotEqual(before, after)

    def test_changed_generation_during_payload_cannot_publish(self):
        service = self.configure()
        service.provision.connect = MagicMock()
        service.remote = MagicMock(return_value={'checks': [{'passed': True}], 'running': True})
        service.upload_image = MagicMock()

        def replace_node(_):
            with self.store.connection(write=True) as db:
                db.execute("UPDATE fleet_inventory SET created_at=created_at+1 WHERE id='test-node'")
            return {'passed': True, 'checks': []}

        service.check = replace_node
        service.worker({'data': self.request(address='8.8.8.8', domain='8.8.8.8'),
                        'plan': {'id': 'f' * 32}, 'remote': {'bootstrap_required': False}})
        self.assertEqual(service.job('f' * 32)['state'], 'rolled_back')
        self.assertEqual(service.remote.call_args.args[1], {'id': 'f' * 32, 'action': 'rollback'})
        self.assertEqual(service.list('test-node'), [])

    def test_stale_failed_attempt_cannot_clean_a_new_node(self):
        service = self.configure()
        data = self.request(cleanup_job='a' * 32)
        service.validate(data)
        context = {key: data[key] for key in ['node', 'host', 'ssh_port', 'username']}
        context['node_generation'] = data['_node_generation']
        service.update('a' * 32, 'test-node', 'failed', 'synthetic', context)
        with self.store.connection(write=True) as db:
            db.execute("UPDATE fleet_inventory SET created_at=created_at+1 WHERE id='test-node'")
        service.provision.connect = MagicMock()
        with self.assertRaises(ProvisionError):
            service.preflight(self.request(cleanup_job='a' * 32))
        service.provision.connect.assert_not_called()

    def test_rollback_removes_partial_transfer_without_container(self):
        directory = Path(self.tmp.name) / ('a' * 32)
        bundle = directory.parent / ('a' * 32 + '.image.tar.gz')
        unrelated = directory.parent / 'unrelated.image.tar.gz'
        bundle.write_bytes(b'partial-transfer')
        unrelated.write_bytes(b'retain')
        with patch('hy2bridge.proxy_install.paths', return_value=(directory, 'synthetic-container')), \
                patch('hy2bridge.proxy_install.inspect_container', return_value=None), \
                patch('hy2bridge.proxy_install.command') as command:
            result = install_proxy({'id': 'a' * 32, 'action': 'rollback'})
        command.assert_not_called()
        self.assertFalse(bundle.exists())
        self.assertTrue(unrelated.exists())
        self.assertFalse(result['removed'])

    def test_stale_service_is_visible_but_cannot_be_checked(self):
        service = self.configure()
        service.provision.connect = MagicMock()
        service.remote = MagicMock(return_value={'checks': [{'passed': True}], 'running': True})
        service.upload_image = MagicMock()
        service.check = MagicMock(return_value={'passed': True, 'checks': []})
        data = self.request(address='8.8.8.8', domain='8.8.8.8')
        service.worker({'data': data, 'plan': {'id': 'e' * 32}, 'remote': {'bootstrap_required': False}})
        with self.store.connection(write=True) as db:
            db.execute("UPDATE fleet_inventory SET created_at=created_at+1 WHERE id='test-node'")
        self.assertTrue(service.list('test-node')[0]['stale'])
        service.check.reset_mock()
        with self.assertRaises(ProvisionError):
            service.recheck('e' * 32, 'synthetic-proxy-secret')
        service.check.assert_not_called()
