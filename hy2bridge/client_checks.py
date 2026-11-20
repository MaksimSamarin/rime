"""Bounded manual payload checks from the panel's direct network location."""
import concurrent.futures
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from .client_probe import xray_probe_binary


CHECK_TIMEOUT = 45
MAX_PENDING = 8
MAX_HISTORY = 500
STAGES = {'configuration', 'route', 'client', 'connect', 'payload'}
ERRORS = {'OSError', 'TimeoutError', 'ValueError', 'SSLError', 'ConnectionRefusedError',
          'ConnectionResetError', 'FileNotFoundError', 'PermissionError', 'ProbeError', 'ProbeDeadline'}


class CheckError(ValueError):
    pass


class StaleCheck(CheckError):
    pass


def unknown_result(target, error):
    try:
        address = str(ipaddress.ip_address(target['expected_ip']))
    except ValueError:
        address = None
    return {'passed': False, 'stage': 'configuration', 'error': error,
            'target_ip': address, 'checked_at': time.time()}


def sanitized_result(value):
    """Return observation fields only, even if an injected runner misbehaves."""
    if not isinstance(value, dict) or type(value.get('passed')) is not bool:
        raise ValueError('Invalid probe result')
    stage = value.get('stage')
    if stage not in STAGES or (value['passed'] and stage != 'payload'):
        raise ValueError('Invalid probe stage')
    address = None if value.get('target_ip') is None and not value['passed'] and stage == 'configuration' else str(ipaddress.ip_address(value['target_ip']))
    checked = value['checked_at']
    if type(checked) not in (int, float) or not time.time() - 120 <= checked <= time.time() + 15:
        raise ValueError('Invalid probe timestamp')
    result = {'passed': value['passed'], 'stage': stage, 'target_ip': address, 'checked_at': checked}
    latency = value.get('latency_ms')
    if type(latency) in (int, float) and 0 <= latency <= 120000:
        result['latency_ms'] = latency
    if not value['passed']:
        result['error'] = value.get('error') if value.get('error') in ERRORS else 'ProbeError'
    return result


class ClientChecks:
    def __init__(self, store, settings, reachability, managed_target=None, probe_runner=None):
        self.store = store
        self.settings = settings
        self.reachability = reachability
        self.managed_target = managed_target
        self.probe_runner = probe_runner or self._probe
        self.lock = threading.RLock()
        self.pending = {}
        self.children = set()
        self.closed = False
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix='client-check')
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_client_checks(
                id TEXT PRIMARY KEY,node TEXT NOT NULL,state TEXT NOT NULL,source TEXT NOT NULL,
                requested_at REAL NOT NULL,started_at REAL,completed_at REAL,result TEXT NOT NULL DEFAULT '{}',
                target TEXT NOT NULL DEFAULT '{}')''')
            if 'target' not in {row['name'] for row in db.execute('PRAGMA table_info(fleet_client_checks)')}:
                db.execute("ALTER TABLE fleet_client_checks ADD COLUMN target TEXT NOT NULL DEFAULT '{}'")
            db.execute('CREATE INDEX IF NOT EXISTS fleet_client_checks_time ON fleet_client_checks(requested_at)')
            db.execute('''UPDATE fleet_client_checks SET state='failed',completed_at=?,result=?
                          WHERE state IN ('queued','running')''',
                       (time.time(), json.dumps({'error': 'ControllerRestarted', 'stage': 'configuration'})))
            db.execute('CREATE TABLE IF NOT EXISTS fleet_client_check_generation(node TEXT PRIMARY KEY,version TEXT NOT NULL)')
            tables = {row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table, changed, aliases in [
                ('fleet_inventory', 'address,protocol,enabled', ['{row}.id']),
                ('nodes', 'address,port,api_port', ["'xray:'||{row}.id"]),
                ('fleet_managed', 'domain,port,protocol,native_id,active', ['{row}.id', "'xray:'||{row}.native_id"]),
            ]:
                if table not in tables:
                    continue
                for operation, row in [('INSERT', 'NEW'), ('UPDATE OF ' + changed, 'NEW'), ('DELETE', 'OLD')]:
                    event = operation.split()[0].lower()
                    expressions = [expression.format(row=row) for expression in aliases]
                    body = ''.join('INSERT INTO fleet_client_check_generation SELECT ' + expression +
                                   ",lower(hex(randomblob(16))) WHERE " + expression + ' IS NOT NULL '
                                   'ON CONFLICT(node) DO UPDATE SET version=excluded.version;' for expression in expressions)
                    db.execute(f'CREATE TRIGGER IF NOT EXISTS fleet_manual_{table}_{event} AFTER {operation} ON {table} BEGIN {body} END')
            self._prune(db)

    @staticmethod
    def _prune(db):
        db.execute("DELETE FROM fleet_client_checks WHERE state NOT IN ('queued','running') AND (requested_at<? OR id IN (SELECT id FROM fleet_client_checks WHERE state NOT IN ('queued','running') ORDER BY requested_at DESC LIMIT -1 OFFSET ?))",
                   (time.time() - 7 * 86400, MAX_HISTORY))
        tables = {row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        alive = ['SELECT id FROM fleet_inventory']
        if 'nodes' in tables:
            alive.append("SELECT 'xray:'||id FROM nodes")
        if 'fleet_managed' in tables:
            alive.extend(['SELECT id FROM fleet_managed', "SELECT 'xray:'||native_id FROM fleet_managed WHERE native_id IS NOT NULL"])
        db.execute('DELETE FROM fleet_client_check_generation WHERE node NOT IN (' + ' UNION '.join(alive) + ')')

    def _prepare(self, node, db):
        tables = {row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'fleet_node_transfers' in tables and db.execute("SELECT 1 FROM fleet_node_transfers WHERE node=? AND state='switched'",(node,)).fetchone():
            raise CheckError('Дождитесь завершения переноса ноды')
        native = node.startswith('xray:') and node[5:].isdigit()
        row = db.execute('SELECT * FROM nodes WHERE id=?', (int(node[5:]),)).fetchone() if native and 'nodes' in tables else (
            db.execute('SELECT * FROM fleet_inventory WHERE id=?', (node,)).fetchone())
        if row is None:
            raise CheckError('Нода не найдена')
        registration = {key: row[key] for key in ('id', 'address', 'port', 'api_port', 'protocol', 'enabled', 'created_at') if key in row.keys()}
        managed = db.execute("SELECT * FROM fleet_managed WHERE id=? OR 'xray:'||native_id=?", (node, node)).fetchone() if 'fleet_managed' in tables else None
        generation = db.execute('SELECT version FROM fleet_client_check_generation WHERE node=?', (node,)).fetchone()
        if managed:
            if not managed['active'] or self.managed_target is None:
                raise CheckError('Клиентская проверка этой ноды ещё не настроена')
            data = {'protocol': managed['protocol'], 'domain': managed['domain'], 'vpn_port': managed['port'],
                    'host': row['address'], 'address': row['address']}
            try:target = self.managed_target(managed['id'], data)
            except ValueError as error:raise CheckError(str(error)) from None
            if target.get('node') != node:
                raise CheckError('Регистрация клиентской проверки не совпадает с нодой')
            source = {'id': 'panel-managed', 'origin': self.settings.get('probe_origin', 'Сервер панели')}
            settings = {'direct_targets': [target['expected_ip']]}
        else:
            path = Path(self.settings.get('client_probe_config', '/run/rime/client-probe.json'))
            try:
                raw = path.read_bytes()
                if len(raw) > 1024 * 1024:
                    raise ValueError('Oversized config')
                config = json.loads(raw)
                if config['id'] != self.settings.get('client_probe_id', 'matryoshka-rf'):
                    raise ValueError('Unexpected probe origin')
                entry = self.reachability.entries[config['id']]
                targets = [target for target in config['targets'] if target.get('node') == node]
                if len(targets) != 1 or node not in entry['nodes']:
                    raise ValueError('Missing fixed target')
                target = targets[0]
                expected = str(ipaddress.ip_address(target['expected_ip']))
                if expected not in config['direct_targets']:
                    raise ValueError('Unverified fixed target')
                source = {'id': config['id'], 'origin': entry['label']}
                settings = {'direct_targets': [expected]}
            except (OSError, ValueError, KeyError, TypeError):
                raise CheckError('Прямая клиентская проверка этой ноды не настроена') from None
        settings.update(xray_binary=xray_probe_binary(self.settings),
                        hysteria_binary=self.settings.get('hysteria_binary', '/var/lib/marzban/provision/hysteria-fleet'))
        if not isinstance(target.get('config'), dict) or not isinstance(target['config'].get('_hostname'), str) or not target['config']['_hostname']:
            raise CheckError('Настройки клиентской проверки повреждены')
        fingerprint = hashlib.sha256(json.dumps({'registration': registration, 'generation': generation['version'] if generation else None,
                                                 'managed': dict(managed) if managed else None, 'target': target, 'settings': settings,
                                                 'source': source}, sort_keys=True).encode()).hexdigest()
        return {'target': copy.deepcopy(target), 'settings': settings, 'source': source,
                'public_target': {'host': target['config']['_hostname'], 'expected_ip': target['expected_ip']},
                'fingerprint': fingerprint, 'managed_job': managed['id'] if managed else None}

    def request(self, node):
        with self.lock:
            if self.closed:
                raise CheckError('Сервис проверок останавливается')
            if node in self.pending:
                current = self.status(self.pending[node])
                if current['state'] in ('queued', 'running'):
                    return current
                self.pending.pop(node)
            if len(self.pending) >= MAX_PENDING:
                raise CheckError('Все места проверки заняты. Повторите позже')
            with self.store.connection(write=True) as db:
                payload = self._prepare(node, db)
                ident = uuid.uuid4().hex
                db.execute('INSERT INTO fleet_client_checks(id,node,state,source,requested_at,target) VALUES(?,?,?,?,?,?)',
                           (ident, node, 'queued', json.dumps(payload['source']), time.time(), json.dumps(payload['public_target'])))
                self._prune(db)
            self.pending[node] = ident
            self.pool.submit(self._run, ident, node, payload)
            return self.status(ident)

    def status(self, ident):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM fleet_client_checks WHERE id=?', (ident,)).fetchone()
        if row is None:
            raise CheckError('Проверка не найдена')
        return {**dict(row), 'source': json.loads(row['source']), 'result': json.loads(row['result']),
                'target': json.loads(row['target'])}

    def _guard(self, node, payload, db):
        if self.closed:
            raise StaleCheck('Controller is stopping')
        try:
            current = self._prepare(node, db)
        except Exception:
            raise StaleCheck('Registration was removed or changed') from None
        if current['fingerprint'] != payload['fingerprint']:
            raise StaleCheck('Registration was removed or changed')

    def _run(self, ident, node, payload):
        state = 'failed'
        result = {'stage': 'configuration', 'error': 'ProbeError'}
        try:
            with self.store.connection(write=True) as db:
                self._guard(node, payload, db)
                db.execute("UPDATE fleet_client_checks SET state='running',started_at=? WHERE id=?", (time.time(), ident))
            try:
                result = sanitized_result(self.probe_runner(payload['target'], payload['settings'], CHECK_TIMEOUT))
                expected = payload['target']['expected_ip']
                try:
                    pinned = str(ipaddress.ip_address(expected))
                except ValueError:
                    pinned = None
                if result['passed'] and pinned is not None and result['target_ip'] != pinned:
                    raise ValueError('Successful result used a different target')
            except Exception:
                result = unknown_result(payload['target'], 'ProbeError')
            guard = lambda db: self._guard(node, payload, db)
            if payload['managed_job']:
                self.reachability.ingest_local(node, result, payload['source']['origin'], guard=guard, job=payload['managed_job'])
            else:
                self.reachability.ingest(payload['source']['id'], node, result, guard=guard)
            state = 'passed' if result['passed'] else 'failed'
        except StaleCheck:
            state = 'stale'
            result = {'stage': 'configuration', 'error': 'ControllerStopped' if self.closed else 'RegistrationChanged'}
        except Exception:
            result = {'stage': 'configuration', 'error': 'ProbeError'}
        finally:
            try:
                with self.store.connection(write=True) as db:
                    db.execute('UPDATE fleet_client_checks SET state=?,completed_at=?,result=? WHERE id=?',
                               (state, time.time(), json.dumps(result), ident))
            finally:
                with self.lock:
                    if self.pending.get(node) == ident:
                        self.pending.pop(node)

    def _probe(self, target, settings, timeout):
        env = {key: value for key, value in os.environ.items()
               if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy')}
        env.update(NO_PROXY='*', no_proxy='*')
        # The parent owns this directory, so a killed child cannot leave keys.
        with tempfile.TemporaryDirectory(prefix='rime-client-check-') as folder:
            env['TMPDIR'] = folder
            process = subprocess.Popen([sys.executable, '-m', 'hy2bridge.client_checks', '--probe-child'],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       text=True, env=env, start_new_session=True)
            with self.lock:
                self.children.add(process)
                if self.closed:
                    self._terminate(process)
            try:
                try:
                    output, _ = process.communicate(json.dumps({'target': target, 'settings': settings}), timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._terminate(process)
                    try:
                        process.communicate(timeout=4)
                    except subprocess.TimeoutExpired:
                        self._terminate(process, force=True)
                        process.communicate()
                    return {**unknown_result(target, 'ProbeDeadline'), 'latency_ms': timeout * 1000}
                if process.returncode != 0 or len(output) > 4096:
                    raise ValueError('Probe process failed')
                return json.loads(output)
            finally:
                with self.lock:
                    self.children.discard(process)

    @staticmethod
    def _terminate(process, force=False):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
            except ProcessLookupError:
                pass

    def close(self):
        with self.lock:
            self.closed = True
            for process in self.children:
                self._terminate(process)
            self.pool.shutdown(wait=False, cancel_futures=True)
            with self.store.connection(write=True) as db:
                db.execute('''UPDATE fleet_client_checks SET state='failed',completed_at=?,result=?
                              WHERE state IN ('queued','running')''',
                           (time.time(), json.dumps({'error': 'ControllerStopped', 'stage': 'configuration'})))


def install(app, store, settings, reachability, managed_target=None):
    from fastapi import Body, Depends, HTTPException, Response
    from app.models.admin import Admin

    checks = ClientChecks(store, settings, reachability, managed_target)
    app.state.fleet_client_checks = checks
    app.add_event_handler('shutdown', checks.close)

    @app.post('/api/fleet/nodes/{node}/client-check', tags=['Fleet'])
    def request(node: str, response: Response, payload: dict | None = Body(None),
                admin: Admin = Depends(Admin.check_sudo_admin)):
        response.headers['Cache-Control'] = 'no-store'
        if payload:
            raise HTTPException(422, 'Адрес и параметры проверки задаются конфигурацией ноды')
        try:
            return checks.request(node)
        except CheckError as error:
            raise HTTPException(409, str(error)) from None

    @app.get('/api/fleet/client-checks/{ident}', tags=['Fleet'])
    def status(ident: str, response: Response, admin: Admin = Depends(Admin.check_sudo_admin)):
        response.headers['Cache-Control'] = 'no-store'
        try:
            return checks.status(ident)
        except CheckError as error:
            raise HTTPException(404, str(error)) from None

    return checks


def probe_child():
    from .client_probe import probe

    def interrupted(*_):
        # Bypass probe's network-error handlers while executing its finally.
        raise SystemExit(1)
    signal.signal(signal.SIGTERM, interrupted)
    raw = sys.stdin.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Oversized probe request')
    payload = json.loads(raw)
    target, settings = payload['target'], payload['settings']
    try:
        address = str(ipaddress.ip_address(target['expected_ip']))
    except ValueError:
        address = socket.getaddrinfo(target['expected_ip'], None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    target['expected_ip'] = address
    settings['direct_targets'] = [address]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    print(json.dumps(sanitized_result(probe(target, settings, port))))


if __name__ == '__main__' and sys.argv[1:] == ['--probe-child']:
    probe_child()
