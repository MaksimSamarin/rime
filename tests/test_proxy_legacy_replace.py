from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import test_accounting
import test_proxy
from hy2bridge.proxy_install import legacy_commit, legacy_profile, legacy_restore, legacy_stop, legacy_unit, qualify_legacy_hash, RemoteError
from hy2bridge.proxy_service import ProxyRequest, ProxyService


CONFIG = '''visible_hostname synthetic
http_port 0.0.0.0:3128
https_port 0.0.0.0:443 tls-cert=/etc/squid/tls/fullchain.pem tls-key=/etc/squid/tls/privkey.pem
cache deny all
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/synthetic.passwd
acl authenticated proxy_auth REQUIRED
acl SSL_ports port 443 563
acl Safe_ports port 80 443 563 1025-65535
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny to_localhost
http_access deny private_dst
http_access allow authenticated
http_access deny all
'''


class LegacyProxyTests(unittest.TestCase):
    setUp = test_accounting.AccountingTests.setUp
    tearDown = test_accounting.AccountingTests.tearDown

    def legacy(self):
        return {'fingerprint': 'f' * 64, 'username': 'old_proxy', 'password_hash': '$apr1$synthetic$hash',
                'passwd': 'old_proxy:$apr1$synthetic$hash\n', 'certificate': 'OLD_CERT', 'certificate_key': 'OLD_KEY',
                'Safe_ports': '80 443 563 1025-65535', 'SSL_ports': '443 563',
                'guard': {'listeners':[[3128,'synthetic',100],[443,'synthetic-tls',100]],'unit': {'FragmentPath': '/usr/lib/systemd/system/squid.service',
                                   'ExecStart': '/usr/sbin/squid --foreground -sYC', 'UnitFileState': 'enabled'},
                          'files': {'/etc/squid/squid.conf': 'config-digest'}}}

    def service(self):
        service = test_proxy.ProxyTests.configure(self)
        service.tls = MagicMock()
        return service

    def request(self):
        return test_proxy.ProxyTests.request(self, replace_legacy_squid=True, proxy_username='',
                                            proxy_password='old', address='8.8.8.8', domain='8.8.8.8', https_port=443)

    def test_legacy_profile_preserves_destination_port_policy(self):
        profile = legacy_profile(CONFIG)
        self.assertEqual(profile['Safe_ports'], '80 443 563 1025-65535')
        self.assertEqual(profile['SSL_ports'], '443 563')
        for change in [CONFIG + 'include /etc/unknown.conf\n', CONFIG.replace('0.0.0.0:443', '0.0.0.0:8443'),
                       CONFIG.replace('http_access deny all', 'http_access allow all')]:
            with self.assertRaises(RuntimeError):
                legacy_profile(change)

    def test_legacy_model_accepts_current_short_password_but_new_proxy_does_not(self):
        self.assertEqual(ProxyRequest(**self.request()).proxy_username, '')
        with self.assertRaises(ValueError):
            ProxyRequest(**{**self.request(), 'replace_legacy_squid': False})

    def test_http_only_profile_does_not_require_or_create_a_tls_listener(self):
        config='\n'.join(line for line in CONFIG.splitlines() if not line.startswith('https_port'))
        profile=legacy_profile(config)
        self.assertEqual(profile['http_port'],3128)
        self.assertIsNone(profile['https_port'])
        self.assertIsNone(profile['certificate_path'])
        service=self.service();data=self.request();legacy=self.legacy()
        legacy.update(https_port=None,certificate='',certificate_key='')
        service.provision.connect=MagicMock()
        service.remote=MagicMock(return_value={'home':'/root','checks':[{'passed':True}],'legacy':legacy})
        with patch('hy2bridge.proxy_service.bootstrap.inspect',return_value={'python_available':True,'bootstrap_required':False}),patch('threading.Timer'):
            plan=service.preflight(data)
        self.assertTrue(plan['ready']);self.assertIsNone(data['https_port'])
        self.assertEqual(plan['summary']['Режимы'],'HTTP')
        config,_=service.configuration('a'*32,data)
        self.assertEqual(config['publish'],[(3128,3128)])
        self.assertNotIn('https_port',config['files']['squid.conf'])

    def test_systemd_execstart_guard_excludes_runtime_timestamps(self):
        raw = 'MainPID=123\nActiveState=active\nUnitFileState=enabled\nFragmentPath=/usr/lib/systemd/system/squid.service\nDropInPaths=\nExecStart={ path=/usr/sbin/squid ; argv[]=/usr/sbin/squid --foreground -sYC ; start_time=old ; pid=123 ; }\n'
        with patch('hy2bridge.proxy_install.command', return_value=raw):
            first = legacy_unit()
        with patch('hy2bridge.proxy_install.command', return_value=raw.replace('start_time=old', 'start_time=new')):
            second = legacy_unit()
        self.assertEqual(first, second)
        with patch('hy2bridge.proxy_install.command', return_value=raw.replace('/usr/sbin/squid ;', '/usr/sbin/other ;')):
            with self.assertRaises(RuntimeError):legacy_unit()

    def test_configuration_preserves_hash_tls_and_existing_authentication(self):
        service = self.service()
        data = self.request()
        data['proxy_password'] = 'current-password-kept-private'
        legacy = self.legacy()
        data.update(proxy_username=legacy['username'], _legacy=legacy,
                    certificate=legacy['certificate'], certificate_key=legacy['certificate_key'])
        config, hashed = service.configuration('a' * 32, data)
        self.assertEqual(hashed, legacy['password_hash'])
        self.assertEqual(config['files']['passwd'], legacy['passwd'])
        self.assertEqual(config['files']['cert.pem'], legacy['certificate'])
        self.assertEqual(config['publish'], [(3128, 3128), (443, 8443)])
        self.assertIn('acl SSL_ports port 443 563', config['files']['squid.conf'])
        self.assertIn('acl Safe_ports port 80 443 563 1025-65535', config['files']['squid.conf'])
        self.assertNotIn(data['proxy_password'], json.dumps({key: value for key, value in config.items() if key != 'node'}))

    def test_preflight_discovery_never_returns_hash_or_private_key(self):
        service = self.service()
        service.provision.connect = MagicMock()
        service.remote = MagicMock(return_value={'home': '/root', 'checks': [{'passed': True}], 'legacy': self.legacy()})
        runtime = {'python_available': True, 'bootstrap_required': True}
        data = self.request()
        with patch('hy2bridge.proxy_service.bootstrap.inspect', return_value=runtime), patch('threading.Timer'):
            plan = service.preflight(data)
        self.assertTrue(plan['ready'])
        self.assertEqual(data['proxy_username'], 'old_proxy')
        for secret in ['OLD_KEY', '$apr1$synthetic$hash']:
            self.assertNotIn(secret, json.dumps(plan))
        self.assertTrue(service.remote.call_args.args[1]['replace_legacy_squid'])

    def worker(self, successful=True, restore_ok=True, commit_failure=None):
        service = self.service()
        service.provision.connect = MagicMock()
        service.upload_image = MagicMock()
        calls = []
        def remote(client, config):
            calls.append(config['action'])
            if config['action'] == 'preflight':return {'checks': [{'passed': True}]}
            if config['action'] == 'legacy-commit':
                with self.store.connection() as db:
                    self.assertIsNotNone(db.execute('SELECT id FROM fleet_proxy_services WHERE id=? AND active=1', ('a' * 32,)).fetchone())
                self.assertEqual(service.job('a' * 32)['state'], 'running')
                if commit_failure is not None:raise commit_failure
            if config['action'] == 'legacy-restore' and not restore_ok:raise RuntimeError('synthetic restore failed')
            return {'running': True}
        service.remote = remote
        service.check = MagicMock(side_effect=[{'passed': successful, 'checks': []}, {'passed': restore_ok, 'checks': []}])
        data = self.request()
        data.update(proxy_username='old_proxy', certificate='OLD_CERT', certificate_key='OLD_KEY', _legacy=self.legacy())
        record = {'data': data, 'plan': {'id': 'a' * 32}, 'remote': {'bootstrap_required': False}}
        if isinstance(commit_failure, SystemExit):
            with self.assertRaises(SystemExit):service.worker(record)
        else:
            service.worker(record)
        return service, calls

    def test_image_is_loaded_before_legacy_stop_and_success_commits(self):
        service, calls = self.worker()
        self.assertEqual(calls, ['preflight', 'image-prepare', 'legacy-stop', 'install', 'legacy-commit'])
        self.assertEqual(service.job('a' * 32)['state'], 'succeeded')
        self.assertEqual(service.list('test-node')[0]['username'], 'old_proxy')

    def test_failed_payload_removes_owned_container_and_restores_legacy(self):
        service, calls = self.worker(successful=False)
        self.assertEqual(calls[-1:], ['legacy-restore'])
        self.assertNotIn('legacy-commit', calls)
        self.assertEqual(service.job('a' * 32)['state'], 'rolled_back')
        self.assertEqual(service.list('test-node'), [])

    def test_failed_legacy_restore_remains_failed(self):
        service, calls = self.worker(successful=False, restore_ok=False)
        self.assertEqual(service.job('a' * 32)['state'], 'failed')

    def test_changed_source_or_pid_blocks_stop_before_any_mutation(self):
        with patch('hy2bridge.proxy_install.legacy_snapshot', return_value={'fingerprint': 'changed'}), \
                patch('hy2bridge.proxy_install.command') as command, \
                patch('hy2bridge.proxy_install.legacy_timer') as timer:
            with self.assertRaises(RemoteError):
                legacy_stop({'id': 'a' * 32, 'legacy_fingerprint': 'expected'})
        command.assert_not_called()
        timer.assert_not_called()

    def test_deadman_leaves_committed_replacement_untouched(self):
        directory = Path(self.tmp.name) / 'backup'
        directory.mkdir()
        (directory / 'committed').write_text('committed')
        with patch('hy2bridge.proxy_install.legacy_backup', return_value=directory), \
                patch('hy2bridge.proxy_install.legacy_lock', return_value=nullcontext()), \
                patch('hy2bridge.proxy_install.command') as command:
            self.assertEqual(legacy_restore('a' * 32), {'restored': False, 'committed': True})
        command.assert_not_called()

    def test_old_deadman_cannot_touch_a_newer_replacement(self):
        directory = Path(self.tmp.name) / 'backup'
        directory.mkdir()
        pointer = Path(self.tmp.name) / 'squid.json'
        pointer.write_text(json.dumps({'id': 'b' * 32}))
        with patch('hy2bridge.proxy_install.legacy_backup', return_value=directory), \
                patch('hy2bridge.proxy_install.legacy_lock', return_value=nullcontext()), \
                patch('hy2bridge.proxy_install.LEGACY_POINTER', pointer), \
                patch('hy2bridge.proxy_install.inspect_container') as inspect, \
                patch('hy2bridge.proxy_install.command') as command:
            with self.assertRaisesRegex(RuntimeError, 'Another proxy owns'):
                legacy_restore('a' * 32, force=True)
        inspect.assert_not_called()
        command.assert_not_called()
        self.assertEqual(json.loads(pointer.read_text())['id'], 'b' * 32)

    def test_commit_writes_owned_pointer_and_disables_only_squid(self):
        directory = Path(self.tmp.name) / 'backup'
        directory.mkdir()
        snapshot = self.legacy()['guard']
        (directory / 'snapshot.json').write_text(json.dumps(snapshot))
        pointer = Path(self.tmp.name) / 'pointer/squid.json'
        found = {'Config': {'Labels': {'rime.proxy.job': 'a' * 32}}, 'State': {'Running': True}}
        with patch('hy2bridge.proxy_install.legacy_backup', return_value=directory), \
                patch('hy2bridge.proxy_install.legacy_lock', return_value=nullcontext()), \
                patch('hy2bridge.proxy_install.paths', return_value=(Path('/owned'), 'fleet-proxy-' + 'a' * 32)), \
                patch('hy2bridge.proxy_install.inspect_container', return_value=found), \
                patch('hy2bridge.proxy_install.legacy_unit', return_value={**snapshot['unit'], 'ActiveState': 'inactive'}), \
                patch('hy2bridge.proxy_install.verify_legacy_files'), \
                patch('hy2bridge.proxy_install.LEGACY_POINTER', pointer), \
                patch('hy2bridge.proxy_install.legacy_timer') as timer, \
                patch('hy2bridge.proxy_install.command') as command:
            self.assertTrue(legacy_commit('a' * 32)['committed'])
        self.assertEqual(json.loads(pointer.read_text())['container'], 'fleet-proxy-' + 'a' * 32)
        command.assert_called_once_with(['systemctl', 'disable', 'squid.service'])
        timer.assert_called_once_with('a' * 32, stop=True)
        self.assertTrue((directory / 'committed').is_file())

    def test_crash_before_remote_commit_preserves_intent_and_requires_reconciliation(self):
        service, calls = self.worker(commit_failure=SystemExit('synthetic controller crash'))
        self.assertEqual(calls[-1], 'legacy-commit')
        row = service.list('test-node')[0]
        self.assertEqual(row['deployment_state'], 'running')
        self.assertTrue(row['result']['passed'])
        restarted = ProxyService(self.store, service.provision)
        self.assertEqual(restarted.list('test-node')[0]['deployment_state'], 'failed')
        with self.assertRaises(ValueError):restarted.recheck('a' * 32, 'old')

    def test_handled_commit_failure_hides_record_after_verified_native_restore(self):
        service, calls = self.worker(commit_failure=RuntimeError('synthetic commit failure'))
        self.assertEqual(calls[-1:], ['legacy-restore'])
        self.assertEqual(service.job('a' * 32)['state'], 'rolled_back')
        self.assertEqual(service.list('test-node'), [])

    def test_failed_commit_and_restore_keep_visible_failed_intent(self):
        service, calls = self.worker(commit_failure=RuntimeError('synthetic commit failure'), restore_ok=False)
        self.assertEqual(service.job('a' * 32)['state'], 'failed')
        self.assertEqual(service.list('test-node')[0]['deployment_state'], 'failed')

    def test_hash_qualification_uses_stdin_before_legacy_stop(self):
        secret = 'current cleartext password'
        current = {'fingerprint': 'f' * 64, 'username': 'existing', 'passwd_path': '/etc/squid/synthetic.passwd'}
        process = MagicMock(returncode=0, stdout='OK\n')
        with patch('hy2bridge.proxy_install.legacy_snapshot', return_value=current), \
                patch('hy2bridge.proxy_install.Path.stat', return_value=SimpleNamespace(st_uid=13, st_gid=13)), \
                patch('hy2bridge.proxy_install.subprocess.run', return_value=process) as command, \
                patch('hy2bridge.proxy_install.inspect_container', return_value=None):
            qualify_legacy_hash({'id': 'a' * 32, 'legacy_fingerprint': 'f' * 64, 'legacy_password': secret}, 'sha256:' + '1' * 64)
        args = command.call_args.args[0]
        self.assertIn('none', args)
        self.assertIn('--read-only', args)
        self.assertEqual(args[args.index('--user') + 1], '13:13')
        self.assertNotIn(secret, ' '.join(args))
        self.assertIn('current%20cleartext%20password', command.call_args.kwargs['input'])
        self.assertNotIn('systemctl', args)

    def test_changed_source_blocks_restore_before_container_or_unit_changes(self):
        directory = Path(self.tmp.name) / 'backup'
        directory.mkdir()
        snapshot = self.legacy()['guard']
        (directory / 'snapshot.json').write_text(json.dumps(snapshot))
        with patch('hy2bridge.proxy_install.legacy_backup', return_value=directory), \
                patch('hy2bridge.proxy_install.legacy_lock', return_value=nullcontext()), \
                patch('hy2bridge.proxy_install.LEGACY_POINTER', Path(self.tmp.name) / 'absent-pointer'), \
                patch('hy2bridge.proxy_install.legacy_unit', return_value=snapshot['unit']), \
                patch('hy2bridge.proxy_install.verify_legacy_files', side_effect=RemoteError('legacy_changed')), \
                patch('hy2bridge.proxy_install.inspect_container') as inspect, \
                patch('hy2bridge.proxy_install.command') as command:
            with self.assertRaises(RemoteError):legacy_restore('a' * 32, force=True)
        inspect.assert_not_called()
        command.assert_not_called()

    def test_changed_source_blocks_commit_before_pointer_or_service_changes(self):
        directory = Path(self.tmp.name) / 'backup'
        directory.mkdir()
        snapshot = self.legacy()['guard']
        (directory / 'snapshot.json').write_text(json.dumps(snapshot))
        pointer = Path(self.tmp.name) / 'absent-pointer'
        with patch('hy2bridge.proxy_install.legacy_backup', return_value=directory), \
                patch('hy2bridge.proxy_install.legacy_lock', return_value=nullcontext()), \
                patch('hy2bridge.proxy_install.LEGACY_POINTER', pointer), \
                patch('hy2bridge.proxy_install.legacy_unit', return_value=snapshot['unit']), \
                patch('hy2bridge.proxy_install.verify_legacy_files', side_effect=RemoteError('legacy_changed')), \
                patch('hy2bridge.proxy_install.inspect_container') as inspect, \
                patch('hy2bridge.proxy_install.command') as command:
            with self.assertRaises(RemoteError):legacy_commit('a' * 32)
        inspect.assert_not_called()
        command.assert_not_called()
        self.assertFalse(pointer.exists())
