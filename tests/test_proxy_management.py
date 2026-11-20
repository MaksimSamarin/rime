import concurrent.futures
import copy
import json
import os
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import unquote, urlsplit

import test_accounting
import test_proxy
from hy2bridge.provision import ProvisionError
from hy2bridge.proxy_secrets import ProxySecrets, ProxySecretError
from hy2bridge.proxy_service import ProxyRequest, ProxyService, PUBLIC_CONTEXT
from hy2bridge.proxy_install import managed_snapshot, legacy_timer


OLD_PASSWORD = 'original:+/@-proxy-password'
NEW_PASSWORD = 'changed:+/@-proxy-password'
OLD_ID = 'a' * 32


class ProxyManagementTests(unittest.TestCase):
    setUp = test_accounting.AccountingTests.setUp
    tearDown = test_accounting.AccountingTests.tearDown

    def test_public_entry_dns_cannot_redirect_proxy_administration_to_the_entry_host(self):
        service=self.existing()
        service.relays=SimpleNamespace(direct_target=lambda node:'9.9.9.9',has_origin_route=lambda node:False)
        service.provision.resolve=lambda host,port:[host]
        wrong={'host':'8.8.8.8','address':'8.8.8.8','ssh_port':22}
        with self.assertRaises(ProvisionError):service.validate_access('test-node',wrong)
        correct={'host':'9.9.9.9','address':'9.9.9.9','ssh_port':22}
        service.validate_access('test-node',correct)
        self.assertEqual(correct['_origin_address'],'9.9.9.9')

    def test_watchdog_uses_the_interpreter_that_runs_the_remote_worker(self):
        with patch('hy2bridge.proxy_install.command') as command, \
                patch('hy2bridge.proxy_install.sys.executable','/usr/local/bin/python3'):
            legacy_timer('a'*32)
        self.assertEqual(command.call_args.args[0][-2],'/usr/local/bin/python3')
        self.assertIn('--on-active=180s',command.call_args.args[0])

    def existing(self):
        service = test_proxy.ProxyTests.configure(self)
        service.tls = MagicMock()
        service.provision.connect = MagicMock()
        service.remote = MagicMock(return_value={'checks': [{'passed': True}], 'running': True})
        service.upload_image = MagicMock()
        service.check = MagicMock(return_value={'passed': True, 'checks': []})
        data = test_proxy.ProxyTests.request(self, address='8.8.8.8', domain='8.8.8.8', proxy_password=OLD_PASSWORD)
        service.worker({'data': data, 'plan': {'id': OLD_ID}, 'remote': {'bootstrap_required': False}})
        self.assertEqual(service.job(OLD_ID)['state'], 'succeeded')
        return service

    def row(self, identity):
        with self.store.connection() as db:
            return dict(db.execute('SELECT * FROM fleet_proxy_services WHERE id=?', (identity,)).fetchone())

    def edit(self, service, password='', commit_error=None, payload_ok=True):
        old = self.row(OLD_ID)
        data = test_proxy.ProxyTests.request(self, replace_service=OLD_ID, proxy_username='', proxy_password=password,
                                            address='8.8.8.8', domain='8.8.8.8', http_port=None, https_port=9443)
        managed = {'fingerprint': 'f' * 64, 'username': old['username'], 'password_hash': old['password_hash'],
                   'certificate': 'OLD_CERT', 'certificate_key': 'OLD_KEY', 'Safe_ports': '80 443', 'SSL_ports': '443'}
        calls = []
        def remote(client, config):
            calls.append(copy.deepcopy(config))
            if config['action'] == 'preflight':
                return {'home': '/root', 'checks': [{'passed': True}], 'managed': managed}
            if config['action'] == 'managed-commit':
                self.assertEqual(self.row(config['id'])['active'], 1)
                self.assertEqual(self.row(OLD_ID)['active'], 0)
                self.assertEqual(service.job(config['id'])['state'], 'running')
                if commit_error is not None:raise commit_error
            return {'running': True}
        service.remote = remote
        runtime = {'python_available': True, 'bootstrap_required': False}
        with patch('hy2bridge.proxy_service.bootstrap.inspect', return_value=runtime), patch('threading.Timer'):
            plan = service.preflight(data)
        job = plan['id']
        record = service.plans.pop(job)
        context = {key: record['data'].get(key) for key in PUBLIC_CONTEXT}
        context['node_generation'] = record['data']['_node_generation']
        service.update(job, 'test-node', 'running', 'Synthetic start', context)
        checks = []
        def check(value):
            checks.append(copy.deepcopy(value))
            return {'passed': payload_ok if len(checks) == 1 else True, 'checks': []}
        service.check = check
        if isinstance(commit_error, SystemExit):
            with self.assertRaises(SystemExit):service.worker(record)
        else:
            service.worker(record)
        return job, calls, checks

    def test_connection_credentials_survive_restart_and_are_absent_from_public_metadata(self):
        service = self.existing()
        row = self.row(OLD_ID)
        self.assertTrue(row['password_secret'].startswith('v1:'))
        self.assertNotIn(OLD_PASSWORD, row['password_secret'])
        self.assertNotIn(OLD_PASSWORD, json.dumps(service.list('test-node')))
        self.assertNotIn('password_secret', service.list('test-node')[0])
        restarted = ProxyService(self.store, service.provision)
        info = restarted.connection_info(OLD_ID)
        self.assertEqual(info['password'], OLD_PASSWORD)
        self.assertEqual(unquote(urlsplit(info['urls']['http']).password), OLD_PASSWORD)
        self.assertIsNone(info['urls']['https'])
        self.assertEqual(len(restarted.secrets.path.read_bytes()), 32)
        if os.name != 'nt':self.assertEqual(restarted.secrets.path.stat().st_mode & 0o777, 0o600)

    def test_missing_key_never_regenerates_when_encrypted_credentials_exist(self):
        service = self.existing()
        original = self.row(OLD_ID)['password_secret']
        service.secrets.path.unlink()
        with self.assertRaises(ProvisionError):service.connection_info(OLD_ID)
        with self.assertRaises(ProvisionError):service.encrypted_password('b' * 32, NEW_PASSWORD)
        self.assertFalse(service.secrets.path.exists())
        self.assertEqual(self.row(OLD_ID)['password_secret'], original)

    def test_wrong_key_cannot_overwrite_old_credentials(self):
        service = self.existing()
        original = self.row(OLD_ID)['password_secret']
        service.secrets.path.write_bytes(os.urandom(32))
        with self.assertRaises(ProvisionError):service.connection_info(OLD_ID)
        with self.assertRaises(ProvisionError):service.encrypted_password('b' * 32, NEW_PASSWORD)
        self.assertEqual(self.row(OLD_ID)['password_secret'], original)

    def test_hash_only_entry_requires_authorized_successful_remember(self):
        service = self.existing()
        with self.store.connection(write=True) as db:db.execute("UPDATE fleet_proxy_services SET password_secret='' WHERE id=?", (OLD_ID,))
        info = service.connection_info(OLD_ID)
        self.assertTrue(info['needs_password'])
        self.assertIsNone(info['password'])
        self.assertFalse(service.list('test-node')[0]['edit_allowed'])
        with self.assertRaises(ProvisionError):service.recheck(OLD_ID, '')
        service.check = MagicMock(return_value={'passed': False, 'checks': []})
        service.recheck(OLD_ID, 'wrong', remember=True)
        self.assertEqual(self.row(OLD_ID)['password_secret'], '')
        service.check = MagicMock(return_value={'passed': True, 'checks': []})
        service.recheck(OLD_ID, OLD_PASSWORD, remember=True)
        self.assertTrue(service.list('test-node')[0]['edit_allowed'])
        self.assertEqual(service.connection_info(OLD_ID)['password'], OLD_PASSWORD)

    def test_saved_password_check_uses_server_vault_without_retrieval(self):
        service = self.existing()
        service.check = MagicMock(return_value={'passed': True, 'checks': []})
        self.assertTrue(service.recheck(OLD_ID, '')['passed'])
        self.assertEqual(service.check.call_args.args[0]['proxy_password'], OLD_PASSWORD)

    def test_deleted_or_recreated_node_cannot_reveal_old_password(self):
        service = self.existing()
        with self.store.connection(write=True) as db:db.execute("UPDATE fleet_inventory SET created_at=created_at+1 WHERE id='test-node'")
        with patch.object(service.secrets, 'decrypt') as decrypt:
            with self.assertRaises(ProvisionError):service.connection_info(OLD_ID)
        decrypt.assert_not_called()
        with self.store.connection(write=True) as db:db.execute("DELETE FROM fleet_inventory WHERE id='test-node'")
        with self.assertRaises(ProvisionError):service.connection_info(OLD_ID)

    def test_update_preserves_empty_password_and_certificate_while_changing_ports(self):
        service = self.existing()
        old_hash = self.row(OLD_ID)['password_hash']
        job, calls, checks = self.edit(service)
        self.assertEqual(service.job(job)['state'], 'succeeded')
        self.assertEqual(self.row(job)['password_hash'], old_hash)
        self.assertEqual(self.row(OLD_ID)['active'], 0)
        self.assertEqual(service.connection_info(job)['password'], OLD_PASSWORD)
        install = next(call for call in calls if call['action'] == 'install')
        self.assertEqual(install['files']['cert.pem'], 'OLD_CERT')
        self.assertEqual(install['publish'], [(9443, 8443)])
        actions = [call['action'] for call in calls]
        self.assertLess(actions.index('image-prepare'), actions.index('managed-stop'))
        self.assertEqual(actions[-2:], ['managed-commit', 'managed-retire'])

    def test_update_changes_credentials_and_encrypts_new_password(self):
        service = self.existing()
        job, calls, checks = self.edit(service, password=NEW_PASSWORD)
        self.assertEqual(service.connection_info(job)['password'], NEW_PASSWORD)
        self.assertNotIn(NEW_PASSWORD, json.dumps(service.job(job)))
        self.assertNotIn(NEW_PASSWORD, self.row(job)['password_secret'])

    def test_edit_preserves_imported_accounts_acl_and_extra_files(self):
        service = self.existing()
        old = self.row(OLD_ID)
        config = ('http_port 3128\nhttps_port 8443 tls-cert=/state/cert.pem tls-key=/state/key.pem\n'
                  'acl owners proxy_auth proxy_user second\nacl allowed dstdomain "/state/extra-domains.txt"\n'
                  'http_access allow owners allowed\nhttp_access deny all\n')
        data = test_proxy.ProxyTests.request(self, address='8.8.8.8', domain='8.8.8.8', http_port=None, https_port=9443,
                                            proxy_username='renamed', proxy_password=NEW_PASSWORD)
        data.update(_replace=old, _managed_files={'squid.conf':config, 'passwd':'proxy_user:'+old['password_hash']+'\nsecond:keep-hash\n',
                                                'extra-domains.txt':'.example.invalid\n'}, certificate='OLD_CERT', certificate_key='OLD_KEY')
        restored, _ = service.configuration('b'*32, data)
        self.assertIn('second:keep-hash\n', restored['files']['passwd'])
        self.assertIn('acl owners proxy_auth renamed second', restored['files']['squid.conf'])
        self.assertIn('http_access allow owners allowed', restored['files']['squid.conf'])
        self.assertEqual(restored['files']['extra-domains.txt'], '.example.invalid\n')
        self.assertNotIn('http_port 3128', restored['files']['squid.conf'])
        self.assertEqual(restored['publish'], [(9443, 8443)])

    def test_failed_update_restores_previous_ports_and_password(self):
        service = self.existing()
        job, calls, checks = self.edit(service, password=NEW_PASSWORD, payload_ok=False)
        self.assertEqual(service.job(job)['state'], 'rolled_back')
        self.assertEqual(checks[-1]['proxy_password'], OLD_PASSWORD)
        self.assertEqual(checks[-1]['http_port'], 3128)
        self.assertIsNone(checks[-1]['https_port'])
        self.assertEqual(self.row(OLD_ID)['active'], 1)
        self.assertEqual(service.list('test-node')[0]['id'], OLD_ID)

    def test_domain_change_and_hash_only_update_fail_before_ssh(self):
        service = self.existing()
        data = test_proxy.ProxyTests.request(self, replace_service=OLD_ID, proxy_username='', proxy_password='',
                                            domain='different.example', address='8.8.8.8')
        service.provision.connect.reset_mock()
        with self.assertRaises(ProvisionError):service.preflight(data)
        service.provision.connect.assert_not_called()
        with self.store.connection(write=True) as db:db.execute("UPDATE fleet_proxy_services SET password_secret='' WHERE id=?", (OLD_ID,))
        with self.assertRaises(ProvisionError):service.preflight({**data, 'domain': '8.8.8.8'})
        service.provision.connect.assert_not_called()

    def test_pending_update_has_real_ssh_reconciliation_path(self):
        service = self.existing()
        job, calls, checks = self.edit(service, password=NEW_PASSWORD, commit_error=SystemExit('synthetic crash'))
        restarted = ProxyService(self.store, service.provision)
        row = self.row(job)
        restarted.provision.connect = MagicMock()
        def remote(client, config):
            if config['action'] == 'reconcile-state':
                return {'candidate': {'username': row['username'], 'password_hash': row['password_hash'], 'running': True},
                        'committed': False, 'restored': False}
            return {'committed': True}
        restarted.remote = remote
        restarted.check = MagicMock(return_value={'passed': True, 'checks': []})
        access = {'host': 'node.lab.invalid', 'address': '8.8.8.8'}
        restarted.reconcile_worker(row, access)
        self.assertEqual(restarted.job(job)['state'], 'succeeded')
        self.assertEqual(restarted.connection_info(job)['password'], NEW_PASSWORD)
        self.assertEqual(access, {})

    def test_pending_missing_candidate_reconciles_back_to_previous_service(self):
        service = self.existing()
        job, calls, checks = self.edit(service, password=NEW_PASSWORD, commit_error=SystemExit('synthetic crash'))
        restarted = ProxyService(self.store, service.provision)
        restarted.provision.connect = MagicMock()
        restarted.remote = MagicMock(return_value={'candidate': None, 'committed': False, 'restored': True})
        restarted.check = MagicMock(return_value={'passed': True, 'checks': []})
        restarted.reconcile_worker(self.row(job), {'host': 'node.lab.invalid', 'address': '8.8.8.8'})
        self.assertEqual(restarted.job(job)['state'], 'rolled_back')
        self.assertEqual(restarted.list('test-node')[0]['id'], OLD_ID)
        self.assertEqual(restarted.check.call_args.args[0]['proxy_password'], OLD_PASSWORD)

    def test_legacy_managed_snapshot_keeps_container_identity_when_reading_acls(self):
        directory = Path(self.tmp.name) / 'managed'
        directory.mkdir()
        (directory / 'squid.conf').write_text('acl Safe_ports port 80 443\nacl SSL_ports port 443\n')
        (directory / 'passwd').write_text('existing:synthetic-hash\n')
        (directory / 'cert.pem').write_text('CERT')
        (directory / 'key.pem').write_text('KEY')
        name = 'fleet-proxy-' + OLD_ID
        pointer = Path(self.tmp.name) / 'squid.json'
        expected = {'id': OLD_ID, 'directory': str(directory), 'container': name}
        pointer.write_text(json.dumps(expected))
        info = {'Id': 'container-id', 'Image': 'image-id', 'Config': {'Labels': {'rime.proxy.job': OLD_ID}},
                'State': {'Running': True}, 'HostConfig': {'PortBindings': {}},
                'Mounts': [{'Destination': '/state', 'Source': str(directory), 'RW': False}]}
        with patch('hy2bridge.proxy_install.paths', return_value=(directory, name)), \
                patch('hy2bridge.proxy_install.inspect_container', return_value=info), \
                patch('hy2bridge.proxy_install.LEGACY_POINTER', pointer):
            result = managed_snapshot(OLD_ID, legacy=True)
        self.assertEqual(result['pointer'], expected)
        self.assertEqual(result['Safe_ports'], '80 443')
        self.assertEqual(result['SSL_ports'], '443')


class ProxySecretTests(unittest.TestCase):
    setUp = test_accounting.AccountingTests.setUp
    tearDown = test_accounting.AccountingTests.tearDown

    def test_concurrent_key_creation_has_one_stable_key(self):
        path = Path(self.tmp.name) / 'key'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            keys = list(pool.map(lambda _: ProxySecrets(path).key(create=True), range(16)))
        self.assertEqual(len(set(keys)), 1)
        self.assertEqual(len(keys[0]), 32)
        self.assertEqual(list(path.parent.glob('.proxy-key-*')), [])

    def test_password_envelope_is_bound_to_service_and_rejects_tampering(self):
        vault = ProxySecrets(Path(self.tmp.name) / 'key')
        value = vault.encrypt(OLD_ID, NEW_PASSWORD, create=True)
        self.assertEqual(vault.decrypt(OLD_ID, value), NEW_PASSWORD)
        self.assertNotEqual(value, vault.encrypt(OLD_ID, NEW_PASSWORD))
        with self.assertRaises(ProxySecretError):vault.decrypt('b' * 32, value)
        with self.assertRaises(ProxySecretError):vault.decrypt(OLD_ID, value[:-2] + 'AA')
