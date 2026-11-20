from copy import deepcopy
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

import test_accounting
from hy2bridge.operations import Operations
from hy2bridge.provision import ProvisionError
from hy2bridge.proxy_secrets import ProxySecrets
from hy2bridge.recovery import Recovery, ArchiveBudget, archive_files, proxy_profile, vless_profile


class RecoveryTests(unittest.TestCase):
    tearDown = test_accounting.AccountingTests.tearDown

    def setUp(self):
        test_accounting.AccountingTests.setUp(self)
        Operations(self.store)
        with self.store.connection(write=True) as db:
            db.execute('CREATE TABLE nodes(id INTEGER PRIMARY KEY,created_at TEXT)')
            db.execute("INSERT INTO nodes VALUES(1,'2026-01-01')")
            db.execute('CREATE TABLE fleet_proxy_services(id TEXT PRIMARY KEY,node TEXT,runtime_id TEXT,password_secret TEXT)')
        self.secrets = ProxySecrets(Path(self.tmp.name) / 'vault.key')
        self.recovery = Recovery(self.store, self.secrets)

    def profile(self):
        return {'version': 1, 'vpn': {'protocol': 'vless', 'config': {'inbounds': [], 'privateKey': 'synthetic-private-material'}},
                'proxies': {}, 'originals': {}}

    def archive(self, members):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, value in members.items():
                data = value.encode() if isinstance(value, str) else value
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        return stream.getvalue()

    def test_sealed_profile_survives_restart_without_plaintext_in_database(self):
        self.recovery.save('xray:1', self.profile())
        restarted = Recovery(self.store, self.secrets)
        self.assertEqual(restarted.load('xray:1'), self.profile())
        self.assertNotIn(b'synthetic-private-material', self.path.read_bytes())
        self.assertEqual(self.secrets.path.stat().st_size, 32)

    def test_identical_capture_does_not_rewrite_the_envelope_or_timestamp(self):
        self.recovery.save('xray:1', self.profile())
        with self.store.connection() as db:before = tuple(db.execute('SELECT * FROM fleet_recovery_profiles').fetchone())
        self.recovery.save('xray:1', self.profile())
        with self.store.connection() as db:self.assertEqual(tuple(db.execute('SELECT * FROM fleet_recovery_profiles').fetchone()), before)

    def test_reused_node_id_cannot_inherit_old_recovery_keys(self):
        self.recovery.save('xray:1', self.profile())
        with self.store.connection(write=True) as db:db.execute("UPDATE nodes SET created_at='2026-02-01'")
        self.assertIsNone(self.recovery.load('xray:1')['vpn'])

    def test_readiness_includes_every_active_proxy_configuration(self):
        self.recovery.save('xray:1',self.profile())
        with self.store.connection(write=True) as db:
            db.execute('ALTER TABLE fleet_proxy_services ADD COLUMN active INTEGER DEFAULT 1')
            db.execute("INSERT INTO fleet_proxy_services VALUES('missing','xray:1','','',1)")
        summary=self.recovery.summary('xray:1')
        self.assertFalse(summary['available'])
        self.assertEqual(summary['missing_proxies'],['missing'])

    def test_missing_key_cannot_be_silently_recreated(self):
        self.recovery.save('xray:1', self.profile())
        self.secrets.path.unlink()
        with self.assertRaises(ProvisionError):self.recovery.save('xray:1', {**self.profile(), 'originals': {'new': 'data'}})
        self.assertFalse(self.secrets.path.exists())

    def test_existing_proxy_vault_protects_against_creating_another_key(self):
        with self.store.connection(write=True) as db:db.execute("INSERT INTO fleet_proxy_services VALUES('proxy','xray:1','','v1:existing')")
        with self.assertRaises(ProvisionError):self.recovery.save('xray:1', self.profile())
        self.assertFalse(self.secrets.path.exists())

    def test_nested_legacy_archive_is_imported_as_data(self):
        config = {'inbounds': [{'tag': 'old', 'protocol': 'vless', 'port': 2053,
                               'settings': {'clients': [{'id': 'revoked-old-key'}]},
                               'streamSettings': {'network': 'xhttp', 'security': 'reality',
                                                  'realitySettings': {'privateKey': 'stable-secret'}}}]}
        nested = self.archive({'etc/node/config.json': json.dumps(config)})
        result = self.recovery.import_archive('xray:1', self.archive({'recovery-base.tar.gz': nested}), 'node.example')
        self.assertTrue(result['available'])
        profile = self.recovery.load('xray:1')
        self.assertEqual(profile['vpn']['config']['inbounds'][0]['streamSettings']['realitySettings']['privateKey'], 'stable-secret')
        self.assertNotIn('clients', profile['vpn']['config']['inbounds'][0]['settings'])

    def test_root_control_tls_files_survive_import_and_partial_refresh(self):
        config={'inbounds':[{'tag':'old','protocol':'vless','port':2053,'settings':{},'streamSettings':{'network':'grpc'}}]}
        files={'config.json':json.dumps(config),'node-cert.pem':'original-cert','node-key.pem':'original-key'}
        self.recovery.import_archive('xray:1',self.archive(files),'node.example')
        expected={'certificate':'original-cert','key':'original-key'}
        self.assertEqual(self.recovery.load('xray:1')['vpn']['management_tls'],expected)
        self.recovery.import_archive('xray:1',self.archive({'config.json':json.dumps(config)}),'node.example')
        self.assertEqual(self.recovery.load('xray:1')['vpn']['management_tls'],expected)

    def test_traversal_and_recursive_links_are_rejected_without_extraction(self):
        for name in ['../outside.json', '/absolute.json', 'etc/../../outside.json', 'etc\\outside.json']:
            with self.subTest(name=name), self.assertRaises(ProvisionError):archive_files(self.archive({name: '{}'}))
        self.assertEqual(list(Path(self.tmp.name).glob('outside*')), [])

    def test_multi_transport_profile_preserves_keys_and_external_ports(self):
        config = {'inbounds': [
            {'tag': 'grpc', 'protocol': 'vless', 'port': 16443, 'settings': {'clients': [{'id': 'old'}]}, 'streamSettings': {'network': 'grpc'}},
            {'tag': 'split', 'protocol': 'vless', 'port': 16444, 'settings': {'clients': []}, 'streamSettings': {'network': 'xhttp', 'xhttpSettings': {'path': '/old', 'extra': {'noGRPCHeader': True}}}},
            {'tag': 'reality', 'protocol': 'vless', 'port': 16445, 'settings': {'clients': []}, 'streamSettings': {'network': 'tcp', 'realitySettings': {'privateKey': 'same-key'}}}],
            'routing': {'domainStrategy': 'AsIs', 'rules': []}}
        hosts = [{'inbound_tag': tag, 'port': port} for tag, port in [('grpc', 443), ('split', 2053), ('reality', 9443)]]
        result = vless_profile(config, hosts)
        self.assertEqual(result['publish'], [[443, 16443, 'tcp'], [2053, 16444, 'tcp'], [9443, 16445, 'tcp']])
        self.assertEqual(result['config']['inbounds'][2]['streamSettings']['realitySettings']['privateKey'], 'same-key')
        self.assertEqual(result['config']['inbounds'][1]['streamSettings']['xhttpSettings'], config['inbounds'][1]['streamSettings']['xhttpSettings'])
        self.assertEqual(config['inbounds'][0]['settings']['clients'], [{'id': 'old'}])

    def test_proxy_keeps_multiple_hashes_and_included_acl_rules(self):
        files = {'etc/squid/squid.conf': 'include /etc/squid/conf.d/*.conf\nhttp_port 3128\nauth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd\nacl authenticated proxy_auth REQUIRED\nhttp_access allow authenticated\nhttp_access deny all\n',
                 'etc/squid/conf.d/sites.conf': 'acl blocked dstdomain "/etc/squid/sites.txt"\nhttp_access deny blocked\n',
                 'etc/squid/sites.txt': '.invalid.example\n', 'etc/squid/passwd': 'first:original-hash\nsecond:another-hash\n'}
        result = proxy_profile('etc/squid/squid.conf', files, 'node.example')
        self.assertEqual(result['files']['passwd'], files['etc/squid/passwd'])
        self.assertIn('http_access deny blocked', result['files']['squid.conf'])
        self.assertIn('/state/extra-', result['files']['squid.conf'])
        self.assertEqual(result['publish'], [[3128, 3128]])

    def test_actual_saved_unpublished_vless_inbound_is_retained(self):
        config={'inbounds':[{'tag':'published','protocol':'vless','port':443,'settings':{}},
                            {'tag':'manual','protocol':'vless','port':2053,'settings':{}}]}
        hosts=[{'inbound_tag':'published','port':443}]
        self.assertEqual(len(vless_profile(config,hosts)['config']['inbounds']),1)
        profile=vless_profile(config,hosts,include_all=True)
        self.assertEqual({value['tag'] for value in profile['config']['inbounds']},{'published','manual'})
        self.assertIn([2053,2053,'tcp'],profile['publish'])
        profile=vless_profile(config,hosts,include_all=True,published=[[8443,2053,'tcp']])
        self.assertIn([8443,2053,'tcp'],profile['publish'])

    def test_cyclic_yaml_does_not_expand_into_a_recovery_profile(self):
        raw = 'listen: :443\nauth: {type: http}\ntls: &x {cert: cert.pem, key: key.pem, recursive: *x}\n'
        with self.assertRaises(ProvisionError):self.recovery.import_archive('hy2', self.archive({'config.yaml': raw}), 'node.example')

    def test_managed_proxy_rebases_state_files_and_rejects_missing_acl(self):
        root='root/.local/share/fleet-proxies/'+'a'*32
        files={root+'/squid.conf':'http_port 3128\nauth_param basic program /usr/lib/squid/basic_ncsa_auth /state/passwd\nacl blocked dstdomain "/state/extra-blocked.txt"\nhttp_access deny blocked\n',
               root+'/passwd':'first:hash\n',root+'/extra-blocked.txt':'.blocked.invalid\n'}
        result=proxy_profile(root+'/squid.conf',files,'node.example')
        self.assertIn('.blocked.invalid\n',result['files'].values())
        self.assertNotIn('/state/extra-blocked.txt',result['files']['squid.conf'])
        del files[root+'/extra-blocked.txt']
        with self.assertRaisesRegex(ProvisionError,'ACL'):proxy_profile(root+'/squid.conf',files,'node.example')

    def test_legacy_proxy_pidfile_uses_the_writable_runtime_directory(self):
        files={'etc/squid/squid.conf':'https_port 8443 tls-cert=/etc/squid/cert.pem tls-key=/etc/squid/key.pem\npid_filename /run/squid.pid\nauth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd\n',
               'etc/squid/passwd':'original:hash\n','etc/squid/cert.pem':'certificate','etc/squid/key.pem':'key'}
        profile=proxy_profile('etc/squid/squid.conf',files,'node.example')
        self.assertIn('pid_filename /run/squid/squid.pid',profile['files']['squid.conf'])
        self.assertNotIn('pid_filename /run/squid.pid\n',profile['files']['squid.conf'])
        files['etc/squid/squid.conf']=files['etc/squid/squid.conf'].replace('pid_filename /run/squid.pid\n','')
        profile=proxy_profile('etc/squid/squid.conf',files,'node.example')
        self.assertEqual(profile['files']['squid.conf'].count('pid_filename /run/squid/squid.pid'),1)

    def test_streaming_budget_bounds_large_reads_before_allocating_them(self):
        source=io.BytesIO(b'123456789')
        budget=ArchiveBudget(source);budget.remaining=4
        with self.assertRaises(ProvisionError):budget.read(1024*1024*1024)
        self.assertEqual(source.tell(),5)

    def test_nested_archives_share_the_same_decompression_budget(self):
        nested=self.archive({'config.json':'{}'})
        archive=self.archive({'recovery.tar.gz':nested})
        with patch('hy2bridge.recovery.MAX_EXPANDED_BYTES',15000), self.assertRaises(ProvisionError):
            archive_files(archive)

    def test_unchanged_profile_still_requires_its_existing_key(self):
        self.recovery.save('xray:1',self.profile())
        self.secrets.path.unlink()
        with self.assertRaises(ProvisionError):self.recovery.save('xray:1',self.profile())


if __name__ == '__main__':
    unittest.main()
