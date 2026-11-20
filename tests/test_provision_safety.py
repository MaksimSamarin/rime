from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import socket
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import test_accounting
from hy2bridge.provision import Provisioner, ProvisionError
from hy2bridge.remote_install import main as remote, control_firewall, authenticated_management


class ProvisionSafetyTests(unittest.TestCase):
    setUp = test_accounting.AccountingTests.setUp
    tearDown = test_accounting.AccountingTests.tearDown

    def test_verified_mtls_runtime_keeps_source_firewall_and_policy_watcher(self):
        self.configured()
        configuration = {'id':'a'*32,'protocol':'vless','control_source':'8.8.8.8',
                         'env':{'SSL_CLIENT_CERT_FILE':'/state/client.pem'},
                         'publish':[[443,24443,'tcp'],[62050,62050,'tcp'],[62051,62051,'tcp']],
                         'files':{'client.pem':(Path(self.tmp.name)/'cert.pem').read_text()}}
        image = json.dumps([{'Config':{'Labels':{'org.rime.management.auth':'controller-mtls-v1'}}}])
        directory = Path(self.tmp.name)
        units=directory/'host-units';units.mkdir()
        helper=directory/'host-helpers';helper.mkdir()
        def target(value):
            if str(value)=='/etc/systemd/system':return units
            if str(value)=='/etc/rime-node-firewalls':return helper
            return Path(value)
        with patch('hy2bridge.remote_install.run',return_value=image), \
             patch('hy2bridge.remote_install.Path',side_effect=target), \
             patch('hy2bridge.remote_install.os.getuid',return_value=0), \
             patch('hy2bridge.remote_install.shutil.which',return_value='/synthetic/tool'), \
             patch('hy2bridge.remote_install.subprocess.run',return_value=MagicMock(returncode=0)):
            self.assertEqual(control_firewall(configuration,directory,image='sha256:qualified'),
                             'controller-mtls-v1')
        self.assertTrue((directory/'control-firewall.json').exists())
        self.assertEqual(json.loads((directory/'control-policy/sources.json').read_text())['sources'],['8.8.8.8'])
        self.assertTrue((units/('rime-node-firewall-'+configuration['id']+'.path')).is_file())
        self.assertTrue((helper/configuration['id']/'worker.py').is_file())
        self.assertFalse((directory/'control-firewall.sh').exists())

    def test_management_mode_cannot_be_declared_by_unqualified_input(self):
        configuration = {'protocol':'vless','management_auth':'controller-mtls-v1',
                         'env':{'SSL_CLIENT_CERT_FILE':'/state/client.pem'},'files':{}}
        legacy = json.dumps([{'Config':{'Labels':{}}}])
        qualified = json.dumps([{'Config':{'Labels':{'org.rime.management.auth':'controller-mtls-v1'}}}])
        with patch('hy2bridge.remote_install.run',return_value=legacy):
            self.assertFalse(authenticated_management(configuration,'sha256:legacy'))
        with patch('hy2bridge.remote_install.run',return_value=qualified):
            with self.assertRaises(ValueError):
                authenticated_management(configuration,'sha256:qualified')
            configuration['files']['client.pem']='invalid certificate'
            with self.assertRaises(ValueError):
                authenticated_management(configuration,'sha256:qualified')

    def test_multi_transport_firewall_restricts_only_management_publications(self):
        directory=Path(self.tmp.name)
        units=directory/'host-units';units.mkdir()
        helpers=directory/'host-helpers';helpers.mkdir()
        def target(value):
            if str(value)=='/etc/systemd/system':return units
            if str(value)=='/etc/rime-node-firewalls':return helpers
            return Path(value)
        config={'id':'a'*32,'control_source':'8.8.8.8','publish':[
            [443,16443,'tcp'],[2053,16444,'tcp'],[9443,16445,'tcp'],
            [62050,62050,'tcp'],[62051,62051,'tcp']]}
        with patch('hy2bridge.remote_install.Path',side_effect=target), \
             patch('hy2bridge.remote_install.os.getuid',return_value=0,create=True), \
             patch('hy2bridge.remote_install.shutil.which',return_value='/synthetic/tool'), \
             patch('hy2bridge.remote_install.subprocess.run',return_value=MagicMock(returncode=0)):
            self.assertIsNone(control_firewall(config,directory))
        saved=json.loads((helpers/config['id']/'config.json').read_text())
        self.assertEqual(saved['ports'],[62050,62051])
        self.assertEqual(saved['panel_source'],'8.8.8.8')
        self.assertFalse((directory/'control-firewall.sh').exists())
        service=(units/('rime-node-firewall-'+config['id']+'.service')).read_text()
        self.assertNotIn(str(directory/'control-firewall.sh'),service)
        self.assertIn(str(helpers/config['id']/'worker.py'),service)
        self.assertIn('ExecStart='+sys.executable+' ',service)

    def test_legacy_cleanup_never_executes_the_container_writable_hook(self):
        directory=Path(self.tmp.name);identity='b'*32
        (directory/'control-firewall.json').write_text(json.dumps({'id':identity,'interface':'eth0'}))
        (directory/'control-firewall.sh').write_text('# untrusted container data')
        units=directory/'host-units';units.mkdir()
        def target(value):
            if str(value)=='/etc/systemd/system':return units
            if str(value)=='/etc/rime-node-firewalls':return directory/'absent-host-helper'
            if str(value)=='/run/systemd/system':return directory/'absent-runtime'
            return Path(value)
        with patch('hy2bridge.remote_install.Path',side_effect=target), \
             patch('hy2bridge.remote_install.subprocess.run',return_value=MagicMock(returncode=1)) as command:
            control_firewall({'id':identity},directory,remove=True)
        self.assertFalse(any('/bin/sh' in call.args[0] for call in command.call_args_list))
        self.assertTrue(any(call.args[0][:2]==['iptables','-F'] for call in command.call_args_list))

    def configured(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'node.example')])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                       .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName('node.example')]), critical=False)
                       .sign(private_key, hashes.SHA256()))
        certificate_path = Path(self.tmp.name) / 'cert.pem'
        key_path = Path(self.tmp.name) / 'key.pem'
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
        settings = {'allow_public_hosts': True, 'panel_url': 'https://panel.example',
                    'hy2_bundle': str(certificate_path), 'certificate_file': str(certificate_path),
                    'certificate_key_file': str(key_path)}
        provision = Provisioner(self.store, settings, None, None, None)
        data = {'name': 'Synthetic', 'host': 'ssh.example', 'ssh_port': 22, 'domain': 'node.example',
                'address': '8.8.8.8', 'vpn_port': 443, 'protocol': 'hysteria2'}
        return provision, data

    @staticmethod
    def records(addresses):
        return [(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 0))
                for address in addresses]

    def dns(self, hosts, domain):
        return lambda name, *args: self.records(hosts if name == 'ssh.example' else domain)

    def test_dns_must_match_the_exact_pinned_ipv4(self):
        provision, data = self.configured()
        with patch('hy2bridge.provision.socket.getaddrinfo', side_effect=self.dns(['8.8.8.8', '1.1.1.1'], ['1.1.1.1'])):
            with self.assertRaisesRegex(ProvisionError, 'только на выбранный IPv4'):
                provision.validate(data)

    def test_additional_a_records_and_unsupported_aaaa_are_rejected(self):
        provision, data = self.configured()
        for addresses in [['8.8.8.8', '1.1.1.1'], ['8.8.8.8', '2001:4860:4860::8888']]:
            with self.subTest(addresses=addresses):
                with patch('hy2bridge.provision.socket.getaddrinfo', side_effect=self.dns(['8.8.8.8'], addresses)):
                    with self.assertRaises(ProvisionError):
                        provision.validate(dict(data))

    def test_single_matching_a_record_and_lab_exception_remain_supported(self):
        provision, data = self.configured()
        with patch('hy2bridge.provision.socket.getaddrinfo', side_effect=self.dns(['8.8.8.8'], ['8.8.8.8'])):
            provision.validate(data)
        self.assertEqual(data['address'], '8.8.8.8')
        provision.settings['lab_network'] = 'bridge'
        with patch('hy2bridge.provision.socket.getaddrinfo') as resolve:
            provision.validate(dict(data))
        resolve.assert_not_called()

    def test_daemon_unavailable_cannot_remove_firewall_or_claim_rollback(self):
        failed = subprocess.CompletedProcess([], 1, '[]', 'Cannot connect to the Docker daemon')
        with patch('hy2bridge.remote_install.Path.home', return_value=Path(self.tmp.name)), \
                patch('hy2bridge.remote_install.subprocess.run', return_value=failed), \
                patch('hy2bridge.remote_install.control_firewall') as firewall, \
                patch('hy2bridge.remote_install.remove_transfers') as transfers:
            with self.assertRaisesRegex(RuntimeError, 'state cannot be confirmed'):
                remote({'id': 'a' * 32, 'action': 'rollback'})
        firewall.assert_not_called()
        transfers.assert_not_called()

    def test_confirmed_absence_removes_only_exact_transfer_files(self):
        parent = Path(self.tmp.name) / '.local/share/fleet-nodes'
        parent.mkdir(parents=True)
        job = 'b' * 32
        for suffix in ['.tar.gz', '.image.tar.gz']:
            (parent / (job + suffix)).write_bytes(b'partial')
        retained = parent / ('c' * 32 + '.image.tar.gz')
        retained.write_bytes(b'retain')

        def missing(arguments, **kwargs):
            self.assertEqual(arguments[:2], ['docker', 'inspect'])
            return subprocess.CompletedProcess(arguments, 1, '[]', 'Error: No such object: ' + arguments[-1] + '\n')

        with patch('hy2bridge.remote_install.Path.home', return_value=Path(self.tmp.name)), \
                patch('hy2bridge.remote_install.subprocess.run', side_effect=missing), \
                patch('hy2bridge.remote_install.control_firewall') as firewall:
            result = remote({'id': job, 'action': 'rollback'})
        self.assertFalse(result['removed'])
        self.assertEqual(list(parent.iterdir()), [retained])
        firewall.assert_called_once()

    def test_foreign_container_preserves_both_firewall_and_transfers(self):
        foreign = {'Config': {'Labels': {'fleet.job': 'other'}}}
        with patch('hy2bridge.remote_install.Path.home', return_value=Path(self.tmp.name)), \
                patch('hy2bridge.remote_install.inspect_container', side_effect=[None, foreign]), \
                patch('hy2bridge.remote_install.run') as command, \
                patch('hy2bridge.remote_install.control_firewall') as firewall, \
                patch('hy2bridge.remote_install.remove_transfers') as transfers:
            with self.assertRaisesRegex(RuntimeError, 'ownership mismatch'):
                remote({'id': 'd' * 32, 'action': 'rollback'})
        command.assert_not_called()
        firewall.assert_not_called()
        transfers.assert_not_called()

    def transfer_failure(self, rollback_fails=False):
        settings = {'base_image_bundle': 'synthetic.image.tar.gz', 'base_image_bundle_sha256': '0' * 64}
        provision = Provisioner(self.store, settings, MagicMock(), MagicMock(), None)
        provision.validate = MagicMock()
        provision.configuration = MagicMock(return_value={'id': 'e' * 32, 'publish': [], 'image': 'sha256:' + '0' * 64})
        provision.connect = MagicMock()
        if rollback_fails:
            provision.connect.side_effect = [MagicMock(), ProvisionError('Synthetic SSH unavailable')]
        provision.remote = MagicMock(side_effect=[{'present': False}, {'removed': False}])
        provision.upload = MagicMock(side_effect=OSError('Synthetic partial upload'))
        data = {'host': 'node.example', 'address': '8.8.8.8', 'protocol': 'vless'}
        provision.worker({'data': data, 'plan': {'id': 'e' * 32}, 'remote': {'home': '/root'}})
        self.assertEqual(data, {})
        provision.unregister.assert_not_called()
        return provision

    def test_interrupted_upload_gets_ownership_checked_remote_cleanup(self):
        provision = self.transfer_failure()
        self.assertEqual(provision.job('e' * 32)['state'], 'rolled_back')
        self.assertEqual([call.args[1]['action'] for call in provision.remote.call_args_list], ['image-present', 'rollback'])

    def test_unreachable_upload_cleanup_remains_failed_for_explicit_retry(self):
        provision = self.transfer_failure(rollback_fails=True)
        self.assertEqual(provision.job('e' * 32)['state'], 'failed')
        self.assertEqual(provision.remote.call_count, 1)
