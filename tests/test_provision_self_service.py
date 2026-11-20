import datetime
import io
import socket
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import test_accounting
from hy2bridge.bootstrap import inspect
from hy2bridge.operations import Operations
from hy2bridge.provision import Provisioner, ProvisionError
from hy2bridge.reachability import Reachability
from hy2bridge.registry import Registry


class SelfServiceTests(unittest.TestCase):
    setUp = test_accounting.AccountingTests.setUp
    tearDown = test_accounting.AccountingTests.tearDown

    def addresses(self, values):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (value, 22)) for value in values]

    def provisioner(self, settings=None, **callbacks):
        return Provisioner(self.store, settings or {}, MagicMock(), MagicMock(), lambda *_: True, **callbacks)

    def test_public_targets_require_explicit_opt_in(self):
        instance = self.provisioner()
        with self.assertRaises(ProvisionError):
            instance.target('8.8.8.8', 22)
        instance.settings['allow_public_hosts'] = True
        with patch('hy2bridge.provision.socket.getaddrinfo', return_value=self.addresses(['8.8.8.8'])):
            self.assertEqual(instance.resolve('node.example', 22), ['8.8.8.8'])

    def test_private_reserved_and_mixed_dns_targets_are_rejected(self):
        instance = self.provisioner({'allow_public_hosts': True})
        for address in ['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1', '192.0.2.1', '224.0.0.1']:
            with self.subTest(address=address):
                with patch('hy2bridge.provision.socket.getaddrinfo', return_value=self.addresses(['8.8.8.8', address])):
                    with self.assertRaises(ProvisionError):
                        instance.resolve('node.example', 22)

    def test_explicit_arena_target_accepts_private_address(self):
        instance = self.provisioner({'allowed_hosts': ['node.lab.invalid']})
        with patch('hy2bridge.provision.socket.getaddrinfo', return_value=self.addresses(['172.25.0.2'])):
            self.assertEqual(instance.resolve('node.lab.invalid', 22), ['172.25.0.2'])

    def test_panel_address_is_protected_through_dns_alias(self):
        instance = self.provisioner({'allow_public_hosts': True, 'protected_hosts': ['8.8.8.8']})
        with patch('hy2bridge.provision.socket.getaddrinfo', return_value=self.addresses(['8.8.8.8'])):
            with self.assertRaises(ProvisionError):
                instance.resolve('alias.example', 22)

    def test_changed_dns_stops_before_ssh_credentials_are_used(self):
        instance = self.provisioner({'allow_public_hosts': True})
        data = {'host': 'node.example', 'ssh_port': 22, 'address': '1.1.1.1'}
        with patch.object(instance, 'resolve', return_value=['8.8.8.8']), patch('paramiko.SSHClient') as client:
            with self.assertRaises(ProvisionError):
                instance.connect(data)
            client.assert_not_called()

    def test_automatic_certificate_stays_out_of_plan(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '*.lab.invalid')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('*.lab.invalid')]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = Path(self.tmp.name) / 'cert.pem', Path(self.tmp.name) / 'key.pem'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        instance = self.provisioner({'allowed_hosts': ['node.lab.invalid'], 'lab_network': 'bridge',
                                    'panel_url': 'https://panel.lab.invalid', 'vless_template': {},
                                    'hy2_bundle': str(cert_path), 'certificate_file': str(cert_path),
                                    'certificate_key_file': str(key_path)})
        data = {'name': 'Test', 'host': 'node.lab.invalid', 'ssh_port': 22, 'vpn_port': 443,
                'protocol': 'hysteria2', 'domain': 'node.lab.invalid', 'password': 'synthetic-secret'}
        instance.connect = MagicMock()
        instance.remote = MagicMock(return_value={'home': '/root', 'uid': 0, 'checks': [{'passed': True}]})
        runtime = {'python_available': True, 'docker_installed': True, 'bootstrap_required': False}
        with patch('hy2bridge.bootstrap.inspect', return_value=runtime), patch('threading.Timer'):
            plan = instance.preflight(data)
        self.assertTrue(plan['ready'])
        self.assertNotIn('PRIVATE KEY', str(plan))
        self.assertNotIn('synthetic-secret', str(plan))
        instance.validate({**data, 'domain': 'another.lab.invalid'})
        with self.assertRaises(ProvisionError):
            instance.validate({**data, 'domain': 'outside.example'})

    def test_expired_plan_forgets_credentials_and_does_not_reserve_target(self):
        instance = self.provisioner()
        data = {'host': 'node.example', 'password': 'synthetic-secret'}
        instance.plans['a' * 32] = {'data': data, 'plan': {'expires_at': time.time() - 1, 'ready': True}}
        with self.assertRaises(ProvisionError):
            instance.deploy('a' * 32)
        self.assertEqual(data, {})
        self.assertEqual(instance.running, set())

    def test_concurrent_plan_keeps_credentials_available_for_later_retry(self):
        instance = self.provisioner()
        for job in ['a' * 32, 'b' * 32]:
            instance.plans[job] = {'data': {'host': 'node.example', 'password': 'synthetic'},
                                   'plan': {'id': job, 'expires_at': time.time() + 60, 'ready': True}}
        with patch('threading.Thread'):
            instance.deploy('a' * 32)
            with self.assertRaises(ProvisionError):
                instance.deploy('b' * 32)
        self.assertIn('b' * 32, instance.plans)

    def test_payload_is_checked_before_publication(self):
        sequence = []
        instance = self.provisioner({'hy2_bundle':'synthetic.tar.gz'},activate=lambda *_: sequence.append('activate'),
                                   verify=lambda *_: sequence.append('payload'))
        instance.validate = lambda _: None
        instance.configuration = lambda job, *_: {'id': job, 'publish': []}
        instance.connect = lambda _: MagicMock()
        instance.remote = MagicMock(return_value={'running': True})
        job = 'c' * 32
        instance.worker({'data': {'protocol': 'hysteria2', 'host': 'node.example'}, 'plan': {'id': job},'remote':{'home':'/root'}})
        self.assertEqual(sequence, ['payload', 'activate'])
        self.assertEqual(instance.job(job)['state'], 'succeeded')

    def test_global_capacity_preserves_plan_for_retry(self):
        instance = self.provisioner({'max_concurrent_installs': 1})
        instance.running.add('other.example')
        job = 'e' * 32
        instance.plans[job] = {'data': {'host': 'node.example'},
                               'plan': {'id': job, 'expires_at': time.time() + 60, 'ready': True}}
        with self.assertRaises(ProvisionError):
            instance.deploy(job)
        self.assertIn(job, instance.plans)
        self.assertEqual(instance.running, {'other.example'})

    def test_failed_payload_rolls_back_without_publication(self):
        activate = MagicMock()
        instance = self.provisioner({'hy2_bundle':'synthetic.tar.gz'},activate=activate, verify=MagicMock(side_effect=ProvisionError('synthetic failure')))
        instance.validate = lambda _: None
        instance.configuration = lambda job, *_: {'id': job, 'publish': []}
        instance.connect = lambda _: MagicMock()
        instance.remote = MagicMock(return_value={'running': True})
        job = 'd' * 32
        instance.worker({'data': {'protocol': 'hysteria2', 'host': 'node.example'}, 'plan': {'id': job},'remote':{'home':'/root'}})
        activate.assert_not_called()
        self.assertEqual(instance.job(job)['state'], 'rolled_back')

    def test_local_client_result_requires_managed_node_and_has_no_external_credential(self):
        operations = Operations(self.store)
        Registry(self.store)
        operations.ensure_node('node')
        reachability = Reachability(self.store)
        sample = {'passed': True, 'stage': 'payload', 'checked_at': time.time(), 'target_ip': '8.8.8.8'}
        with self.assertRaises(ValueError):
            reachability.ingest_local('node', sample, 'Synthetic panel')
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_managed(id,protocol,name,domain,port) VALUES('node','hysteria2','Node','node.invalid',443)")
        reachability.ingest_local('node', sample, 'Synthetic panel')
        self.assertFalse(reachability.authorize('panel-managed', 'node', 'Bearer anything'))
        with self.store.connection() as db:
            self.assertEqual(reachability.summary(db, 'node')['origin'], 'Synthetic panel')

    def test_bootstrap_port_check_distinguishes_udp_from_tcp(self):
        raw = '0\n0\n/root\nLinux\nx86_64\n/usr/bin/python3\n\n/usr/bin/apt-get\nunavailable\n1048576\n4194304\nTCP_SOCKETS\n0: 00000000:01BB 00000000:0000 0A\nUDP_SOCKETS\n'
        output = MagicMock()
        output.read.return_value = raw.encode()
        output.channel.recv_exit_status.return_value = 0
        client = MagicMock()
        client.exec_command.return_value = (None, output, io.BytesIO())
        result = inspect(client, [(443, 'udp'), (443, 'tcp')])
        self.assertTrue(result['bootstrap_required'])
        self.assertTrue(result['checks'][-2]['passed'])
        self.assertFalse(result['checks'][-1]['passed'])
