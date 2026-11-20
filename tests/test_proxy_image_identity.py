import hashlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import test_accounting
import test_proxy
from hy2bridge.provision import ProvisionError
from hy2bridge.proxy_install import RemoteError, main, resolve_image


EXPECTED = 'sha256:' + '1' * 64
PLATFORM = 'sha256:' + '2' * 64


class ProxyImageIdentityTests(unittest.TestCase):
    setUp = test_accounting.AccountingTests.setUp
    tearDown = test_accounting.AccountingTests.tearDown

    def test_classic_store_uses_the_original_config_digest(self):
        with patch('hy2bridge.proxy_install.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '[]', '')) as run:
            self.assertEqual(resolve_image(EXPECTED, [PLATFORM]), EXPECTED)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][-1], EXPECTED)

    def test_containerd_store_uses_only_a_verified_platform_digest(self):
        def inspect(arguments, **kwargs):
            if arguments[-1] == EXPECTED:
                return subprocess.CompletedProcess(arguments, 1, '[]', 'Error: No such image: ' + EXPECTED)
            self.assertEqual(arguments[-1], PLATFORM)
            return subprocess.CompletedProcess(arguments, 0, '[]', '')
        with patch('hy2bridge.proxy_install.subprocess.run', side_effect=inspect):
            self.assertEqual(resolve_image(EXPECTED, [PLATFORM]), PLATFORM)

    def test_missing_candidates_do_not_fall_back_to_a_mutable_tag(self):
        failed = subprocess.CompletedProcess([], 1, '[]', 'Error: No such image')
        with patch('hy2bridge.proxy_install.subprocess.run', return_value=failed) as run:
            self.assertIsNone(resolve_image(EXPECTED, [PLATFORM]))
        self.assertEqual([call.args[0][-1] for call in run.call_args_list], [EXPECTED, PLATFORM])
        with patch('hy2bridge.proxy_install.subprocess.run') as run:
            with self.assertRaises(ValueError):
                resolve_image(EXPECTED, ['rime-proxy-runtime:latest'])
        run.assert_not_called()

    def test_daemon_error_fails_closed_without_searching_other_references(self):
        failed = subprocess.CompletedProcess([], 1, '[]', 'Cannot connect to Docker daemon')
        with patch('hy2bridge.proxy_install.subprocess.run', return_value=failed) as run:
            with self.assertRaises(RuntimeError):
                resolve_image(EXPECTED, [PLATFORM])
        self.assertEqual(run.call_count, 1)

    def configuration(self):
        job = 'a' * 32
        directory = Path(self.tmp.name) / job
        bundle = directory.parent / (job + '.image.tar.gz')
        bundle.write_bytes(b'synthetic-verified-image')
        config = {'id': job, 'node': 'synthetic-node', 'action': 'install', 'image': EXPECTED,
                  'image_candidates': [PLATFORM], 'image_bundle': str(bundle),
                  'image_bundle_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest(),
                  'files': {'squid.conf': 'synthetic', 'passwd': 'synthetic:hash\n'}, 'publish': [(3128, 3128)]}
        return directory, bundle, config

    def test_loaded_proxy_runs_the_resolved_digest_on_containerd(self):
        directory, bundle, config = self.configuration()
        with patch('hy2bridge.proxy_install.paths', return_value=(directory, 'synthetic-proxy')), \
                patch('hy2bridge.proxy_install.os.getuid', return_value=0, create=True), \
                patch('hy2bridge.proxy_install.os.chown', create=True), \
                patch('hy2bridge.proxy_install.inspect_container', side_effect=[None, {'State': {'Running': True}}]), \
                patch('hy2bridge.proxy_install.resolve_image', side_effect=[None, PLATFORM]) as resolve, \
                patch('hy2bridge.proxy_install.command') as command:
            self.assertTrue(main(config)['running'])
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(command.call_args_list[0].args[0], ['docker', 'load', '-i', str(bundle)])
        self.assertEqual(command.call_args_list[1].args[0][-1], PLATFORM)
        self.assertFalse(bundle.exists())

    def test_successful_load_with_unresolved_identity_never_starts_proxy(self):
        directory, bundle, config = self.configuration()
        with patch('hy2bridge.proxy_install.paths', return_value=(directory, 'synthetic-proxy')), \
                patch('hy2bridge.proxy_install.os.getuid', return_value=0, create=True), \
                patch('hy2bridge.proxy_install.inspect_container', return_value=None), \
                patch('hy2bridge.proxy_install.resolve_image', return_value=None), \
                patch('hy2bridge.proxy_install.command') as command:
            with self.assertRaises(RemoteError) as failure:
                main(config)
        self.assertEqual(failure.exception.code, 'image_identity_unresolved')
        command.assert_called_once_with(['docker', 'load', '-i', str(bundle)])
        self.assertTrue(bundle.exists())

    def test_proxy_remote_injects_only_candidates_from_the_verified_artifact(self):
        service = test_proxy.ProxyTests.configure(self)
        incoming, output = MagicMock(), MagicMock()
        output.read.return_value = b'{"present": true}'
        output.channel.recv_exit_status.return_value = 0
        client = MagicMock()
        client.exec_command.return_value = (incoming, output, io.BytesIO())
        config = {'id': 'b' * 32, 'action': 'image-present', 'image': EXPECTED}
        with patch('hy2bridge.provision.archive_image_candidates', return_value=[PLATFORM]) as candidates:
            self.assertTrue(service.remote(client, config)['present'])
        candidates.assert_called_once_with(service.settings['image_bundle'], service.settings['image_bundle_sha256'], EXPECTED)
        self.assertEqual(json.loads(incoming.write.call_args.args[0])['image_candidates'], [PLATFORM])
        self.assertNotIn('image_candidates', config)

    def test_remote_errors_use_allowlisted_text_without_echoing_untrusted_output(self):
        service = test_proxy.ProxyTests.configure(self)
        for code in ['image_identity_unresolved', 'untrusted-secret-code']:
            output = MagicMock()
            output.read.return_value = json.dumps({'code': code, 'error': 'untrusted-secret-error'}).encode()
            output.channel.recv_exit_status.return_value = 1
            client = MagicMock()
            client.exec_command.return_value = (MagicMock(), output, io.BytesIO(b'untrusted-secret-stderr'))
            with self.assertRaises(ProvisionError) as failure:
                service.remote(client, {'id': 'c' * 32, 'action': 'rollback'})
            self.assertNotIn('untrusted-secret', str(failure.exception))
            if code == 'image_identity_unresolved':
                self.assertIn('Docker загрузил архив', str(failure.exception))
