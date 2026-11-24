"""The installer must wait for the destination's management TLS pair."""
import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hy2bridge import remote_install
from test_native_certificate_pinning import certificate


class ProvisionIdentityStartupTests(unittest.TestCase):
    def install(self, *, delayed_identity=False, stops_at=None):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            job = 'a' * 32
            directory = home / '.local/share/fleet-nodes' / job
            cert, key = certificate(home, 'management')
            elapsed = 0.0

            def sleep(seconds):
                nonlocal elapsed
                elapsed += seconds
                if delayed_identity and elapsed >= 4:
                    (directory / 'node-cert.pem').write_bytes(cert.read_bytes())
                    pem = key.read_bytes() if elapsed >= 5 else b'incomplete key'
                    (directory / 'node-key.pem').write_bytes(pem)

            def docker(args):
                if args[:2] == ['docker', 'run']:
                    return 'synthetic-container'
                self.assertEqual(args, ['docker', 'inspect', 'fleet-' + job])
                return json.dumps([{
                    'State': {'Running': stops_at is None or elapsed < stops_at},
                    'NetworkSettings': {'Networks': {}},
                }])

            clock = SimpleNamespace(monotonic=lambda: elapsed, sleep=sleep)
            with (
                patch.object(remote_install, 'time', clock),
                patch.object(remote_install.Path, 'home', return_value=home),
                patch.object(remote_install.os, 'umask'),
                patch.object(remote_install.os, 'getuid', return_value=0, create=True),
                patch.object(remote_install.os, 'getgid', return_value=0, create=True),
                patch.object(remote_install, 'resolve_image', return_value='synthetic-image'),
                patch.object(remote_install, 'control_firewall', return_value=None),
                patch.object(remote_install, 'run', side_effect=docker),
                patch.object(remote_install.subprocess, 'run', return_value=
                             subprocess.CompletedProcess([], 0, 'fixture logs', '')),
            ):
                result = remote_install.main({
                    'action': 'install', 'id': job, 'protocol': 'vless',
                    'files': {}, 'image': 'synthetic-image', 'publish': [],
                    'lab_network': 'none', 'export_identity': True,
                })
            if delayed_identity:
                self.assertGreaterEqual(elapsed, 5)
                self.assertEqual(result.get('management_tls'), {
                    'certificate': cert.read_text(), 'key': key.read_text(),
                })
            return result, elapsed

    def test_waits_past_running_and_partial_key_for_a_valid_pair(self):
        result, _ = self.install(delayed_identity=True)
        self.assertTrue(result['running'])

    def test_missing_identity_has_a_specific_failure(self):
        with self.assertRaisesRegex(remote_install.RemoteError, 'management_identity_not_ready'):
            self.install()

    def test_exit_while_waiting_reports_the_container_stopped(self):
        result, elapsed = self.install(stops_at=3)
        self.assertFalse(result['running'])
        self.assertNotIn('management_tls', result)
        self.assertLess(elapsed, 30)
