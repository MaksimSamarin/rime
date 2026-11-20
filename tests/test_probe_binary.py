import copy
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hy2bridge.client_checks import ClientChecks
from hy2bridge.client_probe import probe, xray_probe_binary
from hy2bridge.provision_probe import ProvisionProbe
from hy2bridge.relays import Relays


class ProbeBinaryTests(unittest.TestCase):
    def test_packaged_client_is_preferred_when_executable(self):
        with patch('hy2bridge.client_probe.os.access', return_value=True) as access:
            self.assertEqual(xray_probe_binary({}), '/opt/rime-probe/xray')
        access.assert_called_once_with('/opt/rime-probe/xray', 1)

    def test_legacy_client_remains_the_fallback(self):
        with patch('hy2bridge.client_probe.os.access', return_value=False):
            self.assertEqual(xray_probe_binary({}), '/usr/local/bin/xray')

    def test_explicit_paths_are_preserved_even_when_unavailable(self):
        cases = [
            ({'xray_binary': '/custom/missing-xray'}, '/custom/missing-xray'),
            ({'client_probe_xray_binary': '/custom/missing-probe',
              'xray_binary': '/custom/xray'}, '/custom/missing-probe'),
        ]
        for settings, expected in cases:
            with self.subTest(settings=settings):
                with patch('hy2bridge.client_probe.os.access') as access:
                    self.assertEqual(xray_probe_binary(settings), expected)
                access.assert_not_called()

    def test_standalone_probe_uses_the_packaged_default(self):
        target = probe_target()
        with patch('hy2bridge.client_probe.os.access', return_value=True):
            with patch('hy2bridge.client_probe.subprocess.Popen', side_effect=OSError) as launch:
                probe(target, {'direct_targets': ['192.0.2.10']}, 12345)
        self.assertEqual(launch.call_args.args[0][0], '/opt/rime-probe/xray')

    def test_missing_explicit_client_reports_configuration_failure(self):
        with patch('hy2bridge.client_probe.os.access', return_value=False) as access:
            with patch('hy2bridge.client_probe.subprocess.Popen') as launch:
                result = probe(probe_target(), {'direct_targets': ['192.0.2.10'],
                    'xray_binary': '/custom/missing-xray'}, 12345)
        access.assert_called_once_with('/custom/missing-xray', 1)
        launch.assert_not_called()
        self.assertFalse(result['passed'])
        self.assertEqual(result['stage'], 'configuration')


def probe_target():
    return {'node': 'node-a', 'expected_ip': '192.0.2.10', 'resolved_ip': '192.0.2.10',
        'config': {'_hostname': 'node.example',
            'inbounds': [{'port': 0}],
            'outbounds': [{'settings': {'vnext': [{'address': '192.0.2.10', 'port': 443}]}}]}}


class ProbeBinaryEntryPointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'probe.json'
        self.path.write_text(json.dumps({'id': 'origin', 'direct_targets': ['192.0.2.10'],
            'targets': [probe_target()]}))
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''CREATE TABLE fleet_inventory(id TEXT,address TEXT);
            INSERT INTO fleet_inventory VALUES('node-a','192.0.2.10');
            CREATE TABLE fleet_client_check_generation(node TEXT,version TEXT);''')

    def test_manual_install_transfer_periodic_and_relay_use_the_same_client(self):
        cases = [
            ({}, True, '/opt/rime-probe/xray'),
            ({}, False, '/usr/local/bin/xray'),
            ({'xray_binary': '/custom/xray'}, True, '/custom/xray'),
            ({'client_probe_xray_binary': '/custom/probe',
              'xray_binary': '/custom/xray'}, False, '/custom/probe'),
        ]
        for settings, packaged, expected in cases:
            with self.subTest(settings=settings, packaged=packaged):
                settings = {**settings, 'client_probe_config': str(self.path), 'client_probe_id': 'origin'}
                with patch('hy2bridge.client_probe.os.access', return_value=packaged):
                    self.assert_entry_points(settings, expected)

    def assert_entry_points(self, settings, expected):
        manual = object.__new__(ClientChecks)
        manual.settings = settings
        manual.reachability = SimpleNamespace(entries={'origin': {'nodes': ['node-a'], 'label': 'Origin'}})
        manual_settings = manual._prepare('node-a', self.db)['settings']
        self.assertEqual(manual_settings['xray_binary'], expected)

        reachability = SimpleNamespace(ingest_local=lambda *_args, **_kwargs: None)
        monitor = ProvisionProbe(None, settings, reachability, None)
        monitor.target = lambda *_: probe_target()
        monitor.active_target = lambda *_: probe_target()
        with patch('hy2bridge.provision_probe.probe', return_value={'passed': True}) as run:
            monitor.run('job', {}, attempts=1)
            monitor.run('job', {}, attempts=1, follow_dns=True)
            monitor.run_targets([probe_target()], 'job')
        self.assertEqual(len(run.call_args_list), 3)
        for call in run.call_args_list:
            self.assertEqual(call.args[1]['xray_binary'], expected)
            self.assertEqual(call.args[1]['direct_targets'], ['192.0.2.10'])

        relay = object.__new__(Relays)
        relay.settings = settings
        relay.transfer = SimpleNamespace(probe=SimpleNamespace(
            transfer_targets=lambda *_: [copy.deepcopy(probe_target())]))
        services = [{'kind': 'vpn', 'origin_port': 443, 'public_port': 10443}]
        with patch('hy2bridge.client_probe.probe', return_value={'passed': True, 'stage': 'payload'}) as run:
            relay.verify_route({}, {}, {'name': 'Entry', 'address': '192.0.2.20'}, '192.0.2.10', services)
        self.assertEqual(run.call_args.args[1]['xray_binary'], expected)
        self.assertEqual(run.call_args.args[1]['direct_targets'], ['192.0.2.20'])
        self.assertEqual(run.call_args.args[0]['resolved_ip'], '192.0.2.20')


if __name__ == '__main__':
    unittest.main()
