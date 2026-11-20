"""Regressions for the native RPyC lifecycle across controller loss."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


class RPyCAutonomyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'rpyc_service.py'
        self.path.write_text('''
@rpyc.service
class XrayService:
    def __init__(self): pass
    def on_connect(self, conn): pass
    def on_disconnect(self, conn): pass
    @rpyc.exposed
    def start(self, config): pass
    @rpyc.exposed
    def stop(self): pass
    @rpyc.exposed
    def restart(self, config): pass
''')
        spec = importlib.util.spec_from_file_location('rpyc_stage_patch', ROOT / 'node-runtime/apply.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.patch_rpyc(self.root)
        autonomy = ModuleType('node_autonomy')
        exec((ROOT / 'node-runtime/node_autonomy.py').read_text(), autonomy.__dict__)
        self.xray = ModuleType('xray')
        self.xray.RIME_API_MTLS = True
        self.modules = patch.dict(sys.modules, {'node_autonomy':autonomy,'xray':self.xray})
        self.modules.start()
        self.addCleanup(self.modules.stop)

        class Config(dict):
            def __init__(self, value, peer):
                super().__init__(json.loads(value))

            def to_json(self):
                return json.dumps(self)

        class Core:
            instances = []

            def __init__(self, **kwargs):
                self.started = False
                self.stop = Mock(side_effect=self.stopped)
                self.instances.append(self)
                self.unread_bytes = 12345

            def start(self, config):
                self.started = True

            def stopped(self):
                self.started = False

            def on_start(self, callback):
                return callback

            def on_stop(self, callback):
                return callback

        namespace = {'rpyc':SimpleNamespace(service=lambda owner:owner, exposed=lambda method:method),
                     'XRayConfig':Config, 'XRayCore':Core, 'logger':Mock(),
                     'socket':SimpleNamespace(getpeername=lambda sock:('192.0.2.20',12345)),
                     'XRAY_EXECUTABLE_PATH':'/fixture/xray', 'XRAY_ASSETS_PATH':'/fixture/assets'}
        exec(compile(self.path.read_text(), str(self.path), 'exec'), namespace)
        self.service = namespace['XrayService']()
        self.connection = self.connection_fixture()
        self.service.on_connect(self.connection)
        self.config = {'inbounds':[{'tag':'vpn','protocol':'vless','port':443,
                                   'settings':{'clients':[{'id':'original-user'}]}}]}
        self.service.start(json.dumps(self.config))
        self.core = self.service.core

    @staticmethod
    def connection_fixture():
        return SimpleNamespace(ping=Mock(), close=Mock(), root=SimpleNamespace(),
                               _channel=SimpleNamespace(close=Mock(),stream=SimpleNamespace(sock=object())))

    def test_lost_controller_preserves_running_core_and_unread_counters(self):
        self.service.on_disconnect(self.connection)
        self.assertIsNone(self.service.connection)
        self.assertIs(self.service.core, self.core)
        self.assertTrue(self.core.started)
        self.assertEqual(self.core.unread_bytes, 12345)
        self.core.stop.assert_not_called()

    def test_verified_reconnect_reuses_core_with_authoritative_user_config(self):
        self.service.on_disconnect(self.connection)
        replacement = self.connection_fixture()
        self.service.on_connect(replacement)
        self.config['inbounds'][0]['settings']['clients'] = [{'id':'current-user'}]
        result = self.service.start(json.dumps(self.config), users_verified=True)
        self.assertIs(self.service.core, self.core)
        self.core.stop.assert_not_called()
        self.assertTrue(json.loads(result)['started'])
        self.assertEqual(json.loads(self.service._rime_effective)['inbounds'][0]['settings']['clients'],
                         [{'id':'current-user'}])

    def test_older_controller_can_start_with_the_original_rpc_signature(self):
        self.service.on_disconnect(self.connection)
        self.service.on_connect(self.connection_fixture())
        self.service.start(json.dumps(self.config))
        self.core.stop.assert_called_once()
        self.assertIsNot(self.service.core, self.core)
        self.assertTrue(self.service.core.started)

    def test_read_only_probe_does_not_claim_or_ping_the_owner(self):
        other = self.connection_fixture()
        self.service.on_connect(other)
        self.service.capabilities()
        other.close.assert_not_called()
        self.connection.ping.assert_not_called()
        self.service.on_disconnect(other)
        self.assertIs(self.service.connection, self.connection)
        self.assertTrue(self.core.started)
        self.core.stop.assert_not_called()

    def test_explicit_claim_fences_the_previous_owner(self):
        previous_owner = json.loads(self.service.capabilities())['owner']
        replacement = self.connection_fixture()
        self.service.on_connect(replacement)
        self.service.claim(previous_owner)
        self.connection.ping.assert_not_called()
        self.connection._channel.close.assert_called_once()
        self.connection.close.assert_not_called()
        self.service.on_disconnect(self.connection)
        self.assertIs(self.service.connection, replacement)
        self.assertTrue(self.core.started)

    def test_stale_claim_preserves_the_current_owner(self):
        other = self.connection_fixture()
        self.service.on_connect(other)
        with self.assertRaises(ConnectionError):
            self.service.claim('stale-owner')
        self.assertIs(self.service.connection, self.connection)
        self.connection.close.assert_not_called()
        with self.assertRaises(ConnectionError):
            self.service.stop()
        self.assertTrue(self.core.started)

    def test_invalid_configuration_retains_the_existing_core(self):
        with self.assertRaises(ValueError):
            self.service.start('{invalid', users_verified=True)
        self.core.stop.assert_not_called()
        self.assertIs(self.service.core, self.core)
        self.assertTrue(self.core.started)

    def test_explicit_stop_and_restart_still_control_the_core(self):
        self.service.restart(json.dumps(self.config))
        self.core.stop.assert_called_once()
        replacement = self.service.core
        self.assertIsNot(replacement, self.core)
        self.service.stop()
        replacement.stop.assert_called_once()
        self.assertIsNone(self.service.core)

    def test_static_listener_change_requires_replacing_the_core(self):
        self.config['inbounds'][0]['port'] = 8443
        self.service.start(json.dumps(self.config), users_verified=True)
        self.core.stop.assert_called_once()
        self.assertIsNot(self.service.core, self.core)

    def test_legacy_api_is_not_advertised_as_mutually_authenticated(self):
        self.xray.RIME_API_MTLS = False
        self.assertEqual(json.loads(self.service.capabilities())['api_mtls'],0)


if __name__ == '__main__':
    unittest.main()
