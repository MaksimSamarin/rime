"""Prepublication native checks preserve the current controller session."""
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hy2bridge.native_management import probe_management, read_rest, read_rpyc


class RelayManagementProbeTests(unittest.TestCase):
    def setUp(self):
        self.source = {'native':{'id':1,'address':'192.0.2.20','port':62050,'api_port':62051}}
        self.profile = {'vpn':{'management_auth':'controller-mtls-v1','management_protocol':'rest',
                               'management_tls':{'certificate':'fixture-node-certificate'}}}
        self.entry = {'address':'192.0.2.10'}
        self.services = [{'id':'rpc','kind':'management','origin_port':62050,'public_port':62450},
                         {'id':'api','kind':'management','origin_port':62051,'public_port':62451}]
        self.credentials = lambda:('fixture-client-key','fixture-client-certificate')
        self.cached = patch('hy2bridge.native_management.cached_node',return_value=None)
        self.cached.start()
        self.addCleanup(self.cached.stop)
        self.environment = patch.dict(os.environ,{'RIME_NODE_CONTROL_OVERRIDES':'{}'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.context = patch('hy2bridge.native_management.ssl.create_default_context')
        self.context.start()
        self.addCleanup(self.context.stop)
        self.api = patch('hy2bridge.native_management.XRay')
        self.make_api = self.api.start()
        self.addCleanup(self.api.stop)

    def run_probe(self):
        return probe_management(self.source,self.profile,self.entry,self.services,self.credentials)

    def test_rest_uses_read_only_status_then_authenticated_stats(self):
        with patch('hy2bridge.native_management.read_rest',return_value={'started':True,'api_mtls':1,'management_sources':1,'api_direct':1}) as status:
            result = self.run_probe()
        self.assertTrue(result['passed'])
        self.assertTrue(result['management_passed'])
        status.assert_called_once()
        self.make_api.return_value.get_sys_stats.assert_called_once_with(timeout=3)
        self.make_api.return_value._channel.close.assert_called_once()
        options = self.make_api.call_args.kwargs
        self.assertEqual(options['ssl_key'],b'fixture-client-key')
        self.assertEqual(options['client_cert'],b'fixture-client-certificate')
        self.assertEqual(options['control_identity'],('192.0.2.20',62051))
        self.assertEqual([row['stage'] for row in result['services']],['control','api'])

    def test_unqualified_rpyc_does_not_open_any_new_connection(self):
        self.profile['vpn'].pop('management_auth')
        self.profile['vpn']['management_protocol'] = 'rpyc'
        with patch('hy2bridge.native_management.read_rpyc') as connection:
            result = self.run_probe()
        self.assertFalse(result['passed'])
        self.assertIsNone(result['management_passed'])
        self.assertEqual(result['stage'],'configuration')
        connection.assert_not_called()
        self.make_api.assert_not_called()

    def test_cached_qualified_runtime_can_supply_its_verified_node_certificate(self):
        self.profile['vpn'].pop('management_auth')
        self.profile['vpn'].pop('management_tls')
        current = SimpleNamespace(_api_mtls=True,_node_cert='cached-node-certificate')
        with patch('hy2bridge.native_management.cached_node',return_value=current), \
             patch('hy2bridge.native_management.read_rest',return_value={'started':True,'api_mtls':1,'management_sources':1,'api_direct':1}):
            result = self.run_probe()
        self.assertTrue(result['passed'])
        self.assertEqual(self.make_api.call_args.kwargs['ssl_cert'],b'cached-node-certificate')

    def test_missing_api_port_fails_before_control_connection(self):
        self.services.pop()
        with patch('hy2bridge.native_management.read_rest') as connection:
            result = self.run_probe()
        self.assertFalse(result['passed'])
        connection.assert_not_called()

    def test_api_failure_prevents_publication_even_if_control_status_passes(self):
        self.make_api.return_value.get_sys_stats.side_effect = ConnectionError('synthetic connection loss')
        with patch('hy2bridge.native_management.read_rest',return_value={'started':True,'api_mtls':1,'management_sources':1,'api_direct':1}):
            result = self.run_probe()
        self.assertFalse(result['passed'])
        self.assertFalse(result['management_passed'])
        self.assertTrue(result['services'][0]['passed'])
        self.assertFalse(result['services'][1]['passed'])
        self.assertEqual(result['stage'],'api')
        self.make_api.return_value._channel.close.assert_called_once()

    def test_saved_protocol_supports_a_panel_restart_without_cached_connections(self):
        self.profile['vpn']['management_protocol'] = 'rpyc'
        with patch('hy2bridge.native_management.read_rpyc',return_value={'started':True,'api_mtls':1,'management_sources':1,'api_direct':1}) as status:
            result = self.run_probe()
        self.assertTrue(result['passed'])
        status.assert_called_once()

    def test_runtime_must_confirm_its_real_api_mode(self):
        with patch('hy2bridge.native_management.read_rest',return_value={'started':True,'api_mtls':0}):
            result = self.run_probe()
        self.assertFalse(result['passed'])
        self.make_api.assert_not_called()

    def test_rest_probe_never_connects_or_starts_the_native_session(self):
        connection = Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = json.dumps({'started':True,'api_mtls':1,'management_sources':1,'api_direct':1}).encode()
        with patch('hy2bridge.native_management.http.client.HTTPSConnection',return_value=connection):
            status = read_rest('192.0.2.10',62450,object())
        self.assertTrue(status['started'])
        self.assertEqual(connection.request.call_args.args[:2],('POST','/'))
        connection.close.assert_called_once()

    def test_rpyc_probe_reads_capabilities_without_claiming_controller(self):
        connection = Mock()
        connection.root.capabilities.return_value = json.dumps({'started':True,'api_mtls':1,'management_sources':1,'api_direct':1})
        with patch('hy2bridge.native_management.rpyc.SocketStream.ssl_connect'), \
             patch('hy2bridge.native_management.rpyc.connect_stream',return_value=connection):
            status = read_rpyc('192.0.2.10',62450,'key','cert','trust')
        self.assertTrue(status['started'])
        connection.root.claim.assert_not_called()
        connection.root.start.assert_not_called()
        connection.root.stop.assert_not_called()
        connection.close.assert_called_once()


if __name__=='__main__':
    unittest.main()
