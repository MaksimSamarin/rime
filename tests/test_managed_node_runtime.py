import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('managed_node_runtime',Path(__file__).resolve().parents[1]/'node-runtime/node_autonomy.py')
runtime=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class ManagedRuntimeTests(unittest.TestCase):
    def config(self):
        return {'inbounds':[{'tag':'VPN','protocol':'vless','listen':'127.0.0.1','port':443,
                             'settings':{'clients':[{'id':'synthetic-uuid'}]},
                             'streamSettings':{'security':'tls','tlsSettings':{'certificates':[{'certificate':['OLD'],'key':['OLDKEY']}]}}},
                            {'tag':'API','protocol':'dokodemo-door','listen':'127.0.0.1','port':12345}]}

    def test_unconfigured_node_retains_exact_input(self):
        text=json.dumps(self.config())
        with patch.dict(os.environ,{},clear=True):
            self.assertIs(runtime.prepare_config(text),text)

    def test_managed_listener_does_not_inherit_panel_loopback(self):
        original=self.config()
        with patch.dict(os.environ,{'RIME_NODE_LISTEN':'0.0.0.0'},clear=True):
            result=json.loads(runtime.prepare_config(original))
        self.assertEqual(result['inbounds'][0]['listen'],'0.0.0.0')
        self.assertEqual(result['inbounds'][1],original['inbounds'][1])
        self.assertEqual(result['inbounds'][0]['settings'],original['inbounds'][0]['settings'])
        self.assertEqual(result['inbounds'][0]['streamSettings'],original['inbounds'][0]['streamSettings'])
        self.assertEqual(original['inbounds'][0]['listen'],'127.0.0.1')

    def test_custom_tls_changes_only_vless_server_certificates(self):
        with tempfile.TemporaryDirectory() as folder:
            cert,key=Path(folder)/'cert.pem',Path(folder)/'key.pem'
            cert.write_text('CERTIFICATE\nPUBLIC\n')
            key.write_text('PRIVATE\nSYNTHETIC\n')
            with patch.dict(os.environ,{'RIME_NODE_CERTIFICATE':str(cert),'RIME_NODE_CERTIFICATE_KEY':str(key)},clear=True):
                result=json.loads(runtime.prepare_config(json.dumps(self.config())))
        self.assertEqual(result['inbounds'][0]['streamSettings']['tlsSettings']['certificates'][0]['certificate'],['CERTIFICATE','PUBLIC'])
        self.assertEqual(result['inbounds'][1],self.config()['inbounds'][1])

    def test_partial_certificate_or_unsupported_listener_is_rejected(self):
        for env in [{'RIME_NODE_CERTIFICATE':'missing.pem'},{'RIME_NODE_LISTEN':'127.0.0.2'}]:
            with patch.dict(os.environ,env,clear=True):
                with self.assertRaises(ValueError):runtime.prepare_config(json.dumps(self.config()))

    def test_static_comparison_ignores_only_vless_accounts(self):
        previous=self.config()
        changed=json.loads(json.dumps(previous))
        changed['inbounds'][0]['settings']['clients']=[{'id':'different','email':'new'}]
        self.assertFalse(runtime.equivalent(json.dumps(previous),json.dumps(changed)))
        self.assertTrue(runtime.equivalent_static(json.dumps(previous),json.dumps(changed)))
        changed['inbounds'][0]['port']=8443
        self.assertFalse(runtime.equivalent_static(json.dumps(previous),json.dumps(changed)))
        self.assertEqual(previous['inbounds'][0]['settings']['clients'],[{'id':'synthetic-uuid'}])

    def test_capabilities_expose_only_vless_tags(self):
        self.assertEqual(runtime.capabilities(None),{'user_reconcile':1,'user_tags':[],'stats_epoch':None})
        self.assertEqual(runtime.capabilities(json.dumps(self.config())),{'user_reconcile':1,'user_tags':['VPN'],'stats_epoch':None})
