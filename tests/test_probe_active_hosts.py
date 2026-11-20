import contextlib,json,sys,types,unittest
from unittest.mock import patch
from hy2bridge.provision_probe import ProvisionProbe
from hy2bridge.provision import ProvisionError


class ProbeActiveHostsTests(unittest.TestCase):
    def prepare(self,disabled=True):
        hosts=[{'id':1,'inbound_tag':'OLD','address':['node.example'],'port':2053,'is_disabled':disabled},
               {'id':2,'inbound_tag':'NEW','address':['node.example'],'port':443,'is_disabled':False}]
        source={'node':'xray:3','protocol':'vless','domain':'node.example','vpn_port':443,'hosts':hosts}
        profile={'vpn':{'config':{'inbounds':[{'tag':'OLD','port':2053},{'tag':'NEW','port':24443},{'tag':'HIDDEN','port':18443}]},'publish':[[2053,2053,'tcp'],[443,24443,'tcp'],[8443,18443,'tcp']]}}
        store=types.SimpleNamespace(connection=lambda:contextlib.nullcontext(None),users=lambda db:{'auth':{'username':'probe'}},allowed=lambda user:True)
        xray=types.SimpleNamespace(hosts={'OLD':[hosts[0]],'NEW':[hosts[1]]})
        probe=ProvisionProbe(store,{'probe_username':'probe'},None,xray)
        return probe,source,profile

    @contextlib.contextmanager
    def app_modules(self):
        names=['app','app.db','app.models','app.models.user','app.subscription','app.subscription.share','app.xray','app.xray.config']
        modules={name:types.ModuleType(name) for name in names}
        for m in modules.values():m.__path__=[]
        modules['app.db'].GetDB=lambda:contextlib.nullcontext(None)
        modules['app.db'].crud=types.SimpleNamespace(get_user=lambda *args:object())
        account=types.SimpleNamespace(proxies={},inbounds={'vless':['OLD','NEW','HIDDEN']},model_dump=lambda:{'username':'probe'})
        modules['app.models.user'].UserResponse=types.SimpleNamespace(model_validate=lambda value:account)
        def render(*args,hosts,**kwargs):
            configs=[]
            for group in hosts.values():
                for host in group:
                    configs.append({'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':host['address'][0],'port':host['port']}]}}]})
            return json.dumps(configs)
        modules['app.subscription.share'].generate_v2ray_json_subscription=render
        modules['app.xray.config'].XRayConfig=lambda value:value
        with patch.dict(sys.modules,modules):yield

    def test_disabled_legacy_address_is_kept_out_of_live_probe_without_dropping_hidden_preserved_inputs(self):
        probe,source,profile=self.prepare()
        with self.app_modules():targets=probe.transfer_targets(source,profile,{'address':'192.0.2.3'})
        self.assertEqual(sorted(v['config']['outbounds'][0]['settings']['vnext'][0]['port'] for v in targets),[443,8443])
        self.assertEqual(source['hosts'][0]['port'],2053)
        self.assertEqual(len(profile['vpn']['config']['inbounds']),3)

    def test_enabled_legacy_address_is_still_checked(self):
        probe,source,profile=self.prepare(disabled=False)
        with self.app_modules():targets=probe.transfer_targets(source,profile,{'address':'192.0.2.3'})
        self.assertEqual(sorted(v['config']['outbounds'][0]['settings']['vnext'][0]['port'] for v in targets),[443,2053,8443])

    def test_no_enabled_addresses_fail_explicitly(self):
        probe,source,profile=self.prepare()
        source['hosts'][1]['is_disabled']=True
        with self.app_modules(),self.assertRaises(ProvisionError):probe.transfer_targets(source,profile,{'address':'192.0.2.3'})
