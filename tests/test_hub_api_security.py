"""Loaded hub configurations must never expose an unauthenticated TCP API."""
import ast
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

# Keep C-extension enum identities stable while application modules are stubbed.
from cryptography.hazmat.primitives import serialization as _serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _X25519PrivateKey
import commentjson as _commentjson
from sqlalchemy import func as _sql_func


ROOT = Path(__file__).resolve().parents[1]


def security_module():
    path = ROOT/'app/xray/api_security.py'
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location('hub_security_fixture', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configured(payload):
    tree = ast.parse((ROOT/'app/xray/config.py').read_text())
    owner = next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='XRayConfig')
    method = next(n for n in owner.body if isinstance(n,ast.FunctionDef) and n.name=='_apply_api')
    merge = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='merge_dicts')
    namespace = {}
    module = security_module()
    if module:
        namespace['protect_hub_api'] = module.protect_hub_api
    exec(compile(ast.Module(body=[merge,method],type_ignores=[]),'hub-api-configuration','exec'),namespace)

    class Configuration(dict):
        def get_inbound(self, tag):
            return next((row for row in self['inbounds'] if row.get('tag')==tag),None)

    value = Configuration(deepcopy(payload))
    value.api_host, value.api_port = '127.0.0.1',23456
    namespace['_apply_api'](value)
    return value


def real_configuration_module(security):
    """Load the actual parser while isolating database/application startup."""
    from enum import Enum
    class ProxyTypes(str,Enum):
        vless='vless'
        vmess='vmess'
        trojan='trojan'
        shadowsocks='shadowsocks'
    modules={name:ModuleType(name) for name in (
        'app','app.db','app.db.models','app.models','app.models.proxy','app.models.user',
        'app.utils','app.utils.crypto','config')}
    modules['app.db'].GetDB=Mock()
    modules['app.db'].models=modules['app.db.models']
    modules['app.models.proxy'].ProxyTypes=ProxyTypes
    modules['app.models.user'].UserStatus=SimpleNamespace(active='active',on_hold='on_hold')
    modules['app.utils.crypto'].get_cert_SANs=lambda _:['fixture.invalid']
    modules['config'].DEBUG=False
    modules['config'].XRAY_EXCLUDE_INBOUND_TAGS=['EXCLUDED']
    modules['config'].XRAY_FALLBACKS_INBOUND_TAG='TLS_FALLBACK'
    if security is not None:modules['app.xray.api_security']=security
    spec=importlib.util.spec_from_file_location('hub_actual_configuration',ROOT/'app/xray/config.py')
    module=importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules,modules):spec.loader.exec_module(module)
    module._fixture_modules=modules
    return module


def real_core_module(endpoint):
    app=ModuleType('app');app.logger=Mock()
    configuration=ModuleType('app.xray.config');configuration.XRayConfig=dict
    security=ModuleType('app.xray.api_security');security.hub_api_endpoint=lambda:endpoint
    config=ModuleType('config');config.DEBUG=False
    access=ModuleType('hy2bridge.access');access.filter_config=lambda value,node:value
    modules={'app':app,'app.xray.config':configuration,'app.xray.api_security':security,
             'config':config,'hy2bridge.access':access}
    spec=importlib.util.spec_from_file_location('hub_actual_core',ROOT/'app/xray/core.py')
    module=importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules,modules):spec.loader.exec_module(module)
    return module,modules


class HubAPISecurityTests(unittest.TestCase):
    def payload(self):
        return {'inbounds':[{'tag':'VPN','protocol':'vless','port':443,
                'settings':{'clients':[{'id':'11111111-1111-4111-8111-111111111111'}]}}],
                'outbounds':[{'tag':'DIRECT','protocol':'freedom'}],
                'routing':{'domainStrategy':'AsIs','rules':[{'type':'field','network':'tcp,udp','outboundTag':'DIRECT'}]}}

    def test_loaded_asis_and_catchall_cannot_precede_private_address_protection(self):
        value = configured(self.payload())
        self.assertEqual(value['routing']['domainStrategy'],'IPOnDemand')
        rules=value['routing']['rules']
        private=next(i for i,row in enumerate(rules) if '127.0.0.0/8' in row.get('ip',[]))
        direct=next(i for i,row in enumerate(rules) if row.get('outboundTag')=='DIRECT')
        self.assertLess(private,direct)
        self.assertIn('::1/128',rules[private]['ip'])

    def test_existing_api_inbound_is_rebuilt_as_private_unix_socket(self):
        payload=self.payload()
        payload['inbounds'].append({'tag':'API_INBOUND','protocol':'dokodemo-door',
                                   'listen':'0.0.0.0','port':23456,'settings':{'address':'127.0.0.1'}})
        value=configured(payload)
        self.assertIsNone(value.get_inbound('API_INBOUND'))
        listen=value['api']['listen']
        self.assertTrue(listen.startswith('/'))
        self.assertTrue(listen.endswith(',0600'))
        self.assertEqual(stat.S_IMODE(Path(listen.rsplit(',',1)[0]).parent.stat().st_mode),0o700)

    def test_localhost_rule_precedes_loaded_domain_allowlist(self):
        payload=self.payload()
        payload['routing']['rules'].insert(0,{'type':'field','domain':['regexp:.*'],'outboundTag':'DIRECT'})
        rules=configured(payload)['routing']['rules']
        localhost=next(i for i,row in enumerate(rules) if 'domain:localhost' in row.get('domain',[]))
        direct=next(i for i,row in enumerate(rules) if row.get('outboundTag')=='DIRECT')
        self.assertLess(localhost,direct)

    def test_no_user_routing_can_select_the_direct_management_api(self):
        payload=self.payload()
        payload['api']={'tag':'API'}
        payload['routing']['rules'].insert(0,{'type':'field','inboundTag':['VPN'],'outboundTag':'API'})
        rules=configured(payload)['routing']['rules']
        management=[row for row in rules if row.get('outboundTag')=='API']
        self.assertEqual(management,[])

    def test_legitimate_public_outbound_named_api_is_preserved_without_handler_collision(self):
        payload=self.payload()
        payload['outbounds'].append({'tag':'API','protocol':'freedom'})
        rule={'type':'field','network':'tcp','outboundTag':'API'}
        payload['routing']['rules']=[rule]
        value=configured(payload)
        self.assertIn(rule,value['routing']['rules'])
        self.assertIn({'tag':'API','protocol':'freedom'},value['outbounds'])
        self.assertTrue(value['api']['listen'].startswith('/'))

    def test_user_configuration_identity_and_metering_remain_unchanged(self):
        payload=self.payload();original=deepcopy(payload['inbounds'][0])
        value=configured(payload)
        self.assertEqual(value.get_inbound('VPN'),original)
        self.assertTrue(value['policy']['levels']['0']['statsUserUplink'])
        self.assertTrue(value['policy']['levels']['0']['statsUserDownlink'])
        self.assertTrue(value['policy']['system']['statsOutboundUplink'])
        self.assertEqual(value['outbounds'][0],payload['outbounds'][0])

    def test_legitimate_balancer_rule_is_preserved_when_loaded_config_has_no_api(self):
        payload=self.payload()
        rule={'type':'field','network':'tcp','balancerTag':'PUBLIC_BALANCER'}
        payload['routing']['rules']=[rule]
        payload['routing']['balancers']=[{'tag':'PUBLIC_BALANCER','selector':['DIRECT']}]
        value=configured(payload)
        self.assertIn(rule,value['routing']['rules'])
        self.assertEqual(value['routing']['balancers'],payload['routing']['balancers'])

    def test_balancer_cannot_select_internal_api_by_tag_prefix_or_fallback(self):
        for selector,fallback in [(['API'],None),(['A'],None),([''],None),(['DIRECT'],'API')]:
            payload=self.payload();payload['api']={'tag':'API'}
            payload['routing']['rules']=[{'type':'field','network':'tcp','balancerTag':'CHOICE'}]
            balancer={'tag':'CHOICE','selector':selector}
            if fallback:balancer['fallbackTag']=fallback
            payload['routing']['balancers']=[balancer]
            value=configured(payload)
            self.assertEqual(value['routing']['balancers'],payload['routing']['balancers'])
            self.assertIsNone(value.get_inbound('API_INBOUND'))
            self.assertTrue(value['api']['listen'].endswith(',0600'))

    def test_legitimate_public_outbound_prefix_is_preserved_without_api_handler(self):
        payload=self.payload();payload['api']={'tag':'API'}
        payload['outbounds'].append({'tag':'A','protocol':'freedom'})
        payload['routing']['rules']=[{'type':'field','network':'tcp','balancerTag':'ALL'}]
        payload['routing']['balancers']=[{'tag':'ALL','selector':['']}]
        value=configured(payload)
        self.assertEqual(value['routing']['balancers'],payload['routing']['balancers'])
        self.assertIn({'tag':'A','protocol':'freedom'},value['outbounds'])
        self.assertTrue(value['api']['listen'].startswith('/'))

    def test_optional_null_api_and_stats_are_rebuilt_as_usable_private_management(self):
        payload=self.payload();payload.update(api=None,stats=None)
        value=configured(payload)
        self.assertTrue(value['api']['listen'].startswith('/'))
        self.assertEqual(value['stats'],{})

    def test_legacy_management_guard_rejects_api_fallbacks_and_outbound_indirection(self):
        security=security_module();self.assertIsNotNone(security)
        for outbounds in (
            [{'tag':'API','protocol':'freedom'}],
            [{'tag':'DIRECT','protocol':'freedom','proxySettings':{'tag':'API'}}],
            [{'tag':'DIRECT','protocol':'freedom','streamSettings':{'sockopt':{'dialerProxy':'API'}}}],
        ):
            with self.assertRaises(ValueError):security._protect_balancers({},outbounds)
        for balancer in ({'tag':'CHOICE','selector':['API']},
                         {'tag':'CHOICE','selector':['DIRECT'],'fallbackTag':'API'}):
            with self.assertRaises(ValueError):security._protect_balancers({'balancers':[balancer]},[{'tag':'DIRECT','protocol':'freedom'}])
        routing={'balancers':[{'tag':'CHOICE','selector':['']}]}
        security._protect_balancers(routing,[{'tag':'DIRECT','protocol':'freedom'}])
        self.assertEqual(routing['balancers'][0]['selector'],['DIRECT'])

    def test_actual_loaded_file_parser_keeps_user_and_special_inbounds(self):
        module=real_configuration_module(security_module())
        payload=self.payload()
        payload['inbounds'] += [
            {'tag':'EXCLUDED','protocol':'vless','port':2053,'settings':{'clients':[],'decryption':'none'},
             'streamSettings':{'network':'xhttp','xhttpSettings':{'path':'/fixture','mode':'auto'}}},
            {'tag':'LOCAL_HTTP','protocol':'http','listen':'127.0.0.1','port':18081,'settings':{}},
            {'tag':'TLS_FALLBACK','protocol':'trojan','port':8443,'settings':{'clients':[]}},
        ]
        original=deepcopy(payload)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'operator-config.json';path.write_text(json.dumps(payload))
            with patch.dict(sys.modules,module._fixture_modules):
                value=module.XRayConfig(str(path),api_host='0.0.0.0',api_port=23456)
        self.assertEqual(value['routing']['domainStrategy'],'IPOnDemand')
        self.assertTrue(value.api_host.startswith('/'))
        self.assertEqual(value.api_port,0)
        for row in original['inbounds']:self.assertEqual(value.get_inbound(row['tag']),row)
        self.assertEqual(value.inbounds_by_tag['VPN']['port'],443)
        self.assertNotIn('EXCLUDED',value.inbounds_by_tag)
        self.assertNotIn('LOCAL_HTTP',value.inbounds_by_tag)
        self.assertEqual(value.get_inbound('VPN')['settings']['clients'][0]['id'],
                         original['inbounds'][0]['settings']['clients'][0]['id'])
        self.assertTrue(value['policy']['levels']['0']['statsUserUplink'])
        self.assertTrue(value['policy']['system']['statsOutboundDownlink'])

    def test_loaded_reality_private_key_without_public_key_survives_qualified_hub(self):
        from base64 import urlsafe_b64encode
        module=real_configuration_module(security_module())
        core_module,_=real_core_module(SimpleNamespace())
        core=core_module.XRayCore.__new__(core_module.XRayCore);core.executable_path='unused-cli'
        private=urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
        payload=self.payload()
        reality={'network':'tcp','security':'reality','realitySettings':{'privateKey':private,
                 'serverNames':['fixture.invalid'],'shortIds':['0123456789abcdef']}}
        payload['inbounds'][0]['streamSettings']=reality
        app_xray=ModuleType('app.xray');app_xray.core=core
        modules={**module._fixture_modules,'app.xray':app_xray}
        with patch.dict(sys.modules,modules),patch.object(core_module.subprocess,'check_output',side_effect=AssertionError('No version-specific CLI')):
            value=module.XRayConfig(payload)
        self.assertTrue(value.inbounds_by_tag['VPN']['pbk'])
        self.assertEqual(value.get_inbound('VPN')['streamSettings'],reality)
        self.assertEqual(value.get_inbound('VPN')['settings']['clients'],payload['inbounds'][0]['settings']['clients'])


@unittest.skipUnless(hasattr(os,'getuid') and hasattr(socket,'AF_UNIX'),'Linux Unix-socket qualification')
class HubSocketLifecycleTests(unittest.TestCase):
    def endpoint(self):
        module=security_module()
        self.assertIsNotNone(module,'The mandatory private hub API module is missing')
        endpoint=module.PrivateAPISocket()
        def cleanup():
            if endpoint.path.is_symlink():endpoint.path.unlink()
            endpoint.close()
        self.addCleanup(cleanup)
        return endpoint

    def test_owned_stale_socket_is_removed_without_changing_private_directory(self):
        endpoint=self.endpoint()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:stream.bind(str(endpoint.path))
        self.assertTrue(endpoint.path.is_socket())
        endpoint.prepare()
        self.assertFalse(endpoint.path.exists())
        self.assertEqual(stat.S_IMODE(endpoint.directory.stat().st_mode),0o700)

    def test_active_owned_socket_is_preserved_and_rejected(self):
        endpoint=self.endpoint()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
            stream.bind(str(endpoint.path));stream.listen(1)
            inode=endpoint.path.stat().st_ino
            with self.assertRaises(RuntimeError):endpoint.prepare()
            self.assertEqual(endpoint.path.stat().st_ino,inode)

    def test_foreign_socket_and_symlink_are_rejected_without_deletion(self):
        endpoint=self.endpoint()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:stream.bind(str(endpoint.path))
        original=Path.lstat
        def foreign(path):
            actual=original(path)
            return SimpleNamespace(st_mode=actual.st_mode,st_uid=os.getuid()+1) if path==endpoint.path else actual
        with patch.object(Path,'lstat',foreign):
            with self.assertRaises(ValueError):endpoint.prepare()
        self.assertTrue(endpoint.path.is_socket())
        endpoint.path.unlink()
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'foreign.txt';target.write_text('preserve')
            endpoint.path.symlink_to(target)
            with self.assertRaises(ValueError):endpoint.prepare()
            self.assertEqual(target.read_text(),'preserve')


class HubStartupAndChannelTests(unittest.TestCase):
    def test_hub_default_prefers_qualified_binary_and_keeps_explicit_override(self):
        tree=ast.parse((ROOT/'config.py').read_text())
        assignments=[node for node in tree.body if isinstance(node,ast.Assign)
                     and any(isinstance(target,ast.Name) and target.id in ('_qualified_hub','XRAY_EXECUTABLE_PATH') for target in node.targets)]
        self.assertEqual(len(assignments),2)
        for explicit in (None,'/usr/local/bin/xray'):
            namespace={'Path':lambda value:SimpleNamespace(is_file=lambda:value=='/opt/rime-probe/xray'),
                       'config':lambda key,default:explicit or default}
            exec(compile(ast.Module(body=assignments,type_ignores=[]),'hub-runtime-default','exec'),namespace)
            self.assertEqual(namespace['XRAY_EXECUTABLE_PATH'],explicit or '/opt/rime-probe/xray')

    def test_running_old_core_without_unix_listener_is_stopped_and_never_ready(self):
        endpoint=SimpleNamespace(prepare=Mock(),path=SimpleNamespace(exists=lambda:False))
        module,modules=real_core_module(endpoint)
        class Configuration(dict):
            def to_json(self):return json.dumps(self)
        process=Mock();process.poll.return_value=None
        core=module.XRayCore.__new__(module.XRayCore)
        core.executable_path='synthetic-old-core';core.version='24.12.31';core._env={}
        core.process=None;core._on_start_funcs=[];core._on_stop_funcs=[]
        core._XRayCore__capture_process_logs=Mock()
        with patch.dict(sys.modules,modules),patch.object(module.subprocess,'Popen',return_value=process),\
                patch.object(module.time,'monotonic',side_effect=[0,6]):
            with self.assertRaises(RuntimeError):core.start(Configuration({'log':{}}))
        process.terminate.assert_called_once()
        self.assertFalse(core.started)
        core._XRayCore__capture_process_logs.assert_not_called()
        self.assertFalse(any('started' in str(call.args[0]) for call in module.logger.warning.call_args_list))

    def test_unix_grpc_channel_uses_only_absolute_private_path_and_disables_proxy(self):
        from xray_api.base import XRayBase
        with patch('xray_api.base.grpc.insecure_channel',return_value=Mock()) as channel:
            client=XRayBase('/tmp/fixture-api.sock',0,unix_socket='/tmp/fixture-api.sock')
        self.assertEqual(client.address,'/tmp/fixture-api.sock')
        self.assertEqual(client.port,0)
        channel.assert_called_once_with('unix:/tmp/fixture-api.sock',options=(('grpc.enable_http_proxy',0),))
        for path,extra in [('relative.sock',{}),('/tmp/fixture.sock',{'ssl_cert':'synthetic-cert'})]:
            with self.assertRaises(ValueError):XRayBase(path,0,unix_socket=path,**extra)

    def test_existing_reality_private_key_is_preserved_without_cli_format_dependency(self):
        module,_=real_core_module(SimpleNamespace())
        core=module.XRayCore.__new__(module.XRayCore);core.executable_path='synthetic-core'
        from base64 import urlsafe_b64encode,urlsafe_b64decode
        private=urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
        with patch.object(module.subprocess,'check_output',side_effect=AssertionError('No version-specific CLI format')):
            result=core.get_x25519(private)
            generated=core.get_x25519()
            self.assertEqual(core.get_x25519(generated['private_key']),generated)
        self.assertEqual(result['private_key'],private)
        self.assertEqual(len(urlsafe_b64decode(result['public_key']+'=')),32)


if __name__=='__main__':
    unittest.main()
