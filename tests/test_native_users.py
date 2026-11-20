import ast
import copy
from pathlib import Path
import sys
import threading
import types
import weakref
import unittest
from unittest.mock import MagicMock, patch

from hy2bridge.native_users import reconcile,supports_inbound


ALICE={'email':'alice','id':'11111111-1111-4111-8111-111111111111','level':0,'flow':''}
BOB={'email':'bob','id':'22222222-2222-4222-8222-222222222222','level':0,'flow':''}


class LiveAPI:
    def __init__(self,users):
        self.users={item['email']:dict(item) for item in users}
        self.calls=[]

    def get_inbound_users(self,tag,timeout):
        return copy.deepcopy(list(self.users.values()))

    def remove_inbound_user(self,tag,email,timeout):
        self.calls.append(('remove',email))
        self.users.pop(email,None)

    def add_inbound_user(self,tag,value,timeout):
        self.calls.append(('add',value['email']))
        self.users[value['email']]=value


class NativeUsersTests(unittest.TestCase):
    def test_node_specific_inbounds_do_not_receive_accounts_for_other_nodes(self):
        node=types.SimpleNamespace(_user_reconcile=True,_user_tags=['OLD','REALITY'])
        self.assertTrue(supports_inbound(node,'OLD'))
        self.assertTrue(supports_inbound(node,'REALITY'))
        self.assertFalse(supports_inbound(node,'ANOTHER_NODE_INBOUND'))
        node._user_tags=[];self.assertFalse(supports_inbound(node,'OLD'))
        self.assertTrue(supports_inbound(types.SimpleNamespace(_user_reconcile=False),'OLD'))
        self.assertTrue(supports_inbound(types.SimpleNamespace(),'OLD'))

    def sync(self,api,users):
        config={'inbounds':[{'tag':'VPN','protocol':'vless','settings':{'clients':users}}]}
        return reconcile(api,config,['VPN'],lambda **value:value)

    def test_actual_accounts_are_compared_without_order(self):
        api=LiveAPI([BOB,ALICE])
        self.assertTrue(self.sync(api,[ALICE,BOB]))
        self.assertEqual(api.calls,[])

    def test_missing_and_revoked_users_are_reconciled_and_confirmed(self):
        api=LiveAPI([ALICE])
        self.assertTrue(self.sync(api,[ALICE,BOB]))
        self.assertEqual(api.calls,[('add','bob')])
        api.calls.clear()
        self.assertTrue(self.sync(api,[ALICE]))
        self.assertEqual(api.calls,[('remove','bob')])

    def test_uuid_level_and_flow_changes_replace_only_the_changed_account(self):
        for changes in [{'id':'33333333-3333-4333-8333-333333333333'},{'level':2},{'flow':'xtls-rprx-vision'}]:
            with self.subTest(changes=changes):
                api=LiveAPI([ALICE,BOB])
                changed={**BOB,**changes}
                self.assertTrue(self.sync(api,[ALICE,changed]))
                self.assertEqual(api.calls,[('remove','bob'),('add','bob')])
                self.assertEqual(api.users['alice'],ALICE)
                self.assertEqual(api.users['bob'],changed)

    def test_partial_failure_cannot_acknowledge_stale_policy(self):
        api=LiveAPI([ALICE,BOB])
        api.remove_inbound_user=lambda *args,**kwargs:(_ for _ in ()).throw(TimeoutError())
        with self.assertRaises(ConnectionError):self.sync(api,[ALICE])

    def test_committed_timeout_is_confirmed_by_an_independent_query(self):
        api=LiveAPI([ALICE,BOB])
        remove=api.remove_inbound_user
        def timed_out(*args,**kwargs):
            remove(*args,**kwargs)
            raise TimeoutError()
        api.remove_inbound_user=timed_out
        self.assertTrue(self.sync(api,[ALICE]))
        self.assertNotIn('bob',api.users)

    def test_unsupported_api_or_accounts_fall_back_without_mutations(self):
        api=LiveAPI([ALICE])
        api.get_inbound_users=lambda *args,**kwargs:(_ for _ in ()).throw(NotImplementedError())
        self.assertFalse(self.sync(api,[ALICE]))
        self.assertEqual(api.calls,[])
        for users in [[{**ALICE,'unknown':'value'}],[{**ALICE,'email':''}],[ALICE,ALICE]]:
            api=LiveAPI([ALICE])
            self.assertFalse(self.sync(api,users))
            self.assertEqual(api.calls,[])

    def test_query_failure_preserves_running_core_policy_without_an_ack(self):
        api=LiveAPI([ALICE])
        api.get_inbound_users=lambda *args,**kwargs:(_ for _ in ()).throw(ConnectionError())
        with self.assertRaises(ConnectionError):self.sync(api,[ALICE,BOB])
        self.assertEqual(api.calls,[])

    def test_mutation_deadline_is_bounded(self):
        api=LiveAPI([ALICE])
        with patch('hy2bridge.native_users.time.monotonic',side_effect=[0,1,20]):
            with self.assertRaises(ConnectionError):self.sync(api,[ALICE,BOB])
        self.assertEqual(api.calls,[])

    def test_user_rpc_helpers_wait_for_the_same_endpoint_lock(self):
        path=Path(__file__).resolve().parents[1]/'app/xray/operations.py'
        source=ast.parse(path.read_text())
        lock=threading.RLock()
        calls=[]
        api=types.SimpleNamespace(add_inbound_user=lambda **kwargs:calls.append('add'),
                                  remove_inbound_user=lambda **kwargs:calls.append('remove'),control_lock=lock)
        env={'NODE_LIFECYCLE_LOCK':lock,'XRayAPI':object,'Account':object,
             'xray':types.SimpleNamespace(exc=types.SimpleNamespace(EmailExistsError=ValueError,
                                                                  EmailNotFoundError=ValueError,ConnectionError=OSError))}
        names=['_add_user_to_inbound','_remove_user_from_inbound','_alter_inbound_user']
        for function in [item for item in source.body if isinstance(item,ast.FunctionDef) and item.name in names]:
            function.decorator_list=[]
            exec(compile(ast.Module(body=[function],type_ignores=[]),str(path),'exec'),env)
        user=types.SimpleNamespace(email='bob')
        with lock:
            threads=[threading.Thread(target=env[names[0]],args=(api,'VPN',user)),
                     threading.Thread(target=env[names[1]],args=(api,'VPN','bob')),
                     threading.Thread(target=env[names[2]],args=(api,'VPN',user))]
            for thread in threads:thread.start()
            self.assertEqual(calls,[])
        for thread in threads:thread.join(timeout=1)
        self.assertEqual(sorted(calls),['add','add','remove','remove'])
        self.assertFalse(any(thread.is_alive() for thread in threads))

    def test_endpoint_registry_shares_same_endpoint_without_blocking_other_nodes(self):
        path=Path(__file__).resolve().parents[1]/'xray_api/base.py'
        source=ast.parse(path.read_text())
        function=next(item for item in source.body if isinstance(item,ast.FunctionDef) and item.name=='control_lock')
        env={'threading':threading,'_CONTROL_LOCKS':weakref.WeakValueDictionary(),
             '_CONTROL_LOCKS_GUARD':threading.Lock()}
        exec(compile(ast.Module(body=[function],type_ignores=[]),str(path),'exec'),env)
        endpoint=env['control_lock']
        busy=endpoint('node.example',62051)
        self.assertIs(busy,endpoint('NODE.EXAMPLE.',62051))
        with busy:
            other=endpoint('other.example',62051)
            self.assertTrue(other.acquire(blocking=False))
            other.release()
        del busy,other
        self.assertEqual(len(env['_CONTROL_LOCKS']),0)

    def test_reconnect_does_not_wait_unboundedly_for_busy_endpoint(self):
        path=Path(__file__).resolve().parents[1]/'app/xray/node.py'
        source=ast.parse(path.read_text())
        observed=[]
        lease=types.SimpleNamespace(acquire=lambda **kwargs:observed.append(kwargs['timeout']) or False,
                                    release=lambda:(_ for _ in ()).throw(AssertionError('Unowned release')))
        for owner in [item for item in source.body if isinstance(item,ast.ClassDef) and item.name in {'ReSTXRayNode','RPyCXRayNode'}]:
            for name in ['start','restart']:
                function=next(item for item in owner.body if isinstance(item,ast.FunctionDef) and item.name==name)
                env={'XRayConfig':dict,'control_lock':lambda *args:lease}
                exec(compile(ast.Module(body=[function],type_ignores=[]),str(path),'exec'),env)
                node=types.SimpleNamespace(address='busy.example',api_port=62051,
                                           control_address='exit.example',control_api_port=62051,
                                           _start_locked=lambda *args:(_ for _ in ()).throw(AssertionError('Unexpected start')),
                                           _restart_locked=lambda *args:(_ for _ in ()).throw(AssertionError('Unexpected restart')))
                with self.assertRaises(ConnectionError):env[name](node,{})
        self.assertEqual(observed,[2,2,2,2])

    def test_stopped_core_skips_live_user_query_and_uses_normal_start(self):
        path=Path(__file__).resolve().parents[1]/'app/xray/node.py'
        source=ast.parse(path.read_text())
        owner=next(item for item in source.body if isinstance(item,ast.ClassDef) and item.name=='ReSTXRayNode')
        function=next(item for item in owner.body if isinstance(item,ast.FunctionDef) and item.name=='_start_locked')
        calls=[]
        class Config(dict):
            def to_json(self):return '{}'
        api=types.SimpleNamespace(_channel=object(),get_sys_stats=MagicMock())
        env={'XRayConfig':Config,'XRayAPI':lambda **kwargs:api,
             'initialize_api_transport':lambda node,mode:api,
             'grpc':types.SimpleNamespace(channel_ready_future=lambda channel:types.SimpleNamespace(result=lambda **kwargs:None),
                                         FutureTimeoutError=TimeoutError),
             '_control_timeout':lambda address,timeout:timeout,'NodeAPIError':RuntimeError}
        exec(compile(ast.Module(body=[function],type_ignores=[]),str(path),'exec'),env)
        def request(path,**kwargs):
            calls.append((path,kwargs))
            return {'user_reconcile':1,'user_tags':['VPN']}
        node=types.SimpleNamespace(address='node.example',api_port=62051,_node_cert='synthetic',
                                   ssl_key='fixture-key',ssl_cert='fixture-cert',control_address='node.example',control_api_port=62051,
                                   connected=True,started=False,_started=True,_user_reconcile=True,
                                   _user_tags=['VPN'],_prepare_config=lambda config:config,make_request=request)
        env['_start_locked'](node,Config())
        self.assertEqual(calls,[('/start',{'timeout':10,'config':'{}','users_verified':False})])
        self.assertTrue(node._started)

    def test_unsupported_live_schema_forces_restart_instead_of_cached_start(self):
        path=Path(__file__).resolve().parents[1]/'app/xray/node.py'
        source=ast.parse(path.read_text())
        owner=next(item for item in source.body if isinstance(item,ast.ClassDef) and item.name=='ReSTXRayNode')
        function=next(item for item in owner.body if isinstance(item,ast.FunctionDef) and item.name=='_start_locked')
        class Config(dict):
            def to_json(self):return '{}'
        env={'XRayConfig':Config,'NodeAPIError':RuntimeError}
        exec(compile(ast.Module(body=[function],type_ignores=[]),str(path),'exec'),env)
        restart=MagicMock(return_value={'restarted':True})
        node=types.SimpleNamespace(connected=True,started=True,_started=False,_user_reconcile=True,
                                   _user_tags=['VPN'],api=object(),_prepare_config=lambda config:config,restart=restart,
                                   make_request=lambda *args,**kwargs:(_ for _ in ()).throw(AssertionError('Cached start must not run')))
        account_module=types.ModuleType('xray_api.types.account')
        account_module.VLESSAccount=object
        config=Config()
        with patch.dict(sys.modules,{'xray_api.types.account':account_module}), \
                patch('hy2bridge.native_users.reconcile',return_value=False) as sync:
            result=env['_start_locked'](node,config)
        self.assertTrue(result['restarted'])
        sync.assert_called_once()
        restart.assert_called_once_with(config)

    def test_explicit_restart_refreshes_capability_and_inbound_tags(self):
        path=Path(__file__).resolve().parents[1]/'app/xray/node.py'
        source=ast.parse(path.read_text())
        owner=next(item for item in source.body if isinstance(item,ast.ClassDef) and item.name=='ReSTXRayNode')
        function=next(item for item in owner.body if isinstance(item,ast.FunctionDef) and item.name=='_restart_locked')
        class Config(dict):
            def to_json(self):return '{}'
        api=types.SimpleNamespace(_channel=object(),get_sys_stats=MagicMock())
        env={'XRayConfig':Config,'XRayAPI':lambda **kwargs:api,
             'initialize_api_transport':lambda node,mode:api,
             'grpc':types.SimpleNamespace(channel_ready_future=lambda channel:types.SimpleNamespace(result=lambda **kwargs:None),
                                         FutureTimeoutError=TimeoutError),
             '_control_timeout':lambda address,timeout:timeout}
        exec(compile(ast.Module(body=[function],type_ignores=[]),str(path),'exec'),env)
        response={'user_reconcile':1,'user_tags':['NEW_TAG']}
        request=MagicMock(return_value=response)
        node=types.SimpleNamespace(address='node.example',api_port=62051,_node_cert='synthetic',
                                   ssl_key='fixture-key',ssl_cert='fixture-cert',control_address='node.example',control_api_port=62051,
                                   connected=True,_started=True,_user_reconcile=False,_user_tags=['OLD_TAG'],
                                   _prepare_config=lambda config:config,make_request=request)
        self.assertEqual(env['_restart_locked'](node,Config()),response)
        request.assert_called_once_with('/restart',timeout=10,config='{}')
        self.assertTrue(node._user_reconcile)
        self.assertEqual(node._user_tags,['NEW_TAG'])
