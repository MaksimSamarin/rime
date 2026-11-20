"""One interrupted control client must not stop recording healthy nodes."""
import ast
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from operator import attrgetter
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock


class NodeAPIError(Exception):
    pass


class XrayError(Exception):
    pass


class API:
    def __init__(self, active=False):
        self.active = active
        self.resets = []
        self.control_lock = threading.RLock()

    def get_users_stats(self, reset, timeout):
        self.resets.append(('users',reset))
        return [SimpleNamespace(name='1.fixture-user',value=5)] if self.active else []

    def get_outbounds_stats(self, reset, timeout):
        self.resets.append(('node',reset))
        return [SimpleNamespace(link='uplink',value=7),SimpleNamespace(link='downlink',value=11)] if self.active else []


class UnavailableNode:
    def __init__(self, phase, error):
        self.phase,self.error = phase,error

    @property
    def connected(self):
        if self.phase=='connected':raise self.error
        return True

    @property
    def started(self):
        if self.phase=='started':raise self.error
        return True

    @property
    def api(self):
        raise self.error


class UsageNodeIsolationTests(unittest.TestCase):
    def setUp(self):
        self.local,self.healthy = API(),API(active=True)
        self.nodes = {1:UnavailableNode('api',ConnectionError('Synthetic cached client state')),
                      2:SimpleNamespace(connected=True,started=True,api=self.healthy,usage_coefficient=1)}
        self.db = MagicMock()
        self.db.query.return_value.all.return_value = [(1,None)]
        self.execute = Mock()
        self.user_history,self.node_history = Mock(),Mock()
        model = SimpleNamespace(id=MagicMock(),admin_id=MagicMock(),used_traffic=MagicMock(),
                                users_usage=MagicMock(),uplink=MagicMock(),downlink=MagicMock())
        namespace = {'xray':SimpleNamespace(api=self.local,nodes=self.nodes),'NodeAPIError':NodeAPIError,
                     'xray_exc':SimpleNamespace(XrayError=XrayError),'defaultdict':defaultdict,
                     'ThreadPoolExecutor':ThreadPoolExecutor,'attrgetter':attrgetter,'datetime':datetime,
                     'GetDB':lambda:self.db,'User':model,'Admin':model,'System':model,
                     'bindparam':MagicMock(),'update':MagicMock(),'safe_execute':self.execute,
                     'record_user_stats':self.user_history,'record_node_stats':self.node_history,
                     'DISABLE_RECORDING_NODE_USAGE':False,'XRayAPI':object,
                     'uses_cumulative_usage':lambda api:False,'record_native_usage':Mock(),
                     'logger':SimpleNamespace(warning=lambda *args:None)}
        self.db.__enter__.return_value = self.db
        tree = ast.parse((Path(__file__).resolve().parents[1]/'app/jobs/record_usages.py').read_text())
        names = ['get_users_stats','get_outbounds_stats','get_recordable_stats','record_user_usages','record_node_usages']
        functions = [node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
        exec(compile(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])),'usage-jobs','exec'),namespace)
        self.namespace = namespace

    def test_user_usage_continues_after_one_node_api_selection_fails(self):
        self.namespace['record_user_usages']()
        self.assertEqual(self.healthy.resets,[('users',True)])
        self.user_history.assert_any_call([{'uid':'1','value':5}],2,1)
        self.assertEqual(self.execute.call_args.args[2],[{'uid':'1','value':5}])
        self.assertFalse(any(call.args[1]==1 for call in self.user_history.call_args_list))

    def test_node_usage_continues_after_one_node_api_selection_fails(self):
        self.namespace['record_node_usages']()
        self.assertEqual(self.healthy.resets,[('node',True)])
        self.node_history.assert_any_call([{'up':7,'down':0},{'up':0,'down':11}],2)
        self.assertFalse(any(call.args[1]==1 for call in self.node_history.call_args_list))

    def test_control_state_transport_failures_are_isolated_per_node(self):
        for phase in ['connected','started','api']:
            for error in [OSError('transport'),TimeoutError('deadline'),NodeAPIError('session'),XrayError('rpc')]:
                with self.subTest(phase=phase,error=type(error).__name__):
                    self.nodes[1] = UnavailableNode(phase,error)
                    self.healthy.resets.clear()
                    self.namespace['record_user_usages']()
                    self.namespace['record_node_usages']()
                    self.assertEqual(self.healthy.resets,[('users',True),('node',True)])

    def test_retired_api_with_cleared_epoch_never_falls_back_to_reset(self):
        self.healthy.retired = True
        self.healthy.usage_epoch = None
        self.assertEqual(self.namespace['get_recordable_stats'](self.healthy,2,'users'),[])
        self.assertEqual(self.healthy.resets,[])


if __name__=='__main__':
    unittest.main()
