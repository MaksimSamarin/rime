import ast,copy,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import MagicMock


class ScopedCoreUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'core.json';self.path.write_text('{"original":true}')
        self.xray=types.SimpleNamespace(config=types.SimpleNamespace(api_port=10001),core=MagicMock(),hosts=MagicMock(),operations=MagicMock(),nodes={3:types.SimpleNamespace(connected=True),6:types.SimpleNamespace(connected=True),5:types.SimpleNamespace(connected=False)})
        class Config:
            def __init__(self,payload,api_port):
                if payload.get('invalid'):raise ValueError('Invalid core')
                self.api_port=api_port;self.payload=payload
            def include_db_users(self):return {'users':'same existing accounts','config':self.payload}
        class HTTPError(Exception):
            def __init__(self,**values):self.values=values
        self.error=HTTPError
        tree=ast.parse((Path(__file__).parents[1]/'app/routers/core.py').read_text())
        fn=copy.deepcopy(next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='modify_core_config'));fn.decorator_list=[]
        namespace={'json':json,'xray':self.xray,'XRAY_JSON':str(self.path),'XRayConfig':Config,'HTTPException':HTTPError,'Admin':types.SimpleNamespace(check_sudo_admin=None),'Depends':lambda value:None}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'core.py','exec'),namespace)
        self.apply=namespace['modify_core_config']

    def test_scoped_config_update_retains_existing_users_without_restarting_remote_nodes(self):
        payload={'inbounds':[{'tag':'EXISTING'},{'tag':'NEW_NODE_ENDPOINT'}]}
        self.assertEqual(self.apply(payload,restart_nodes=False),payload)
        self.xray.operations.restart_node.assert_not_called()
        self.xray.core.restart.assert_called_once_with({'users':'same existing accounts','config':payload})
        self.assertEqual(json.loads(self.path.read_text()),payload)
        self.xray.hosts.update.assert_called_once()

    def test_default_retains_restart_behavior_for_connected_nodes(self):
        self.apply({'inbounds':[]})
        self.assertEqual([c.args[0] for c in self.xray.operations.restart_node.call_args_list],[3,6])

    def test_invalid_config_does_not_write_or_restart_any_core(self):
        before=self.path.read_bytes();config=self.xray.config
        with self.assertRaises(self.error):self.apply({'invalid':True},restart_nodes=False)
        self.assertEqual(self.path.read_bytes(),before);self.assertIs(self.xray.config,config)
        self.xray.core.restart.assert_not_called();self.xray.operations.restart_node.assert_not_called()
