"""Keep controller connections aligned with the selected entry generation."""
import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
import threading
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('management_node_jobs', ROOT / 'app/utils/node_jobs.py')
jobs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jobs)


class ManualExecutor:
    def submit(self, function, *args):
        self.function, self.args = function, args

    def run(self):
        self.function(*self.args)


class TunnelManagementEndpointTests(unittest.TestCase):
    def setUp(self):
        self.selected = ('entry-a.example', 62450, 62451)
        self.dbnode = SimpleNamespace(id=5, name='Fixture exit', status='connected',
                                      address='192.0.2.20', port=62050, api_port=62051, usage_coefficient=1)
        self.original = self.node(self.selected)
        self.nodes = {5:self.original}
        self.created = []

        def add_node(dbnode):
            node = self.node(self.selected)
            self.created.append(node)
            self.nodes[dbnode.id] = node
            return node

        class Database:
            def __enter__(self):return self
            def __exit__(self,*args):return None

        self.namespace = {'GetDB':Database,
                          'crud':SimpleNamespace(get_node_by_id=lambda db,ident:self.dbnode),
                          'NodeStatus':SimpleNamespace(disabled='disabled', connecting='connecting', connected='connected', error='error'),
                          'logger':Mock(), '_connecting_nodes':{}, '_change_node_status':Mock(),
                          'filter_config':lambda value,node:value, '_management_endpoint':lambda node:self.selected,
                          'xray':SimpleNamespace(nodes=self.nodes, operations=SimpleNamespace(add_node=add_node),
                                                 config=SimpleNamespace(include_db_users=lambda:{'users':'latest'}))}
        tree = ast.parse((ROOT / 'app/xray/operations.py').read_text())
        for name in ['_node_endpoint_matches','_connect_node','_restart_node']:
            function = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==name)
            exec(compile(ast.Module(body=[function],type_ignores=[]),'management-operations','exec'),self.namespace)

    def node(self, endpoint):
        return SimpleNamespace(address=endpoint[0],port=endpoint[1],api_port=endpoint[2],
                               control_address='192.0.2.20',control_api_port=62051,usage_coefficient=1,
                               connected=True,start=Mock(),restart=Mock(),get_version=lambda:'26.6.1')

    def test_healthy_old_connection_is_replaced_when_selected_entry_changes(self):
        self.selected = ('entry-b.example', 63450, 63451)
        self.namespace['_connect_node'](5)
        self.assertEqual(len(self.created),1)
        self.assertEqual(self.nodes[5].address,'entry-b.example')
        self.original.start.assert_not_called()
        self.nodes[5].start.assert_called_once_with({'users':'latest'})

    def test_unchanged_endpoint_keeps_the_existing_client(self):
        self.namespace['_connect_node'](5)
        self.assertFalse(self.created)
        self.original.start.assert_called_once()

    def test_replacement_reconciles_a_user_committed_during_initial_start(self):
        self.selected = ('entry-b.example', 63450, 63451)
        users = ['existing-user']
        include_users = Mock(side_effect=lambda:{'users':list(users)})
        self.namespace['xray'].config.include_db_users = include_users
        original_add = self.namespace['xray'].operations.add_node

        def add_replacement(dbnode):
            node = original_add(dbnode)
            node._user_reconcile = True
            node.api = SimpleNamespace(control_lock=threading.RLock())

            def start(configuration):
                if node.start.call_count == 1:
                    users.append('created-during-start')

            node.start.side_effect = start
            return node

        self.namespace['xray'].operations.add_node = add_replacement
        self.namespace['_connect_node'](5)
        current = self.nodes[5]
        self.assertEqual(current.address,'entry-b.example')
        self.assertEqual(include_users.call_count,2)
        self.assertEqual(current.start.call_args_list[0].args[0],{'users':['existing-user']})
        self.assertEqual(current.start.call_args_list[1].args[0],
                         {'users':['existing-user','created-during-start']})
        self.assertEqual(self.namespace['_change_node_status'].call_args.args[1],'connected')

    def test_forwarded_api_port_change_replaces_client(self):
        self.selected = ('entry-a.example', 62450, 63451)
        self.namespace['_connect_node'](5)
        self.assertEqual(self.nodes[5].api_port,63451)

    def test_explicit_restart_uses_the_selected_entry(self):
        self.selected = ('entry-b.example', 63450, 63451)
        self.namespace['_restart_node'](5, {'requested':'restart'})
        self.assertEqual(self.nodes[5].address,'entry-b.example')
        self.nodes[5].restart.assert_called_once_with({'requested':'restart'})
        self.original.restart.assert_not_called()

    def test_restart_reconciles_latest_database_without_repopulating_a_snapshot(self):
        from contextlib import contextmanager
        from sqlalchemy import Column,ForeignKey,Integer,JSON,String,Table,create_engine
        from sqlalchemy.orm import declarative_base,sessionmaker
        from test_hub_api_security import real_configuration_module,security_module
        base=declarative_base()
        class User(base):
            __tablename__='users'
            id=Column(Integer,primary_key=True)
            username=Column(String)
            status=Column(String)
        class Proxy(base):
            __tablename__='proxies'
            id=Column(Integer,primary_key=True)
            user_id=Column(ForeignKey('users.id'))
            type=Column(String)
            settings=Column(JSON)
        excluded=Table('excluded',base.metadata,Column('proxy_id',ForeignKey('proxies.id')),
                       Column('inbound_tag',String))
        engine=create_engine('sqlite:///:memory:');self.addCleanup(engine.dispose)
        base.metadata.create_all(engine);sessions=sessionmaker(bind=engine)
        @contextmanager
        def database():
            with sessions() as db:yield db
        module=real_configuration_module(security_module())
        module.GetDB=database
        module.db_models.User=User;module.db_models.Proxy=Proxy
        module.db_models.excluded_inbounds_association=excluded
        def add_user(identity,name):
            with sessions.begin() as db:
                db.add(User(id=identity,username=name,status='active'))
                db.add(Proxy(id=identity,user_id=identity,type='vless',settings={'id':str(identity)}))
        add_user(1,'alice')
        raw=module.XRayConfig({'inbounds':[{'tag':'VPN','port':443,'protocol':'vless',
            'settings':{'clients':[],'decryption':'none'}}],
            'outbounds':[{'tag':'DIRECT','protocol':'freedom'}]})
        startup=raw.include_db_users()
        self.assertEqual(len(startup.get_inbound('VPN')['settings']['clients']),1)
        self.namespace['xray'].config=raw
        self.original._user_reconcile=True
        self.original.api=SimpleNamespace(control_lock=threading.RLock())
        self.original.restart.side_effect=lambda _:add_user(2,'bob')
        self.namespace['_restart_node'](5,startup)
        self.original.start.assert_called_once()
        latest=self.original.start.call_args.args[0]
        emails=[user['email'] for user in latest.get_inbound('VPN')['settings']['clients']]
        self.assertEqual(emails,['1.alice','2.bob'])
        self.assertEqual(len(startup.get_inbound('VPN')['settings']['clients']),1)

    def test_only_latest_endpoint_refresh_runs_after_an_inflight_connect(self):
        executor = ManualExecutor()
        queue = jobs.NodeJobs(executor=executor)
        seen = []

        def first():
            seen.append('a')
            queue.submit(5,'connect',lambda:seen.append('b'),replace_connect=True)
            queue.submit(5,'connect',lambda:seen.append('c'),replace_connect=True)

        queue.submit(5,'connect',first)
        executor.run()
        self.assertEqual(seen,['a','c'])
        self.assertFalse(queue._running)

    def test_endpoint_refresh_preserves_an_explicit_queued_restart(self):
        executor = ManualExecutor()
        queue = jobs.NodeJobs(executor=executor)
        seen = []

        def first():
            queue.submit(5,'restart',lambda:seen.append('restart'))
            queue.submit(5,'connect',lambda:seen.append('refresh'),replace_connect=True)

        queue.submit(5,'connect',first)
        executor.run()
        self.assertEqual(seen,['restart'])

    def test_retiring_a_client_closes_only_local_transports_even_if_disconnect_fails(self):
        tree = ast.parse((ROOT / 'app/xray/node.py').read_text())
        function = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='close_control_client')
        namespace = {'control_lock':lambda *identity:threading.RLock()}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'close-controller','exec'),namespace)
        api = SimpleNamespace(usage_epoch=lambda:'epoch',_channel=SimpleNamespace(close=Mock()))
        node = SimpleNamespace(address='entry-a',api_port=62451,control_address='exit',control_api_port=62051,
                               _api=api,disconnect=Mock(side_effect=OSError('Old entry unavailable')),stop=Mock(),
                               _logs_queues=[[]],session=Mock(),_keyfile=Mock(),_certfile=Mock())
        with self.assertRaises(OSError):
            namespace['close_control_client'](node)
        self.assertTrue(api.retired)
        self.assertIsNone(api.usage_epoch)
        api._channel.close.assert_called_once()
        node.stop.assert_not_called()
        node.session.close.assert_called_once()
        node._keyfile.close.assert_called_once()
        self.assertEqual(node._logs_queues,[])

    def test_delayed_user_mutations_skip_a_retired_channel(self):
        tree = ast.parse((ROOT / 'app/xray/operations.py').read_text())
        api = SimpleNamespace(control_lock=threading.RLock(),retired=True,
                              add_inbound_user=Mock(),remove_inbound_user=Mock())
        namespace = {'XRayAPI':object,'Account':object}
        names = ['_add_user_to_inbound','_remove_user_from_inbound','_alter_inbound_user']
        for function in [node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]:
            function.decorator_list=[]
            exec(compile(ast.Module(body=[function],type_ignores=[]),'retired-mutations','exec'),namespace)
        for name in names:
            namespace[name](api,'VPN',SimpleNamespace(email='1.fixture'))
        api.add_inbound_user.assert_not_called()
        api.remove_inbound_user.assert_not_called()

    def test_retired_rpyc_disconnect_closes_transport_without_waiting_for_rpc(self):
        tree = ast.parse((ROOT / 'app/xray/node.py').read_text())
        owner = next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='RPyCXRayNode')
        function = next(node for node in owner.body if isinstance(node,ast.FunctionDef) and node.name=='disconnect')
        namespace = {}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'retired-rpyc-disconnect','exec'),namespace)
        connection = SimpleNamespace(close=Mock(side_effect=AssertionError('Graceful RPC close would wait on the dead entry')),
                                     _channel=SimpleNamespace(close=Mock()))
        node = SimpleNamespace(_closed=True,connection=connection)
        namespace['disconnect'](node)
        namespace['disconnect'](node)
        connection._channel.close.assert_called_once()
        connection.close.assert_not_called()
        self.assertFalse(hasattr(node,'connection'))


if __name__ == '__main__':
    unittest.main()
