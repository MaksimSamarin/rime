"""Validate per-node transport options and backward-compatible defaults without any network."""
import ast,json,os,socket,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]

def functions():
 tree=ast.parse((ROOT/'app/xray/node.py').read_text());env={'json':json,'os':os}
 for name in ['_node_control_options','_control_timeout','_control_failure_threshold']:
  fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
  exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'node-options','exec'),env)
 return tree,env

class ControlOptionsTests(unittest.TestCase):
 def setUp(self):
  self.env_patch=patch.dict(os.environ,{'RIME_NODE_CONTROL_OVERRIDES':'{}'});self.env_patch.start();self.addCleanup(self.env_patch.stop)
  self.tree,self.env=functions()
 def setting(self,value):os.environ['RIME_NODE_CONTROL_OVERRIDES']=json.dumps(value)
 def test_default_deadlines_unchanged(self):
  for default in [1,2,3,5,10,15,30]:self.assertEqual(self.env['_control_timeout']('example',default),default)
 def test_only_selected_node_gets_larger_deadline(self):
  self.setting({'selected':{'timeout':10,'health_timeout':8}})
  self.assertEqual(self.env['_control_timeout']('selected',3),10)
  self.assertEqual(self.env['_control_timeout']('selected',2,'health_timeout'),8)
  self.assertEqual(self.env['_control_timeout']('other',3),3)
 def test_override_never_reduces_existing_deadline(self):
  self.setting({'selected':{'timeout':10}});self.assertEqual(self.env['_control_timeout']('selected',30),30)
 def test_bad_json_uses_defaults(self):
  os.environ['RIME_NODE_CONTROL_OVERRIDES']='{';self.assertEqual(self.env['_control_timeout']('selected',3),3)
 def test_non_mapping_uses_defaults(self):
  for value in [[],None,42,'x',{'selected':[]}]:
   self.setting(value);self.assertEqual(self.env['_control_timeout']('selected',3),3)
 def test_invalid_deadlines_are_ignored(self):
  for value in [True,False,'10',None,0,-1,61,float('nan'),float('inf')]:
   self.setting({'selected':{'timeout':value}});self.assertEqual(self.env['_control_timeout']('selected',3),3)
 def test_explicit_rest_skips_heuristic_network_probe(self):
  self.setting({'selected':{'protocol':'rest'}})
  owner=next(n for n in self.tree.body if isinstance(n,ast.ClassDef) and n.name=='XRayNode')
  fn=next(n for n in owner.body if isinstance(n,ast.FunctionDef) and n.name=='__new__')
  self.env.update(ReSTXRayNode=lambda **kw:kw,RPyCXRayNode=lambda **kw:None,socket=types.SimpleNamespace(socket=lambda *a:(_ for _ in ()).throw(AssertionError('Heuristic used'))))
  exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'node-factory','exec'),self.env)
  result=self.env['__new__'](None,address='selected',port=62050,api_port=62051,ssl_key='test-key',ssl_cert='test-cert')
  self.assertEqual(result['address'],'selected');self.assertEqual(result['api_port'],62051)
 def test_relay_transport_keeps_the_exit_node_protocol_settings(self):
  self.setting({'exit-node':{'protocol':'rest','health_timeout':8}})
  owner=next(n for n in self.tree.body if isinstance(n,ast.ClassDef) and n.name=='XRayNode')
  fn=next(n for n in owner.body if isinstance(n,ast.FunctionDef) and n.name=='__new__')
  self.env.update(ReSTXRayNode=lambda **kw:kw,RPyCXRayNode=lambda **kw:None,socket=types.SimpleNamespace(socket=lambda *a:(_ for _ in ()).throw(AssertionError('Heuristic used'))))
  exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'node-factory','exec'),self.env)
  result=self.env['__new__'](None,address='entry-node',port=10443,api_port=10444,ssl_key='synthetic-key',ssl_cert='synthetic-cert',control_address='exit-node')
  self.assertEqual(result['address'],'entry-node')
  self.assertEqual(result['control_address'],'exit-node')
 def test_health_job_honours_per_node_deadline(self):
  tree=ast.parse((ROOT/'app/jobs/0_xray_core.py').read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='core_health_check')
  observed=[]
  def node(timeout=None):
   n=types.SimpleNamespace(connected=True,started=True,api=types.SimpleNamespace(get_sys_stats=lambda timeout:observed.append(timeout)))
   if timeout is not None:n.health_check_timeout=timeout
   return n
  env={'xray':types.SimpleNamespace(core=types.SimpleNamespace(started=True),nodes={3:node(8),5:node()}),'xray_exc':types.SimpleNamespace(XrayError=RuntimeError)}
  exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'health-job','exec'),env)
  env['core_health_check']();self.assertEqual(observed,[8,2])
 def test_failure_threshold_validation(self):
  for value in [True,'3',0,-1,11,None]:
   self.setting({'selected':{'health_failures':value}});self.assertEqual(self.env['_control_failure_threshold']('selected'),1)
  self.setting({'selected':{'health_failures':3}});self.assertEqual(self.env['_control_failure_threshold']('selected'),3)
 def health(self,node):
  tree=ast.parse((ROOT/'app/jobs/0_xray_core.py').read_text());actions=[]
  env={'xray':types.SimpleNamespace(core=types.SimpleNamespace(started=True),nodes={3:node},operations=types.SimpleNamespace(connect_node=lambda *a:actions.append('connect'),restart_node=lambda *a:actions.append('restart')),config=types.SimpleNamespace(include_db_users=lambda:{})),
   'logger':types.SimpleNamespace(warning=lambda *a:None),'xray_exc':types.SimpleNamespace(XrayError=RuntimeError)}
  for name in ['_defer_health_recovery','core_health_check']:
   fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
   exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'health-recovery','exec'),env)
  return env['core_health_check'],actions
 def test_single_and_second_transient_do_not_restart_selected_node(self):
  def fail(timeout):raise TimeoutError('simulated')
  node=types.SimpleNamespace(connected=True,started=True,health_failure_threshold=3,api=types.SimpleNamespace(get_sys_stats=fail))
  health,actions=self.health(node);health();health();self.assertEqual(actions,[])
  health();self.assertEqual(actions,['connect'])
 def test_success_resets_consecutive_failure_count(self):
  def fail(timeout):raise TimeoutError('simulated')
  node=types.SimpleNamespace(connected=True,started=True,health_failure_threshold=3,api=types.SimpleNamespace(get_sys_stats=fail))
  health,actions=self.health(node);health();node.api.get_sys_stats=lambda timeout:None;health()
  self.assertEqual(node._health_failure_count,0)
  node.api.get_sys_stats=fail;health();health();self.assertEqual(actions,[])
 def test_confirmed_stopped_core_restarts_immediately(self):
  node=types.SimpleNamespace(connected=True,started=False,health_failure_threshold=3)
  health,actions=self.health(node);health();self.assertEqual(actions,['restart'])
 def test_unconfigured_node_keeps_first_failure_recovery(self):
  def fail(timeout):raise TimeoutError('simulated')
  node=types.SimpleNamespace(connected=True,started=True,api=types.SimpleNamespace(get_sys_stats=fail))
  health,actions=self.health(node);health();self.assertEqual(actions,['connect'])

if __name__=='__main__':unittest.main()
