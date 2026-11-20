"""Independent regressions for the 2026-11 relay audit findings."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import time
import unittest
from unittest.mock import Mock

import test_relay_switch as fixture
from hy2bridge.provision import ProvisionError
from hy2bridge.relay_control import initial_configuration


class RelayAuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.RelaySwitchTests('test_healthy_switch_publishes_after_probe_and_keeps_identity')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.relays = self.fixture.relays

    def test_invalid_hy2_port_preserves_the_original_subscription_link(self):
        for link in ('hysteria2://key@exit.example:20000-30000/?sni=exit.example',
                     'hysteria2://key@exit.example:not-a-port/', 'hysteria2://key@exit.example:99999/'):
            self.assertEqual(self.relays.published_link('node-a',link),link)

    def test_force_detach_unreachable_entry_publishes_direct_and_recovers_cleanup(self):
        old=self.fixture.mapping()
        self.fixture.controls['a'*32].offline=True
        route=self.relays.switches.snapshot(self.fixture.route_id)['tunnel']
        self.relays.retirements.detach('f'*32,route)
        self.assertEqual(self.relays.endpoint_map('node-a'),{})
        self.assertEqual(self.relays.job('f'*32)['state'],'succeeded')
        self.assertEqual(self.relays.published_link('node-a','hysteria2://key@exit.example:443'),'hysteria2://key@exit.example:443')
        self.assertEqual(self.relays.retirements.pending_entry('a'*32),1)
        self.fixture.controls['a'*32].offline=False
        with self.relays.store.connection(write=True) as db:
            db.execute('UPDATE fleet_relay_retirements SET retry_at=0')
        self.relays.retirements.recover()
        self.assertNotIn(json.loads(old['config'])['name'],self.fixture.controls['a'*32].values)
        self.assertEqual(self.relays.retirements.pending_entry('a'*32),0)

    def test_forget_requires_exact_confirmation_and_no_current_routes(self):
        entry=self.relays.entry('a'*32)
        with self.assertRaises(ProvisionError):self.relays.forget_entry(entry['id'],'wrong-domain')
        with self.assertRaises(ProvisionError):self.relays.forget_entry(entry['id'],entry['domain'])
        self.fixture.controls['a'*32].offline=True
        self.relays.retirements.detach('f'*32,self.relays.switches.snapshot(self.fixture.route_id)['tunnel'])
        self.relays.forget_entry(entry['id'],entry['domain'])
        self.assertEqual(self.relays.entry(entry['id'])['state'],'deleted')
        self.assertEqual(self.relays.entry(entry['id'])['credential'],'')
        self.assertEqual(self.relays.retirements.pending_entry(entry['id']),0)

    def test_planned_switch_keeps_old_rules_until_grace_expires(self):
        self.relays.settings.pop('relay_switch_grace_seconds',None)
        previous=deepcopy(self.fixture.controls['a'*32].values)
        job=self.fixture.execute(self.fixture.plan())
        self.assertEqual(job['state'],'succeeded')
        self.assertEqual(self.fixture.controls['a'*32].values,previous)
        row=self.relays.switches.read(job['id'])
        self.assertEqual(row['phase'],'grace_pending')
        self.assertGreater(row['retry_at'],time.time()+23*3600)
        self.relays.switches.recover()
        self.assertEqual(self.fixture.controls['a'*32].values,previous)
        self.fixture.due();self.relays.switches.recover()
        self.assertEqual(self.fixture.controls['a'*32].values,{})

    def test_emergency_switch_skips_default_grace_for_dead_old_entry(self):
        self.relays.settings.pop('relay_switch_grace_seconds',None)
        self.fixture.controls['a'*32].offline=True
        job=self.fixture.execute(self.fixture.plan())
        self.assertEqual(job['state'],'succeeded')
        self.assertEqual(self.relays.switches.read(job['id'])['phase'],'cleanup_pending')
        self.assertIsNone(job['context']['grace_until'])

    def test_recovery_after_publication_preserves_the_planned_grace(self):
        self.relays.settings.pop('relay_switch_grace_seconds',None)
        plan=self.fixture.plan();original=self.relays.switches.grace_seconds
        def interrupted(*args,**kwargs):raise SystemExit('Synthetic process loss after publication')
        self.relays.switches.grace_seconds=interrupted
        with self.assertRaises(SystemExit):self.relays.switches.worker(plan['id'],self.relays.plans[plan['id']])
        self.relays.switches.grace_seconds=original
        self.relays.switches.recover()
        self.assertEqual(self.relays.switches.read(plan['id'])['phase'],'grace_pending')
        self.assertTrue(self.fixture.controls['a'*32].values)

    def test_proxy_detach_is_journaled_before_remote_change_and_recovers(self):
        route=self.relays.switches.snapshot(self.fixture.route_id)
        service=deepcopy(route['services'][0]);service.update(id='9'*32,kind='proxy',proxy='8'*32,protocol='tcp',origin_port=3128,public_port=13128)
        from hy2bridge.relay_control import forwarding_service
        service['config']=json.dumps(forwarding_service('9'*32+'-12345678',13128,'192.0.2.20',3128,'tcp'))
        with self.relays.store.connection(write=True) as db:
            db.execute('INSERT INTO fleet_tunnel_services VALUES(?,?,?,?,?,?,?,?,?,?)',tuple(service[k] for k in ('id','tunnel','entry','kind','proxy','protocol','origin_port','public_port','config','state')))
            db.execute('CREATE TABLE fleet_proxy_jobs(id TEXT PRIMARY KEY,state TEXT)')
            db.execute('INSERT INTO fleet_proxy_jobs VALUES(?,?)',('7'*32,'running'))
        self.fixture.controls['a'*32].add(json.loads(service['config']))
        desired=self.relays.changes.prepare_proxy_delete('7'*32,'node-a','8'*32)
        self.relays.changes.apply('7'*32,desired)
        self.assertNotIn(json.loads(service['config'])['name'],self.fixture.controls['a'*32].values)
        self.assertEqual(self.relays.changes.read('7'*32)['phase'],'applied')
        self.relays.busy.clear();self.relays.changes.recover()
        self.assertIn(json.loads(service['config'])['name'],self.fixture.controls['a'*32].values)
        self.assertEqual(self.relays.changes.read('7'*32)['phase'],'rolled_back')

    def test_direct_proxy_delete_does_not_require_an_unrelated_entry(self):
        self.fixture.controls['a'*32].offline=True
        self.assertIsNone(self.relays.changes.prepare_proxy_delete('7'*32,'node-a','8'*32))
        self.assertIsNone(self.relays.changes.read('7'*32))
        self.assertFalse(self.relays.busy)

    def test_all_owned_rules_are_verified_before_any_destructive_removal(self):
        control=self.fixture.controls['a'*32]
        safe={'name':'a-owned','addr':'0.0.0.0:13128','listener':{'type':'tcp'},'metadata':{'enableStats':True}}
        changed={'name':'z-changed','addr':'0.0.0.0:13129','listener':{'type':'tcp'},'metadata':{'enableStats':True}}
        control.add(deepcopy(safe));control.add({**changed,'addr':'0.0.0.0:33333'})
        original=deepcopy(control.values)
        before={'services':[{'config':json.dumps(safe)},{'config':json.dumps(changed)}]}
        change={'entry':'a'*32,'before':json.dumps(before),'after':None}
        with self.assertRaises(ProvisionError):self.relays.changes.replace_remote(change,{'services':[]})
        self.assertEqual(control.values,original)

    def test_orphaned_running_change_can_be_abandoned_without_later_resurrection(self):
        change='6'*32
        self.relays.changes.prepare(change,'node-a','native-edit')
        self.relays.update(change,'running','Synthetic orphaned worker',{'node':'node-a'})
        with self.relays.store.connection(write=True) as db:
            db.execute("UPDATE fleet_relay_changes SET phase='needs_reconcile' WHERE id=?",(change,))
            db.execute("INSERT INTO fleet_relay_edits VALUES(?,?,'prepared')",(change,'node-a'))
        self.relays.busy.clear();self.relays.provision.running=set()
        self.fixture.controls['a'*32].offline=True
        route=self.relays.switches.snapshot(self.fixture.route_id)['tunnel']
        self.relays.retirements.detach('5'*32,route)
        self.assertEqual(self.relays.changes.read(change)['phase'],'abandoned')
        self.assertEqual(self.relays.job(change)['state'],'failed')
        self.assertIsNone(self.relays.changes.pending(change))
        self.relays.changes.finish(change,True,recheck=True)
        self.relays.changes.rollback(change)
        self.relays.changes.recover()
        self.assertEqual(self.relays.endpoint_map('node-a'),{})
        self.assertEqual(self.relays.changes.read(change)['phase'],'abandoned')
        self.assertIsNone(self.relays.changes.prepare(change,'node-a','native-edit'))
        self.relays.forget_entry('a'*32,self.relays.entry('a'*32)['domain'])
        self.relays.changes.recover()
        self.assertFalse(self.relays.busy)
        self.assertEqual(self.relays.endpoint_map('node-a'),{})

    def test_force_does_not_clear_a_live_worker_or_live_exit_operation(self):
        change='6'*32
        self.relays.changes.prepare(change,'node-a','native-edit')
        route=self.relays.switches.snapshot(self.fixture.route_id)['tunnel']
        with self.assertRaises(ProvisionError):self.relays.retirements.detach('5'*32,route)
        self.assertEqual(self.relays.changes.read(change)['phase'],'prepared')
        self.relays.busy.clear();self.relays.provision.running={'192.0.2.20'}
        with self.assertRaises(ProvisionError):self.relays.retirements.detach('5'*32,route)
        self.assertTrue(self.relays.endpoint_map('node-a'))

    def test_force_abandons_interrupted_switch_and_cleans_candidate_without_resurrection(self):
        plan=self.fixture.plan();publish=self.relays.switches.publish
        def interrupted(*args):raise SystemExit('Synthetic controller loss before publication')
        self.relays.switches.publish=interrupted
        try:
            with self.assertRaises(SystemExit):self.relays.switches.worker(plan['id'],self.relays.plans[plan['id']])
        finally:self.relays.switches.publish=publish
        self.assertTrue(self.fixture.controls['c'*32].values)
        self.fixture.controls['a'*32].offline=True
        route=self.relays.switches.snapshot(self.fixture.route_id)['tunnel']
        self.relays.retirements.detach('5'*32,route)
        self.assertEqual(self.relays.switches.read(plan['id'])['phase'],'abandoned')
        self.assertFalse(self.fixture.controls['c'*32].values)
        self.relays.switches.recover()
        self.relays.changes.recover()
        self.assertEqual(self.relays.endpoint_map('node-a'),{})
        self.assertEqual(self.relays.retirements.pending_entry('a'*32),1)
        self.assertEqual(self.relays.retirements.pending_entry('c'*32),0)


class ObserverAuditTests(unittest.TestCase):
    @staticmethod
    def observer():
        spec=importlib.util.spec_from_file_location('audit_observer',Path(__file__).parents[1]/'relay-runtime/observer.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_local_plugin_has_separate_authentication_token(self):
        credential={'username':'control','password':'control-password','observer_token':'synthetic-local-observer-token'}
        config=initial_configuration(credential,62080,62081,'/state',62082)
        self.assertEqual(config['observers'][0]['plugin']['token'],credential['observer_token'])

    def test_rejected_packet_is_quarantined_and_following_health_can_progress(self):
        import tempfile
        module=self.observer()
        with tempfile.TemporaryDirectory() as d:
            journal=module.Journal(Path(d)/'journal.db')
            journal.collect('boot',{'cpu_percent':1})
            rejected=journal.first()
            journal.quarantine(rejected[0],409,'registration_conflict')
            journal.collect('boot',{'cpu_percent':2})
            following=journal.first()
            self.assertGreater(following[0],rejected[0])
            self.assertEqual(json.loads(following[1])['health']['cpu_percent'],2)
            with journal.connect() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM quarantine').fetchone()[0],1)

    def test_permanent_http_rejection_does_not_block_following_health(self):
        import io,tempfile,urllib.error
        module=self.observer()
        with tempfile.TemporaryDirectory() as d:
            journal=module.Journal(Path(d)/'journal.db')
            journal.collect('boot',{'cpu_percent':1})
            with journal.connect() as db:
                module.Journal.enqueue(db,{'epoch':'boot','observed_at':time.time(),'totals':{}})
            responses=[urllib.error.HTTPError('http://fixture',409,'Registration rejected',{},None),io.BytesIO(b'{"received":true}')]
            class Opener:
                def open(self,*args,**kwargs):
                    result=responses.pop(0)
                    if isinstance(result,Exception):raise result
                    return result
            module.deliver(journal,Opener(),{'panel_url':'http://fixture','id':'entry','token':'synthetic'})
            self.assertIsNone(journal.first())
            self.assertEqual(journal.quarantine_count(),1)

    def test_health_is_prioritized_without_skipping_older_counter_receipts(self):
        import tempfile
        module=self.observer()
        with tempfile.TemporaryDirectory() as d:
            journal=module.Journal(Path(d)/'journal.db')
            journal.observe([{'kind':'service','type':'stats','service':'rime-'+'a'*32+'-12345678',
                              'stats':{'inputBytes':10,'outputBytes':20}}],'boot')
            journal.collect('boot',{'cpu_percent':1})
            health=journal.first();health_body=json.loads(health[1])
            self.assertIn('health',health_body)
            journal.acknowledge(health[0])
            traffic=json.loads(journal.first()[1])
            self.assertLess(traffic['seq'],health_body['seq'])
            self.assertNotEqual(traffic['spool'],health_body['spool'])

    def test_poison_batch_is_isolated_so_known_service_can_be_accepted(self):
        import tempfile
        module=self.observer()
        with tempfile.TemporaryDirectory() as d:
            journal=module.Journal(Path(d)/'journal.db')
            with journal.connect() as db:
                module.Journal.enqueue(db,{'epoch':'boot','observed_at':time.time(),
                    'totals':{'a'*32:{'rx':1,'tx':2,'epoch':'service-a'},'b'*32:{'rx':3,'tx':4,'epoch':'service-b'}}})
            row=journal.first();journal.quarantine(row[0],409,'unknown_service')
            with journal.connect() as db:rows=[json.loads(row[0]) for row in db.execute('SELECT body FROM pending')]
            self.assertEqual(len(rows),2)
            self.assertTrue(all(len(row['totals'])==1 for row in rows))

    def test_transient_or_auth_failure_preserves_the_delivery_packet(self):
        import tempfile,urllib.error
        module=self.observer()
        for status in (401,403,429,503):
            with tempfile.TemporaryDirectory() as d:
                journal=module.Journal(Path(d)/'journal.db');journal.collect('boot',{})
                original=journal.first()
                class Opener:
                    def open(self,*args,**kwargs):raise urllib.error.HTTPError('http://fixture',status,'Retry later',{},None)
                with self.assertRaises(urllib.error.HTTPError):
                    module.deliver(journal,Opener(),{'panel_url':'http://fixture','id':'entry','token':'synthetic'})
                self.assertEqual(journal.first(),original)
                self.assertEqual(journal.quarantine_count(),0)

    def test_actual_packet_contract_accepts_counter_batch_without_health(self):
        from hy2bridge.relay_api import EntryPacket
        value=EntryPacket.model_validate({'spool':'synthetic-spool-0001','epoch':'synthetic-epoch','seq':1,
            'observed_at':time.time(),'totals':{'a'*32:{'rx':1,'tx':2,'epoch':'synthetic-counter'}}})
        self.assertIsNone(value.health)


class RelayAuditApiTests(unittest.TestCase):
    def setUp(self):
        import test_relay_switch_api as api_fixture
        self.fixture=api_fixture.RelaySwitchApiTests('test_switch_planning_requires_sudo')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.service.detach_route=Mock(return_value={'id':'f'*32})
        self.fixture.service.forget_entry=Mock(return_value={'forgotten':True})

    def test_force_and_forget_require_sudo_and_forward_explicit_confirmation(self):
        for kind,path,confirmation in [('detach_route','routes/'+'a'*32+'/detach','a'*32),
                                       ('forget_entry','entry/'+'b'*32+'/forget','entry.example')]:
            endpoint='/api/fleet/relays/'+path
            self.assertEqual(self.fixture.post(endpoint,{'confirmation':confirmation}).status_code,403)
            response=self.fixture.post(endpoint,{'confirmation':confirmation},headers=self.fixture.headers)
            self.assertEqual(response.status_code,200)
            getattr(self.fixture.service,kind).assert_called_once_with(('a' if kind=='detach_route' else 'b')*32,confirmation)


if __name__=='__main__':unittest.main()
