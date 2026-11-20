"""Cross-component regressions discovered during the independent fixes review."""
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
import urllib.error

from hy2bridge.store import Store
from hy2bridge.relay_accounting import RelayAccounting

spec=importlib.util.spec_from_file_location('cross_review_observer',Path(__file__).resolve().parents[1]/'relay-runtime/observer.py')
observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)


class ObserverAccountingCrossReview(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);database=root/'panel.sqlite3'
        with sqlite3.connect(database) as db:
            db.execute('CREATE TABLE fleet_tunnel_services(id TEXT PRIMARY KEY,entry TEXT)')
            db.execute('INSERT INTO fleet_tunnel_services VALUES(?,?)',('a'*32,'entry'))
        self.accounting=RelayAccounting(Store(database))
        self.journal=observer.Journal(root/'observer.sqlite3')

    def queue(self,known,unknown=False):
        totals={'a'*32:{'epoch':'process-generation','rx':known,'tx':0}}
        if unknown:totals['b'*32]={'epoch':'process-generation','rx':known,'tx':0}
        with self.journal.connect() as db:
            observer.Journal.enqueue(db,{'epoch':'process-one','observed_at':time.time(),'totals':totals})

    def deliver(self):
        accounting=self.accounting
        class Opener:
            def open(self,request,timeout):
                try:result=accounting.ingest('entry',json.loads(request.data))
                except ValueError as error:
                    code='relay_service_unregistered' if 'does not belong' in str(error) else 'journal_conflict'
                    raise urllib.error.HTTPError(request.full_url,409,'Rejected',{},
                        io.BytesIO(json.dumps({'detail':{'code':code}}).encode())) from None
                return io.BytesIO(json.dumps(result).encode())
        observer.deliver(self.journal,Opener(),{'panel_url':'http://127.0.0.1','id':'entry','token':'synthetic-token'},limit=16)

    def total(self):
        with self.accounting.store.connection() as db:
            row=db.execute('SELECT rx FROM fleet_relay_totals WHERE service=?',('a'*32,)).fetchone()
        return row[0] if row else 0

    def test_quarantine_fragment_cannot_rebill_an_older_cumulative_snapshot(self):
        self.queue(100,unknown=True)
        self.queue(150)
        self.deliver()
        self.assertEqual(self.total(),150)
        self.assertGreaterEqual(self.journal.quarantine_count(),1)
        self.assertIsNone(self.journal.first())

    def test_journal_conflict_does_not_replay_fragments_under_a_new_receipt(self):
        self.queue(100,unknown=True)
        self.queue(180)
        first=json.loads(self.journal.first()[1])
        accepted={**first,'totals':{'a'*32:{'epoch':'process-generation','rx':150,'tx':0}}}
        self.accounting.ingest('entry',accepted)
        self.deliver()
        self.assertEqual(self.total(),180)

    def test_actual_telemetry_route_distinguishes_registration_and_sequence_conflicts(self):
        from unittest.mock import Mock
        from test_relay_switch_api import RelaySwitchApiTests
        from hy2bridge.relay_accounting import UnknownRelayService
        fixture=RelaySwitchApiTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.service.ingest=Mock(side_effect=UnknownRelayService('Unknown registered service'))
        packet={'spool':'s'*32,'seq':1,'epoch':'process-one','observed_at':time.time(),
                'totals':{'a'*32:{'epoch':'process-generation','rx':100,'tx':0}}}
        path='/api/fleet/relays/'+'e'*32+'/telemetry'
        response=fixture.post(path,packet,headers={'Authorization':'Bearer synthetic-token'})
        self.assertEqual(response.status_code,409)
        self.assertEqual(response.json()['detail']['code'],'relay_service_unregistered')
        fixture.service.ingest.side_effect=ValueError('Sequence conflicts with accepted data')
        response=fixture.post(path,packet,headers={'Authorization':'Bearer synthetic-token'})
        self.assertEqual(response.status_code,409)
        self.assertIsInstance(response.json()['detail'],str)


class RelayOwnershipCrossReview(unittest.TestCase):
    def setUp(self):
        from test_relays import RelayTests
        self.fixture=RelayTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.relays=self.fixture.relays
        self.relays.install_route('b'*32,self.fixture.record())
        self.job='f'*32
        self.desired=self.relays.changes.prepare_proxy_delete(self.job,'node-a','c'*32)

    def test_retained_rule_survives_gost_metadata_case_normalization(self):
        from copy import deepcopy
        from hy2bridge.relay_switch import RelaySwitches
        self.fixture.control.values={name:deepcopy(RelaySwitches.comparable_configuration(value))
                                     for name,value in self.fixture.control.values.items()}
        self.relays.changes.apply(self.job,self.desired)
        retained=self.desired['services'][0]
        self.assertIn(json.loads(retained['config'])['name'],self.fixture.control.values)

    def test_removal_preserves_manually_changed_rule_with_the_same_name(self):
        from hy2bridge.provision import ProvisionError
        before=json.loads(self.relays.changes.read(self.job)['before'])
        removed=next(value for value in before['services'] if value['proxy']=='c'*32)
        name=json.loads(removed['config'])['name']
        self.fixture.control.values[name]['forwarder']['nodes'][0]['addr']='192.0.2.222:29999'
        with self.assertRaises(ProvisionError):self.relays.changes.apply(self.job,self.desired)
        self.assertEqual(self.fixture.control.values[name]['forwarder']['nodes'][0]['addr'],'192.0.2.222:29999')


class RelayAvailabilityCrossReview(unittest.TestCase):
    def test_planned_switch_uses_current_telemetry_for_the_selected_grace_period(self):
        from test_relay_switch import RelaySwitchTests
        fixture=RelaySwitchTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        relays=fixture.relays
        plan=relays.switches.plan(fixture.route_id,'c'*32,grace_seconds=3600)
        record=relays.plans[plan['id']]
        record['previous_entry']['seen_at']=time.time()-120
        with relays.store.connection(write=True) as db:
            db.execute('UPDATE fleet_relay_entries SET seen_at=? WHERE id=?',(time.time(),'a'*32))
        relays.switches.worker(plan['id'],record)
        self.assertEqual(relays.switches.read(plan['id'])['phase'],'grace_pending')
        self.assertTrue(fixture.controls['a'*32].values)

    def test_dead_entry_with_a_stale_failed_change_can_be_detached_and_forgotten(self):
        from test_relay_switch import RelaySwitchTests
        fixture=RelaySwitchTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        relays=fixture.relays
        relays.changes.prepare('f'*32,'node-a','native-edit')
        with relays.store.connection(write=True) as db:
            db.execute("UPDATE fleet_relay_changes SET phase='needs_reconcile' WHERE id=?",('f'*32,))
            db.execute("INSERT INTO fleet_relay_edits VALUES(?,?,'failed')",('f'*32,'node-a'))
            db.execute("UPDATE fleet_tunnels SET state='needs_reconcile' WHERE id=?",(fixture.route_id,))
        # Process restart released RAM ownership; the old VPS is permanently gone.
        relays.busy.clear();fixture.controls['a'*32].offline=True
        route=relays.switches.snapshot(fixture.route_id)['tunnel']
        relays.retirements.detach('e'*32,route)
        self.assertEqual(relays.endpoint_map('node-a'),{})
        result=relays.forget_entry('a'*32,relays.entry('a'*32)['domain'])
        self.assertTrue(result['forgotten'])


class ProxyCheckpointCrossReview(unittest.TestCase):
    def test_cleanup_resumes_original_checkpoint_after_commit_gap_and_timer_restore(self):
        from test_proxy_delete import ProxyDeletionTests
        from hy2bridge.provision import ProvisionError
        fixture=ProxyDeletionTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        original=fixture.proxy.remote
        checkpoints=[]
        def crash_before_remote_commit(client,config):
            if config['action']=='managed-delete-commit':
                checkpoints.append(config['id'])
                raise SystemExit('Process lost after database commit but before remote commit')
            return original(client,config)
        fixture.proxy.remote=crash_before_remote_commit
        plan=fixture.deletion.plan('a'*32,fixture.access())
        record=fixture.deletion.plans.pop(plan['id'])
        with self.assertRaises(SystemExit):fixture.deletion.worker(record,'192.0.2.1')
        with fixture.store.connection() as db:
            self.assertEqual(db.execute('SELECT active FROM fleet_proxy_services WHERE id=?',('a'*32,)).fetchone()[0],0)
        fixture.running=True # The original remote watchdog restored the service.
        resumed=[]
        def strict_remote(client,config):
            if config['action']=='managed-delete-resume':
                resumed.append(config['id']);fixture.running=False
                return {'committed':True}
            if config['action']=='managed-delete-finalize' and fixture.running:
                raise ProvisionError('Actual remote finalize refuses a running container')
            return original(client,config)
        fixture.proxy.remote=strict_remote
        result=fixture.execute()
        self.assertEqual(result['state'],'succeeded')
        self.assertEqual(resumed,checkpoints)
        self.assertTrue(fixture.removed)


if __name__=='__main__':unittest.main()
