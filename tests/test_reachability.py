import time
import unittest
from hy2bridge.operations import Operations
from hy2bridge.reachability import Reachability
import test_accounting


class ReachabilityTests(unittest.TestCase):
    setUp=test_accounting.AccountingTests.setUp
    tearDown=test_accounting.AccountingTests.tearDown

    def configure(self):
        ops=Operations(self.store);ops.ensure_node('n1')
        probe=Reachability(self.store,[{'id':'home','label':'Home test network','nodes':['n1'],'token':'s'*32}])
        ops.reachability=probe
        return ops,probe

    def sample(self,passed=True,stage='payload'):
        return {'passed':passed,'stage':stage,'checked_at':time.time(),'target_ip':'192.0.2.1','latency_ms':20}

    def test_resource_health_never_claims_client_reachability(self):
        ops,_=self.configure();ops.heartbeat('n1',{'service_healthy':True})
        self.assertEqual(ops.nodes()[0]['client_access']['state'],'unknown')

    def test_credential_is_separate_and_node_scoped(self):
        _,p=self.configure()
        self.assertTrue(p.authorize('home','n1','Bearer '+'s'*32))
        for probe,node,header in [('home','other','Bearer '+'s'*32),('other','n1','Bearer '+'s'*32),('home','n1','Bearer '+'x'*32)]:
            self.assertFalse(p.authorize(probe,node,header))

    def test_real_failure_opens_one_incident_and_success_resolves(self):
        ops,p=self.configure();ops.heartbeat('n1',{'service_healthy':True})
        for _ in range(3):p.ingest('home','n1',self.sample(False,'connect'))
        self.assertEqual(ops.nodes()[0]['client_access']['state'],'unavailable')
        self.assertEqual(ops.events()[0]['occurrences'],3)
        self.assertIsNone(ops.events()[0]['resolved_at'])
        self.assertIn('test-uuid',self.store.policy('n1')['allowed'])
        p.ingest('home','n1',self.sample())
        self.assertEqual(ops.nodes()[0]['client_access']['state'],'available')
        self.assertIsNotNone(ops.events()[0]['resolved_at'])

    def test_expired_result_becomes_unknown_and_rows_are_bounded(self):
        ops,p=self.configure();p.ingest('home','n1',self.sample())
        with self.store.connection(write=True) as db:db.execute('UPDATE fleet_client_probes SET checked_at=?',(time.time()-200,))
        self.assertEqual(ops.nodes()[0]['client_access']['state'],'unknown')
        for _ in range(10):p.ingest('home','n1',self.sample())
        with self.store.connection() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM fleet_client_probes').fetchone()[0],1)

    def test_bad_clock_route_or_only_auth_cannot_claim_payload_success(self):
        ops,p=self.configure()
        with self.assertRaises(ValueError):p.ingest('home','n1',{**self.sample(),'checked_at':time.time()-300})
        with self.assertRaises(ValueError):p.ingest('home','n1',self.sample(True,'connect'))
        p.ingest('home','n1',self.sample(False,'route'))
        self.assertEqual(ops.nodes()[0]['client_access']['state'],'unknown')

    def test_replaced_registration_does_not_inherit_old_green_result(self):
        ops,p=self.configure();p.ingest('home','n1',self.sample())
        with self.store.connection(write=True) as db:db.execute('DELETE FROM fleet_inventory WHERE id=?',('n1',))
        ops.ensure_node('n1',address='198.51.100.1')
        self.assertEqual(ops.nodes()[0]['client_access']['state'],'unknown')
