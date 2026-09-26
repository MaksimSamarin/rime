import unittest
import test_accounting
from hy2bridge.periods import Periods
from hy2bridge.store import Conflict

class PeriodTests(unittest.TestCase):
    setUp=test_accounting.AccountingTests.setUp
    tearDown=test_accounting.AccountingTests.tearDown
    batch=test_accounting.AccountingTests.batch

    def test_all_nodes_must_drain_before_reset(self):
        self.store.ingest('n1',self.batch());self.store.ingest('n2',self.batch())
        periods=Periods(self.store);job=periods.begin(['test-uuid'])
        self.assertEqual(self.store.policy('n1')['allowed'],[])
        self.assertFalse(periods.complete(job))
        with self.assertRaises(Conflict):periods.ack('n1',job,2)
        periods.ack('n1',job,1);self.assertFalse(periods.complete(job))
        self.store.ingest('n2',self.batch(2,110,220))
        periods.ack('n2',job,2);self.assertTrue(periods.complete(job))
        with self.store.connection(write=True) as db:db.execute('UPDATE users SET used_traffic=0')
        periods.end(job)
        self.store.ingest('n2',self.batch(3,120,230))
        with self.store.connection() as db:self.assertEqual(db.execute('SELECT used_traffic FROM users').fetchone()[0],20)

    def test_node_cannot_ack_another_node_or_stale_snapshot(self):
        self.store.ingest('n1',self.batch())
        periods=Periods(self.store);job=periods.begin(['test-uuid'])
        with self.assertRaises(Conflict):periods.ack('n2',job,1)
        with self.assertRaises(Conflict):periods.ack('n1',job,0)

    def test_on_hold_authorized_without_starting_clock_until_payload(self):
        with self.store.connection(write=True) as db:db.execute("UPDATE users SET status='on_hold'")
        self.assertEqual(self.store.policy()['allowed'],['test-uuid'])
        with self.store.connection() as db:self.assertIsNone(db.execute('SELECT online_at FROM users').fetchone()[0])
        self.store.ingest('n1',self.batch())
        with self.store.connection() as db:self.assertIsNotNone(db.execute('SELECT online_at FROM users').fetchone()[0])
