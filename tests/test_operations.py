from datetime import datetime,timedelta,timezone
import time
import unittest
import test_accounting
from test_accounting import connect
from hy2bridge.operations import Operations


class OperationsTests(unittest.TestCase):
    setUp=test_accounting.AccountingTests.setUp
    tearDown=test_accounting.AccountingTests.tearDown
    batch=test_accounting.AccountingTests.batch

    def test_native_history_survives_reset_delete_and_restart(self):
        with connect(self.path) as db:
            db.execute('CREATE TABLE node_user_usages(node_id INTEGER,user_id INTEGER,created_at TEXT,used_traffic INTEGER)')
            db.execute("INSERT INTO node_user_usages VALUES(NULL,1,'2026-09-26 12:00:00',100)")
        Operations(self.store)
        with connect(self.path) as db:
            db.execute('UPDATE node_user_usages SET used_traffic=150')
            db.execute('DELETE FROM node_user_usages')
            db.execute("INSERT INTO node_user_usages VALUES(NULL,1,'2026-09-26 12:00:00',0)")
            db.execute('UPDATE node_user_usages SET used_traffic=30')
        Operations(self.store)
        with connect(self.path) as db:
            self.assertEqual(db.execute('SELECT total FROM fleet_xray_hourly').fetchone()[0],180)
            db.execute('DELETE FROM users')
            self.assertEqual(db.execute('SELECT username FROM fleet_xray_hourly').fetchone()[0],'alice')
    def test_real_reports_and_filters(self):
        self.store.ingest('n1',self.batch())
        ops=Operations(self.store)
        now=datetime.now(timezone.utc)
        report=ops.traffic(now-timedelta(days=1),now+timedelta(hours=1))
        self.assertEqual(report['total'],300)
        self.assertEqual(report['rows'][0]['username'],'alice')
        self.assertEqual(ops.traffic(now-timedelta(days=1),now,node='other')['total'],0)
        with self.assertRaises(ValueError):ops.traffic(now,now-timedelta(hours=1))

    def test_health_staleness_and_error_recovery(self):
        ops=Operations(self.store);ops.ensure_node('n1')
        self.assertEqual(ops.nodes()[0]['state'],'unknown')
        ops.heartbeat('n1',{'error':'accounting_failed'})
        ops.heartbeat('n1',{'error':'accounting_failed'})
        self.assertEqual(ops.events()[0]['occurrences'],2)
        self.assertEqual(ops.nodes()[0]['state'],'degraded')
        ops.heartbeat('n1',{'error':None})
        self.assertIsNotNone(ops.events()[0]['resolved_at'])
        with connect(self.path) as db:db.execute('UPDATE fleet_health SET seen_at=?',(time.time()-60,))
        self.assertEqual(ops.nodes()[0]['state'],'offline')
        self.assertTrue(ops.events()[0]['derived'])
        ops.heartbeat('n1',{'error':None})
        outages=[e for e in ops.events() if e['code']=='heartbeat_stale']
        self.assertEqual(len(outages),1)
        self.assertIsNotNone(outages[0]['resolved_at'])
