from datetime import datetime,timedelta,timezone
from contextlib import closing
import sqlite3
import time
import unittest
import test_accounting
from test_accounting import connect
from hy2bridge.operations import Operations


class OperationsTests(unittest.TestCase):
    setUp=test_accounting.AccountingTests.setUp
    tearDown=test_accounting.AccountingTests.tearDown
    batch=test_accounting.AccountingTests.batch

    def test_compact_traffic_preserves_totals_and_groupings_without_raw_rows(self):
        self.store.ingest('n1',self.batch())
        self.store.ingest('n2',self.batch(tx=40,rx=60))
        ops=Operations(self.store);now=datetime.now(timezone.utc)
        full=ops.traffic(now-timedelta(days=1),now+timedelta(hours=1))
        compact=ops.traffic(now-timedelta(days=1),now+timedelta(hours=1),detail=False)
        self.assertTrue(full['rows']);self.assertEqual(compact['rows'],[])
        self.assertEqual(compact['row_count'],len(full['rows']))
        for key in ['total','totals','series','users','nodes','hy2_upload_bytes','hy2_download_bytes']:
            self.assertEqual(compact[key],full[key])
        self.assertEqual(sum(r['total'] for r in compact['nodes']),compact['total'])

    def test_retention_keeps_open_incidents_and_accounting(self):
        self.store.ingest('n1',self.batch());ops=Operations(self.store)
        with connect(self.path) as db:
            db.executemany('INSERT INTO fleet_events(node,code,severity,first_at,last_at,resolved_at) VALUES(?,?,?,?,?,?)',
                [('n1','stats_unavailable','error',1,1,None),('n1','heartbeat_stale','error',1,1,2),('n1','heartbeat_stale','error',4000000,4000000,4000001)])
        ops.prune(now=4000002)
        with connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM fleet_events').fetchone()[0],2)
            self.assertEqual(db.execute('SELECT used_traffic FROM users').fetchone()[0],300)

    def test_repeated_stale_gaps_coalesce_instead_of_growing_rows(self):
        ops=Operations(self.store);ops.ensure_node('n1');ops.heartbeat('n1',{})
        for _ in range(5):
            with connect(self.path) as db:db.execute('UPDATE fleet_health SET seen_at=?',(time.time()-60,))
            ops.heartbeat('n1',{})
        with connect(self.path) as db:
            row=db.execute("SELECT COUNT(*),SUM(occurrences) FROM fleet_events WHERE code='heartbeat_stale'").fetchone()
            self.assertEqual(row,(1,5))

    def test_native_probe_does_not_hold_database_read_lock(self):
        with connect(self.path) as db:
            db.execute('CREATE TABLE nodes(id INTEGER,name TEXT,address TEXT,status TEXT,message TEXT,xray_version TEXT,last_status_change TEXT)')
            db.executemany('INSERT INTO nodes VALUES(?,?,?, ?,NULL,?,NULL)',
                [(1,'first','first.invalid','connected','test'),(2,'second','second.invalid','connected','test')])
        ops=Operations(self.store)
        def probe(node_id):
            # A slow remote check must not keep a read cursor open while the
            # independent accounting connection tries to commit its counters.
            with closing(sqlite3.connect(self.path,timeout=.05)) as db, db:
                db.execute('UPDATE users SET used_traffic=used_traffic+1')
            return True
        ops.native_probe=probe
        self.assertEqual([n['state'] for n in ops.nodes()],['healthy','healthy'])
        with connect(self.path) as db:
            self.assertEqual(db.execute('SELECT used_traffic FROM users').fetchone()[0],2)

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

    def test_real_traffic_check_opens_and_resolves_incident(self):
        ops=Operations(self.store);ops.ensure_node('n1');ops.heartbeat('n1',{'error':None})
        check=ops.request_check('n1');claimed=ops.claim_check('n1')
        self.assertEqual(claimed['id'],check['id'])
        ops.heartbeat('n1',{'error':None,'check':{'id':check['id'],'passed':False,'stage':'payload','error':'refused'}})
        self.assertEqual(ops.checks('n1')[0]['state'],'failed')
        self.assertEqual(ops.nodes()[0]['state'],'degraded')
        self.assertEqual(ops.events()[0]['code'],'traffic_failed')
        retry=ops.request_check('n1');ops.claim_check('n1')
        ops.heartbeat('n1',{'error':None,'check':{'id':retry['id'],'passed':True,'stage':'payload','bytes':1024,'latency_ms':4.2}})
        self.assertEqual(ops.checks('n1')[0]['state'],'passed')
        self.assertEqual(ops.nodes()[0]['state'],'healthy')
        self.assertIsNotNone(next(e for e in ops.events() if e['code']=='traffic_failed')['resolved_at'])
