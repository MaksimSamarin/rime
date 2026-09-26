import concurrent.futures
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager

from hy2bridge.spool import Spool
from hy2bridge.store import Store, Conflict


@contextmanager
def connect(path,timeout=10):
    db=sqlite3.connect(path,timeout=timeout)
    try:
        with db:
            yield db
    finally:
        db.close()


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'panel.db'
        with connect(self.path) as db:
            db.executescript('''
            CREATE TABLE admins(id INTEGER PRIMARY KEY,users_usage INTEGER);
            CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT,status TEXT,used_traffic INTEGER,
                data_limit INTEGER,expire INTEGER,admin_id INTEGER,online_at TEXT,created_at TEXT);
            CREATE TABLE proxies(user_id INTEGER,type TEXT,settings TEXT);
            INSERT INTO admins VALUES(1,0);
            INSERT INTO users VALUES(1,'alice','active',0,1000,NULL,1,NULL,'2026-01-01 00:00:00');
            INSERT INTO proxies VALUES(1,'VLESS','{"id":"test-uuid"}');
            ''')
        self.store=Store(self.path);self.store.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def batch(self,seq=1,tx=100,rx=200):
        return {'spool':'synthetic-spool-001','seq':seq,'totals':{'test-uuid':{'tx':tx,'rx':rx}}}

    def usage(self):
        with connect(self.path) as db:
            return db.execute('SELECT used_traffic FROM users').fetchone()[0]

    def test_retry_after_lost_ack_is_idempotent(self):
        self.store.ingest('n1',self.batch())
        self.assertTrue(self.store.ingest('n1',self.batch())['duplicate'])
        self.assertEqual(self.usage(),300)

    def test_changed_retry_rejected(self):
        self.store.ingest('n1',self.batch())
        with self.assertRaises(Conflict):self.store.ingest('n1',self.batch(tx=101))
        self.assertEqual(self.usage(),300)

    def test_multiple_nodes_sum(self):
        self.store.ingest('n1',self.batch());self.store.ingest('n2',self.batch())
        self.assertEqual(self.usage(),600)

    def test_parallel_native_and_hy2_no_lost_increment(self):
        def native():
            for _ in range(20):
                with connect(self.path,timeout=10) as db:
                    db.execute('UPDATE users SET used_traffic=used_traffic+7 WHERE id=1')
        def hy2():
            for i in range(1,21):self.store.ingest('n1',self.batch(i,i*3,i*5))
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            for future in [pool.submit(native),pool.submit(hy2)]:future.result()
        self.assertEqual(self.usage(),300)

    def test_failure_mid_batch_rolls_back_usage_and_cursor(self):
        batch=self.batch();batch['totals']['unknown']={'tx':1,'rx':1}
        with self.assertRaises(Conflict):self.store.ingest('n1',batch)
        self.assertEqual(self.usage(),0)
        self.assertEqual(self.store.report()['nodes'],[])

    def test_counter_decrease_rejected(self):
        self.store.ingest('n1',self.batch())
        with self.assertRaises(Conflict):self.store.ingest('n1',self.batch(2,99,200))
        self.assertEqual(self.usage(),300)

    def test_spool_replacement_rejected(self):
        self.store.ingest('n1',self.batch())
        b=self.batch(2);b['spool']='other-spool-00001'
        with self.assertRaises(Conflict):self.store.ingest('n1',b)

    def test_stale_sequence_rejected(self):
        self.store.ingest('n1',self.batch(2))
        with self.assertRaises(Conflict):self.store.ingest('n1',self.batch(1))

    def test_reset_does_not_rebill_previous_snapshot(self):
        self.store.ingest('n1',self.batch())
        with connect(self.path) as db:db.execute('UPDATE users SET used_traffic=0')
        self.store.ingest('n1',self.batch(2,110,210))
        self.assertEqual(self.usage(),20)

    def test_policy_checks_limit_expiry_and_status(self):
        self.assertEqual(self.store.policy()['allowed'],['test-uuid'])
        for condition in ['used_traffic=1000','expire=1',"status='disabled'"]:
            with connect(self.path) as db:
                db.execute("UPDATE users SET used_traffic=0,expire=NULL,status='active'")
                db.execute('UPDATE users SET '+condition)
            self.assertEqual(self.store.policy()['allowed'],[])

    def test_spool_restart_and_new_server_epoch(self):
        path=Path(self.tmp.name)/'spool.db'
        s=Spool(path)
        first=s.observe('process-1',{'test-uuid':{'tx':100,'rx':200}})
        s=Spool(path)
        again=s.observe('process-1',{'test-uuid':{'tx':100,'rx':200}})
        self.assertEqual(first['spool'],again['spool'])
        self.assertEqual(first['totals'],again['totals'])
        new=s.observe('process-2',{'test-uuid':{'tx':10,'rx':20}})
        self.assertEqual(new['totals']['test-uuid'],{'tx':110,'rx':220})

    def test_raw_counter_reset_requires_epoch_change(self):
        s=Spool(Path(self.tmp.name)/'spool.db')
        s.observe('p1',{'test-uuid':{'tx':100,'rx':200}})
        with self.assertRaises(ValueError):s.observe('p1',{'test-uuid':{'tx':1,'rx':2}})
        self.assertEqual(s.observe('p1',{})['totals']['test-uuid'],{'tx':100,'rx':200})

    def test_deleted_user_tail_is_retained_without_charging_reused_id(self):
        self.store.policy()
        with connect(self.path) as db:
            db.execute('DELETE FROM proxies');db.execute('DELETE FROM users')
            db.execute("INSERT INTO users VALUES(1,'bob','active',0,0,NULL,1,NULL,'2026-02-01 00:00:00')")
        self.store.ingest('n1',self.batch())
        self.assertEqual(self.usage(),0)
        self.assertEqual(self.store.report()['usage'][0]['username'],'alice')

    def test_uuid_reassignment_is_rejected(self):
        self.store.policy()
        with connect(self.path) as db:db.execute("UPDATE users SET created_at='2026-02-01 00:00:00'")
        with self.assertRaises(Conflict):self.store.policy()

    def test_current_owner_receives_new_usage_after_transfer(self):
        self.store.policy()
        with connect(self.path) as db:
            db.execute('INSERT INTO admins VALUES(2,0)')
            db.execute('UPDATE users SET admin_id=2')
        self.store.ingest('n1',self.batch())
        with connect(self.path) as db:
            self.assertEqual(db.execute('SELECT users_usage FROM admins ORDER BY id').fetchall(),[(0,),(300,)])


if __name__=='__main__':unittest.main()
