from datetime import datetime,timedelta,timezone
import unittest
import test_accounting
from test_accounting import connect
from hy2bridge import access
from hy2bridge.operations import Operations
from hy2bridge.registry import Registry


class AccessTests(unittest.TestCase):
    def setUp(self):
        test_accounting.AccountingTests.setUp(self)
        self.access=access.Access(self.store);access.current=self.access
        self.ops=Operations(self.store);self.registry=Registry(self.store)

    def tearDown(self):
        access.current=None
        test_accounting.AccountingTests.tearDown(self)

    def test_existing_users_keep_all_nodes_and_hy2_policy(self):
        self.assertTrue(self.access.allows(1,'new-node'))
        self.assertEqual(self.store.policy('new-node')['allowed'],['test-uuid'])

    def test_selected_policy_filters_both_protocols_and_copies_config(self):
        self.access.save(1,['team'],['n1','xray:2'])
        self.assertEqual(self.store.policy('n1')['allowed'],['test-uuid'])
        self.assertEqual(self.store.policy('n2')['allowed'],[])
        config={'inbounds':[{'settings':{'clients':[{'email':'1.alice'}]}}]}
        self.assertEqual(self.access.filtered_config(config,'xray:local')['inbounds'][0]['settings']['clients'],[])
        self.assertEqual(len(self.access.filtered_config(config,'xray:2')['inbounds'][0]['settings']['clients']),1)
        self.assertEqual(len(config['inbounds'][0]['settings']['clients']),1)
        self.access.save(1,[],None)
        self.assertTrue(self.access.allows(1,'xray:local'))

    def test_reused_user_id_does_not_inherit_tags_or_restrictions(self):
        self.access.save(1,['private'],['n1'])
        with connect(self.path) as db:db.execute("UPDATE users SET created_at='2026-02-01',username='bob' WHERE id=1")
        self.assertEqual(self.access.metadata(1),{'tags':[],'nodes':None})

    def test_hy2_links_and_native_host_filter_are_fail_closed(self):
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_managed(id,protocol,name,domain,port,active) VALUES('n1','hysteria2','One','one.invalid',443,1)")
            db.execute("INSERT INTO fleet_managed(id,protocol,name,domain,port,active) VALUES('n2','hysteria2','Two','two.invalid',443,1)")
            db.execute("INSERT INTO fleet_host_nodes VALUES(12,'xray:2')")
        self.assertEqual(len(self.registry.links('test-uuid')),2)
        self.access.save(1,[],['n1','xray:2'])
        self.assertEqual(len(self.registry.links('test-uuid')),1)
        self.assertIn('one.invalid',self.registry.links('test-uuid')[0])
        self.assertTrue(self.access.host_allowed('alice',12))
        self.assertFalse(self.access.host_allowed('alice',13))

    def test_tag_report_totals_and_unmatched_tag(self):
        self.access.save(1,['team'],None)
        self.store.ingest('n1',test_accounting.AccountingTests.batch(self))
        now=datetime.now(timezone.utc)
        self.assertEqual(self.ops.traffic(now-timedelta(days=1),now,tag='team')['total'],300)
        self.assertEqual(self.ops.traffic(now-timedelta(days=1),now,tag='other')['total'],0)

    def test_old_identity_traffic_does_not_match_new_tag(self):
        self.store.ingest('n1',test_accounting.AccountingTests.batch(self))
        with connect(self.path) as db:
            db.execute("UPDATE users SET created_at='2026-02-01',username='bob' WHERE id=1")
            db.execute('UPDATE proxies SET settings=?',('{"id":"new-uuid"}',))
        self.access.save(1,['new-team'],None)
        now=datetime.now(timezone.utc)
        self.assertEqual(self.ops.traffic(now-timedelta(days=1),now,tag='new-team')['total'],0)

    def test_outage_comment_survives_recovery(self):
        import time
        with self.store.connection(write=True) as db:
            db.execute('CREATE TABLE fleet_event_actions(event_key TEXT PRIMARY KEY,acknowledged INTEGER,note TEXT,actor TEXT,updated_at REAL)')
        self.ops.ensure_node('n1');self.ops.heartbeat('n1',{'error':None})
        before=time.time()-120
        with self.store.connection(write=True) as db:
            db.execute('UPDATE fleet_health SET seen_at=?',(before,))
            db.execute('INSERT INTO fleet_event_actions VALUES(?,?,?,?,?)',('offline:n1:'+str(before),1,'Investigating','admin',time.time()))
        self.ops.heartbeat('n1',{'error':None})
        recovered=next(e for e in self.ops.events() if e['code']=='heartbeat_stale')
        self.assertIsNotNone(recovered['resolved_at'])
        self.assertEqual(recovered['action']['note'],'Investigating')

    def test_unique_legacy_host_mapping_and_ambiguous_host(self):
        with self.store.connection(write=True) as db:
            db.execute('CREATE TABLE hosts(id INTEGER,address TEXT)')
            db.execute('CREATE TABLE nodes(id INTEGER,address TEXT)')
            db.executemany('INSERT INTO nodes VALUES(?,?)',[(2,'one.invalid'),(3,'shared.invalid'),(4,'shared.invalid')])
            db.executemany('INSERT INTO hosts VALUES(?,?)',[(1,'{SERVER_IP}'),(2,'one.invalid'),(3,'shared.invalid')])
        access.Access(self.store)
        self.access.save(1,[],['xray:2'])
        self.assertTrue(self.access.host_allowed('alice',2))
        self.assertFalse(self.access.host_allowed('alice',1))
        self.assertFalse(self.access.host_allowed('alice',3))
