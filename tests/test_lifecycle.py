import json
import unittest
from unittest.mock import Mock
import test_accounting
from test_accounting import connect
from hy2bridge.access import Access
from hy2bridge.operations import Operations
from hy2bridge.registry import Registry
from hy2bridge.observers import Observers
from hy2bridge.quotas import NodeQuotas
from hy2bridge.periods import Periods
from hy2bridge.lifecycle import Lifecycle,DeleteConflict


class LifecycleTests(unittest.TestCase):
    tearDown=test_accounting.AccountingTests.tearDown
    def setUp(self):
        test_accounting.AccountingTests.setUp(self)
        with connect(self.path) as db:
            db.executescript('''
            CREATE TABLE nodes(id INTEGER PRIMARY KEY,name TEXT,address TEXT,port INTEGER,api_port INTEGER,created_at TEXT,status TEXT,message TEXT,xray_version TEXT,last_status_change TEXT);
            INSERT INTO nodes VALUES(1,'raw-first','first.invalid',62050,62051,'2026-01-01','connected',NULL,'test',NULL),(2,'second','second.invalid',62050,62051,'2026-01-02','connected',NULL,'test',NULL);
            CREATE TABLE hosts(id INTEGER PRIMARY KEY,remark TEXT,address TEXT,port INTEGER);
            INSERT INTO hosts VALUES(1,'first','first.invalid',443),(2,'second','second.invalid',443);
            CREATE TABLE node_user_usages(node_id INTEGER REFERENCES nodes(id),user_id INTEGER,created_at TEXT,used_traffic INTEGER);
            CREATE TABLE node_usages(node_id INTEGER REFERENCES nodes(id),created_at TEXT,uplink INTEGER,downlink INTEGER);
            INSERT INTO users VALUES(2,'bob','active',55,1000,NULL,1,NULL,'2026-01-02');
            INSERT INTO proxies VALUES(2,'VLESS','{"id":"other-uuid"}');
            ''')
        self.ops=Operations(self.store);self.access=Access(self.store);self.registry=Registry(self.store);self.quotas=NodeQuotas(self.store);self.periods=Periods(self.store)
        self.entries=[{'node':'xray:1','kind':'native','token':'a'*40,'name':'first','address':'first.invalid','domain':'first.invalid','port':443},
                      {'node':'xray:2','kind':'native','token':'b'*40,'name':'second','address':'second.invalid','domain':'second.invalid','port':443}]
        self.observers=Observers(self.store,self.entries)
        self.access.save(1,['keep'],['xray:1','xray:2']);self.access.save(2,['also-keep'],['xray:1'])
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_managed(id,protocol,name,domain,port,native_id,host_id,active) VALUES(?,'vless','Friendly first','first.invalid',443,1,1,1)",('a'*32,))
            db.execute('CREATE TABLE fleet_jobs(id TEXT PRIMARY KEY,state TEXT,message TEXT,steps TEXT,created_at REAL)')
            db.execute("INSERT INTO fleet_jobs VALUES(?,'succeeded','done','[]',1)",('a'*32,))
            db.execute('CREATE TABLE fleet_health_history(node TEXT,minute INTEGER,state TEXT,metrics TEXT,PRIMARY KEY(node,minute))')
            db.execute('CREATE TABLE fleet_event_actions(event_key TEXT PRIMARY KEY,acknowledged INTEGER,note TEXT,actor TEXT,updated_at REAL)')
            for node,nid in [('xray:1',1),('xray:2',2)]:
                db.execute('INSERT INTO fleet_health VALUES(?,?,?)',(node,1,'{}'))
                db.execute('INSERT INTO fleet_health_history VALUES(?,?,?,?)',(node,1,'healthy','{}'))
                event=db.execute("INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,'native_unavailable','error',1,1)",(node,)).lastrowid
                db.execute("INSERT INTO fleet_event_actions VALUES(?,1,'keep only if other node','admin',1)",(str(event),))
                db.execute('INSERT INTO node_user_usages VALUES(?,?,?,?)',(nid,1,'2026-01-01 00:00:00',100))
                db.execute('INSERT INTO node_usages VALUES(?,?,?,?)',(nid,'2026-01-01 00:00:00',10,20))
        self.life=Lifecycle(self.store);self.life.disconnect=Mock();self.life.invalidate=Mock()

    def protected(self):
        with self.store.connection() as db:return [tuple(r) for r in db.execute('SELECT * FROM users')],[tuple(r) for r in db.execute('SELECT * FROM proxies')]

    def test_delete_cleans_only_target_and_is_idempotent_without_access_escalation(self):
        before=self.protected();plan=self.life.plan('xray:1');self.assertEqual(plan['name'],'Friendly first')
        result=self.life.delete('xray:1',plan['name'],plan['confirmation'],True)
        self.assertEqual(result['users_deleted'],0);self.assertEqual(self.protected(),before)
        self.assertEqual(self.access.metadata(1),{'tags':['keep'],'nodes':['xray:2']})
        self.assertEqual(self.access.metadata(2),{'tags':['also-keep'],'nodes':[]})
        with self.store.connection() as db:
            for table,column in [('fleet_health','node'),('fleet_health_history','node'),('fleet_events','node'),('fleet_xray_hourly','node'),('fleet_node_traffic','node'),('fleet_observers','node')]:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM '+table+' WHERE '+column+'=?',('xray:1',)).fetchone()[0],0)
                self.assertGreater(db.execute('SELECT COUNT(*) FROM '+table+' WHERE '+column+'=?',('xray:2',)).fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hosts WHERE id=1').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hosts WHERE id=2').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM fleet_jobs').fetchone()[0],0)
        self.life.disconnect.assert_called_once_with(1)
        self.assertTrue(self.life.delete('xray:1',plan['name'],plan['confirmation'],True)['already_absent'])

    def test_wrong_confirmation_never_disconnects_or_changes_data(self):
        plan=self.life.plan('xray:1');before=self.protected()
        for name,revision,ack in [('wrong',plan['confirmation'],True),(plan['name'],'0'*64,True),(plan['name'],plan['confirmation'],False)]:
            with self.assertRaises(DeleteConflict):self.life.delete('xray:1',name,revision,ack)
        self.life.disconnect.assert_not_called();self.assertEqual(self.protected(),before)
        with self.assertRaises(DeleteConflict):self.life.plan('xray:local')

    def test_reused_node_id_requires_new_preview(self):
        plan=self.life.plan('xray:1');self.life.delete('xray:1',plan['name'],plan['confirmation'],True)
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO nodes VALUES(1,'new server','new.invalid',62050,62051,'2026-02-01','connected',NULL,'test',NULL)")
            db.execute("INSERT INTO hosts VALUES(3,'new','new.invalid',443)");db.execute("INSERT INTO fleet_host_nodes VALUES(3,'xray:1')")
        with self.assertRaises(DeleteConflict):self.life.delete('xray:1',plan['name'],plan['confirmation'],True)
        self.assertIsNotNone(self.life.plan('xray:1'))

    def test_legacy_endpoint_and_ledger_removed_without_removing_shared_user(self):
        entry={'node':'legacy','kind':'legacy_hy2','token':'c'*40,'name':'Legacy','address':'legacy.invalid','domain':'legacy.invalid','port':443}
        Observers(self.store,self.entries+[entry])
        with self.store.connection(write=True) as db:db.execute("INSERT INTO fleet_external_links VALUES('legacy','hysteria2://','@legacy.invalid:443/#legacy',0)")
        self.store.ingest('legacy',test_accounting.AccountingTests.batch(self));self.store.ingest('other-node',test_accounting.AccountingTests.batch(self))
        before=self.protected();self.assertEqual(len(self.registry.links('test-uuid')),1)
        plan=self.life.plan('legacy');self.life.delete('legacy',plan['name'],plan['confirmation'],True)
        self.assertEqual(self.registry.links('test-uuid'),[]);self.assertEqual(self.protected(),before)
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM hy2_totals WHERE node='legacy'").fetchone()[0],0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM hy2_totals WHERE node='other-node'").fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hy2_identities').fetchone()[0],2)
