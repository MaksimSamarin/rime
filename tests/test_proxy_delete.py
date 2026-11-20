import contextlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import types
import unittest

from hy2bridge.proxy_delete import ProxyDeletion
from hy2bridge.provision import ProvisionError
from hy2bridge.store import Store


class ProxyDeletionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        path = Path(self.temporary.name) / 'database.sqlite3'
        with sqlite3.connect(path) as database:
            database.execute('''CREATE TABLE fleet_proxy_services(id TEXT PRIMARY KEY,node TEXT,active INTEGER,
                runtime_id TEXT,legacy_squid INTEGER,http_port INTEGER,https_port INTEGER,username TEXT,password_secret TEXT)''')
            database.executemany('INSERT INTO fleet_proxy_services VALUES(?,?,?,?,?,?,?,?,?)', [
                ('a'*32,'node',1,'',0,3128,8443,'fixture','encrypted-fixture'),
                ('b'*32,'node',1,'',0,3129,None,'peer','encrypted-peer')])
            database.execute('CREATE TABLE recovery(value TEXT)')
            database.execute('INSERT INTO recovery VALUES(?)',(json.dumps({'version':1,'proxies':{
                'a'*32:{'known_password':'synthetic-existing-password','files':{'passwd':'fixture:synthetic-hash'}},
                'b'*32:{'known_password':'synthetic-peer-password'}}}),))
        self.store = Store(path)
        self.running = True
        self.removed = False
        self.fail_commit = False
        self.fail_finalize = False
        self.actions = []
        self.jobs = {}
        provision = types.SimpleNamespace(lock=threading.Lock(),running=set(),target=lambda *_:None,
            resolve=lambda *_:['192.0.2.1'],connect=lambda _:contextlib.nullcontext(object()))
        recovery = types.SimpleNamespace(load=self.load_profile,save=self.save_profile)
        self.proxy = types.SimpleNamespace(store=self.store,provision=provision,recovery=recovery,
            node_identity=lambda *_:('192.0.2.1','generation'),require_stable_node=lambda _:None,
            current_generation=lambda *_:'generation',remote=self.remote,update=self.update)
        self.deletion = ProxyDeletion(self.proxy)

    def load_profile(self,node,database=None):
        if database is None:
            with self.store.connection() as connection:return self.load_profile(node,connection)
        return json.loads(database.execute('SELECT value FROM recovery').fetchone()[0])

    def save_profile(self,node,value,database):
        database.execute('UPDATE recovery SET value=?',(json.dumps(value),))

    def update(self,job,node,state,message,context=None):
        self.jobs[job]={'state':state,'message':message}

    def remote(self,client,config):
        action=config['action'];self.actions.append(action)
        if action=='managed-snapshot':return {'fingerprint':'fixture-guard','files':{'passwd':'fixture:synthetic-hash'}}
        if action=='managed-stop':self.running=False;return {'stopped':True}
        if action=='managed-delete-commit':
            if self.fail_commit:raise ProvisionError('Synthetic commit failure')
            return {'committed':True}
        if action=='managed-delete-resume':
            self.running=False
            return {'committed':True}
        if action=='managed-restore':self.running=True;return {'restored':True}
        if action=='managed-delete-finalize':
            if self.fail_finalize:raise ProvisionError('Synthetic cleanup failure')
            self.removed=True;return {'removed':True}
        raise AssertionError('Unexpected remote action')

    def access(self):
        return {'host':'192.0.2.1','address':'192.0.2.1','ssh_port':22,'username':'root',
                'password':'synthetic-ssh-password','fingerprint':'SHA256:'+'a'*43}

    def execute(self):
        access=self.access()
        plan=self.deletion.plan('a'*32,access)
        self.deletion.deploy(plan['id'])
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if self.jobs.get(plan['id'],{}).get('state') in ['succeeded','failed','rolled_back'] and not access:
                return self.jobs[plan['id']]
            time.sleep(.01)
        self.fail('Deletion did not finish')

    def test_one_proxy_is_removed_and_the_other_proxy_keeps_its_access(self):
        result=self.execute()
        self.assertEqual(result['state'],'succeeded')
        self.assertTrue(self.removed)
        with self.store.connection() as database:
            values=dict(database.execute('SELECT id,active FROM fleet_proxy_services'))
        self.assertEqual(values,{'a'*32:0,'b'*32:1})
        profile=self.load_profile('node')
        self.assertNotIn('a'*32,profile['proxies'])
        self.assertEqual(profile['proxies']['b'*32]['known_password'],'synthetic-peer-password')

    def test_failed_commit_restores_runtime_and_recoverable_plaintext_credential(self):
        self.fail_commit=True
        result=self.execute()
        self.assertEqual(result['state'],'rolled_back')
        self.assertTrue(self.running)
        profile=self.load_profile('node')
        self.assertEqual(profile['proxies']['a'*32]['known_password'],'synthetic-existing-password')
        with self.store.connection() as database:
            self.assertEqual(database.execute('SELECT active FROM fleet_proxy_services WHERE id=?',('a'*32,)).fetchone()[0],1)

    def test_cleanup_retry_is_idempotent_and_does_not_restart_the_deleted_proxy(self):
        self.fail_finalize=True
        self.assertEqual(self.execute()['state'],'failed')
        self.assertFalse(self.running)
        self.fail_finalize=False
        self.assertEqual(self.execute()['state'],'succeeded')
        self.assertEqual(self.actions.count('managed-stop'),1)
        self.assertNotIn('managed-restore',self.actions)
