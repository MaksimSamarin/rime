"""Entry replacement keeps publication and accounting consistent across failure."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hy2bridge.provision import ProvisionError
from hy2bridge.proxy_secrets import ProxySecrets
from hy2bridge.relay_control import RelayPortConflict, credentials
from hy2bridge.relays import Relays
from hy2bridge.store import Store


class Control:
    def __init__(self):
        self.values = {}
        self.offline = False
        self.timeout = 12

    def services(self):
        if self.offline:
            raise ProvisionError('Synthetic unavailable entry')
        return list(self.values.values())

    def add(self, value):
        self.services()
        if any(item['addr'] == value['addr'] and item['listener']['type'] == value['listener']['type'] for item in self.values.values()):
            raise RelayPortConflict('Synthetic occupied port')
        self.values[value['name']] = deepcopy(value)

    def remove(self, name):
        self.services()
        self.values.pop(name, None)

    def save(self):
        self.services()


class RelaySwitchTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        sqlite3.connect(self.root / 'panel.db').close()
        self.store = Store(self.root / 'panel.db')
        with self.store.connection(write=True) as database:
            database.execute('CREATE TABLE fleet_host_nodes(host_id INTEGER,node TEXT)')
            database.execute("INSERT INTO fleet_host_nodes VALUES(1,'node-a')")
            database.execute('CREATE TABLE users(id INTEGER,used_traffic INTEGER)')
            database.execute('INSERT INTO users VALUES(1,12345)')
            database.execute('CREATE TABLE fleet_proxy_services(id TEXT PRIMARY KEY,node TEXT,active INTEGER,http_port INTEGER,https_port INTEGER)')
        self.source = {'node':'node-a','name':'Node A','protocol':'hysteria2',
                       'identity':{'created_at':'stable-generation','address':'192.0.2.20'},'native':None}
        self.profile = {'vpn':{'protocol':'hysteria2'},'proxies':{}}
        provision = SimpleNamespace(store=self.store, settings={'relay_switch_grace_seconds':0}, lock=threading.Lock(), resolve=self.resolve)
        transfer = SimpleNamespace(digest=lambda value:json.dumps(value,sort_keys=True), snapshot=lambda *_:self.source)
        proxies = SimpleNamespace(secrets=ProxySecrets(self.root/'private.key'), clear_password=lambda _: 'synthetic-proxy-password')
        self.relays = Relays(provision, transfer, proxies)
        self.relays.reconnect = lambda _:None
        self.relays.source = lambda _:(deepcopy(self.source),deepcopy(self.profile))
        self.relays.verify_route = lambda *_:{'passed':True,'vpn_passed':True,'proxies_passed':True}
        self.controls = {key:Control() for key in ['a'*32,'c'*32,'d'*32]}
        self.relays.control = lambda entry:self.controls[entry['id']]
        with self.store.connection(write=True) as database:
            for index,identity in enumerate(self.controls,1):
                database.execute('''INSERT INTO fleet_relay_entries(id,name,host,address,domain,control_port,metrics_port,
                    api_port,credential,ssh_port,username,fingerprint,state,created_at,seen_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (identity,'Entry '+str(index),str(index)+'.entry.example','192.0.2.'+str(index),str(index)+'.entry.example',
                     62080,62081,62082,'private-credential',22,'root','SHA256:fixture','active',time.time(),time.time()))
        self.route_id = 'b'*32
        old = self.relays.entry('a'*32)
        self.relays.install_route(self.route_id, {'entry':old,'source':self.source,'origin':'192.0.2.20',
            'services':[{'kind':'vpn','proxy':None,'protocol':'udp','origin_port':443,'public_port':10443}]})
        self.leases = patch.dict(sys.modules, {'update_runtime.leases':SimpleNamespace(acquire=lambda *_:os.open(os.devnull, os.O_RDONLY))})
        self.leases.start()
        self.addCleanup(self.leases.stop)

    def plan(self, entry='c'*32):
        return self.relays.switches.plan(self.route_id, entry)

    def resolve(self, host, port):
        with self.store.connection() as database:
            row = database.execute('SELECT address FROM fleet_relay_entries WHERE domain=?',(host,)).fetchone()
        return [row['address']] if row else []

    def execute(self, plan):
        self.relays.deploy(plan['id'])
        deadline = time.monotonic()+4
        while time.monotonic()<deadline:
            job = self.relays.job(plan['id'])
            if job['state'] != 'running':
                return job
            time.sleep(.01)
        self.fail('Switch worker did not complete')

    def mapping(self):
        return next(iter(self.relays.endpoint_map('node-a').values()))

    def due(self):
        with self.store.connection(write=True) as database:
            database.execute('UPDATE fleet_relay_switches SET retry_at=0')

    def packet(self, identity, seq, rx, tx, spool='sender-spool-00001'):
        return {'spool':spool,'seq':seq,'epoch':'entry-epoch-01','observed_at':time.time(),
                'totals':{identity:{'rx':rx,'tx':tx,'epoch':'service-epoch-01'}}}

    def test_healthy_switch_publishes_after_probe_and_keeps_identity(self):
        previous = self.mapping()
        old_link = self.relays.published_link('node-a','hysteria2://same-key@exit.example:443?sni=exit.example')
        seen = []
        def verify(source, profile, entry, origin, services):
            seen.append(self.mapping()['entry'])
            self.assertEqual(origin,'192.0.2.20')
            return {'passed':True,'vpn_passed':True}
        self.relays.verify_route = verify
        plan = self.plan()
        job = self.execute(plan)
        self.assertEqual(job['state'],'succeeded')
        self.assertEqual(seen,['a'*32])
        self.assertEqual(self.mapping()['tunnel'],self.route_id)
        self.assertEqual(self.mapping()['entry'],'c'*32)
        self.assertEqual(self.mapping()['public_port'],previous['public_port'])
        self.assertNotEqual(self.mapping()['id'],previous['id'])
        self.assertIn('same-key@',self.relays.published_link('node-a','hysteria2://same-key@exit.example:443?sni=exit.example'))
        self.assertNotEqual(old_link,self.relays.published_link('node-a','hysteria2://same-key@exit.example:443?sni=exit.example'))
        self.assertFalse(self.controls['a'*32].values)
        self.assertEqual(job['context']['progress']['completed'],7)
        self.assertFalse(self.relays.busy)

    def test_dead_old_entry_does_not_block_switch_or_second_switch(self):
        self.controls['a'*32].offline = True
        first = self.execute(self.plan())
        self.assertEqual(first['state'],'succeeded')
        self.assertTrue(first['context']['old_cleanup_pending'])
        self.assertEqual(self.mapping()['entry'],'c'*32)
        second_plan = self.plan('d'*32)
        second = self.execute(second_plan)
        self.assertEqual(second['state'],'succeeded')
        self.assertEqual(self.mapping()['entry'],'d'*32)
        self.assertEqual(self.relays.switches.pending_entry('a'*32),1)
        self.assertEqual(self.relays.switches.pending_entry('c'*32),0)
        self.controls['a'*32].offline = False
        self.due()
        self.relays.switches.recover()
        self.assertFalse(self.controls['a'*32].values)
        self.assertFalse(self.relays.catalog()['tunnels'][0]['old_cleanup_pending'])
        self.assertEqual(self.relays.catalog()['tunnels'][0]['switch']['id'],second_plan['id'])

    def test_payload_failure_keeps_old_publication_and_removes_new_rules(self):
        before = self.mapping()
        self.relays.verify_route = lambda *_:{'passed':False}
        job = self.execute(self.plan())
        self.assertEqual(job['state'],'rolled_back')
        self.assertEqual(self.mapping(),before)
        self.assertFalse(self.controls['c'*32].values)

    def test_stale_plan_and_concurrent_proxy_change_are_rejected(self):
        plan = self.plan()
        self.source['name'] = 'Changed after planning'
        job = self.execute(plan)
        self.assertEqual(job['state'],'failed')
        self.assertEqual(self.mapping()['entry'],'a'*32)
        self.assertFalse(self.controls['c'*32].values)
        self.relays.busy.add('a'*32)
        with self.assertRaises(ProvisionError):
            self.plan()

    def test_old_late_telemetry_is_retained_and_counted_once(self):
        old = self.mapping()
        self.relays.accounting.ingest('a'*32,self.packet(old['id'],1,100,200))
        self.execute(self.plan())
        new = self.mapping()
        delayed = self.packet(old['id'],2,130,230)
        self.relays.accounting.ingest('a'*32,delayed)
        self.relays.accounting.ingest('a'*32,delayed)
        self.relays.accounting.ingest('c'*32,self.packet(new['id'],1,20,30))
        route = self.relays.catalog()['tunnels'][0]
        self.assertEqual(route['services'][0]['traffic'],{'rx':150,'tx':260})
        self.assertEqual(route['traffic'],{'rx':150,'tx':260})
        with self.store.connection() as database:
            self.assertEqual(database.execute('SELECT used_traffic FROM users').fetchone()[0],12345)

    def test_old_cleanup_never_removes_changed_rule_or_peer(self):
        old = self.mapping()
        config = json.loads(old['config'])
        self.controls['a'*32].values[config['name']]['addr'] = '0.0.0.0:33333'
        peer = {'name':'peer-route','addr':'0.0.0.0:34444','listener':{'type':'tcp'}}
        self.controls['a'*32].values[peer['name']] = peer
        job = self.execute(self.plan())
        self.assertTrue(job['context']['old_cleanup_pending'])
        self.assertEqual(self.controls['a'*32].values[config['name']]['addr'],'0.0.0.0:33333')
        self.assertIn('peer-route',self.controls['a'*32].values)

    def test_port_collision_after_plan_gets_verified_alternative(self):
        plan = self.plan()
        port = plan['services'][0]['public_port']
        self.controls['c'*32].values['new-peer'] = {'name':'new-peer','addr':'0.0.0.0:'+str(port),'listener':{'type':'udp'}}
        job = self.execute(plan)
        self.assertEqual(job['state'],'succeeded')
        self.assertNotEqual(self.mapping()['public_port'],port)
        self.assertIn('new-peer',self.controls['c'*32].values)

    def test_proxy_certificate_and_credentials_are_checked_during_plan(self):
        identity = 'e'*32
        certificate = credentials('*.entry.example','192.0.2.3')['certificate']
        self.profile['proxies'][identity] = {'files':{'cert.pem':certificate}}
        with self.store.connection(write=True) as database:
            database.execute('INSERT INTO fleet_proxy_services VALUES(?,?,1,?,?)',(identity,'node-a',3128,8443))
            key = 'f'*32
            database.execute('INSERT INTO fleet_tunnel_services VALUES(?,?,?,?,?,?,?,?,?,?)',
                (key,self.route_id,'a'*32,'proxy',identity,'tcp',8443,18443,json.dumps({'name':'rime-'+key,'addr':'0.0.0.0:18443','listener':{'type':'tcp'}}),'active'))
        plan = self.plan()
        proxy = next(item for item in plan['services'] if item['kind']=='proxy')
        self.assertEqual(proxy['mode'],'https')
        with self.store.connection(write=True) as database:
            database.execute("UPDATE fleet_relay_entries SET domain='outside.invalid' WHERE id=?",('c'*32,))
        with self.assertRaisesRegex(ProvisionError,'HTTPS'):
            self.plan()

    def test_recovery_before_publish_rolls_back_only_new_rules(self):
        plan = self.plan()
        original = self.relays.switches.publish
        def interrupted(*_):
            raise SystemExit('Synthetic process interruption')
        self.relays.switches.publish = interrupted
        record = self.relays.plans[plan['id']]
        with self.assertRaises(SystemExit):
            self.relays.switches.worker(plan['id'],record)
        self.relays.switches.publish = original
        self.relays.switches.recover()
        self.assertEqual(self.mapping()['entry'],'a'*32)
        self.assertFalse(self.controls['c'*32].values)
        self.assertEqual(self.relays.switches.read(plan['id'])['phase'],'rolled_back')

    def test_recovery_after_publish_keeps_new_route(self):
        plan = self.plan()
        original = self.relays.switches.cleanup
        self.relays.switches.cleanup = lambda *_: (_ for _ in ()).throw(SystemExit('Synthetic interruption'))
        with self.assertRaises(SystemExit):
            self.relays.switches.worker(plan['id'],self.relays.plans[plan['id']])
        self.relays.switches.cleanup = original
        self.relays.switches.recover()
        self.assertEqual(self.mapping()['entry'],'c'*32)
        self.assertFalse(self.controls['a'*32].values)
        self.assertEqual(self.relays.switches.read(plan['id'])['phase'],'complete')

    def test_pending_cleanup_prevents_entry_credential_removal(self):
        self.controls['a'*32].offline = True
        self.execute(self.plan())
        self.assertGreater(self.relays.entry('a'*32)['created_at'],0)
        self.assertEqual(self.relays.catalog()['entries'][0]['pending_cleanup_count'],1)
        with self.assertRaisesRegex(ProvisionError,'Очистка'):
            self.relays.plan_entry_remove('a'*32,{})

    def test_removing_current_route_does_not_restore_retired_rules(self):
        self.controls['a'*32].offline = True
        self.execute(self.plan())
        before = dict(self.controls['a'*32].values)
        with self.store.connection() as database:
            route = dict(database.execute('SELECT * FROM fleet_tunnels WHERE id=?',(self.route_id,)).fetchone())
        self.relays.remove_route_worker('9'*32,route)
        self.assertEqual(self.controls['a'*32].values,before)
        self.assertFalse(self.controls['c'*32].values)

    def test_late_old_check_cannot_replace_new_result(self):
        with self.store.connection() as database:
            previous = dict(database.execute('SELECT * FROM fleet_tunnels WHERE id=?',(self.route_id,)).fetchone())
        self.execute(self.plan())
        self.relays.record_check(previous, {'passed':False,'vpn_passed':False,'proxies_passed':False})
        with self.store.connection() as database:
            result = json.loads(database.execute('SELECT result FROM fleet_tunnels WHERE id=?',(self.route_id,)).fetchone()[0])
        self.assertTrue(result['passed'])

    def test_stale_remove_and_recheck_cannot_mutate_replacement_entry(self):
        with self.store.connection() as database:
            previous = dict(database.execute('SELECT * FROM fleet_tunnels WHERE id=?',(self.route_id,)).fetchone())
        self.execute(self.plan())
        before = deepcopy(self.mapping())
        rules = deepcopy(self.controls['c'*32].values)
        with self.assertRaises(ProvisionError):
            self.relays.remove_route_worker('9'*32,previous)
        with self.assertRaises(ProvisionError):
            self.relays.recheck_route_worker('8'*32,previous)
        self.assertEqual(self.mapping(),before)
        self.assertEqual(self.controls['c'*32].values,rules)

    def test_wrong_entry_dns_is_rejected_before_install(self):
        self.relays.provision.resolve = lambda *_:['192.0.2.99']
        with self.assertRaisesRegex(ProvisionError,'DNS'):
            self.plan()
        self.assertEqual(self.mapping()['entry'],'a'*32)

    def test_entry_dns_change_during_payload_keeps_previous_route(self):
        plan = self.plan()
        def verify(*_):
            self.relays.provision.resolve = lambda *_:['192.0.2.99']
            return {'passed':True}
        self.relays.verify_route = verify
        job = self.execute(plan)
        self.assertEqual(job['state'],'rolled_back')
        self.assertEqual(self.mapping()['entry'],'a'*32)
        self.assertFalse(self.controls['c'*32].values)

    def test_cleanup_retry_does_not_reconnect_current_native_route(self):
        calls = []
        self.relays.reconnect = calls.append
        self.controls['a'*32].offline = True
        self.execute(self.plan())
        count = len(calls)
        for _ in range(2):
            self.due()
            self.relays.switches.recover()
        self.assertEqual(len(calls),count)

    def test_restart_lowercase_metadata_preserves_owned_cleanup(self):
        old = self.mapping()
        config = self.controls['a'*32].values[json.loads(old['config'])['name']]
        def lower_metadata(value):
            if isinstance(value,list):
                for item in value:lower_metadata(item)
            elif isinstance(value,dict):
                for key,item in list(value.items()):
                    if key=='metadata':value[key]={name.lower():setting for name,setting in item.items()}
                    else:lower_metadata(item)
        lower_metadata(config)
        peer = {'name':'peer-route','addr':'0.0.0.0:34444','listener':{'type':'tcp'}}
        self.controls['a'*32].values[peer['name']] = peer
        job = self.execute(self.plan())
        self.assertEqual(job['state'],'succeeded')
        self.assertFalse(job['context']['old_cleanup_pending'])
        self.assertEqual(self.controls['a'*32].values,{'peer-route':peer})

    def test_changed_metadata_values_and_case_collisions_are_protected(self):
        old = self.mapping()
        config = self.controls['a'*32].values[json.loads(old['config'])['name']]
        config['metadata']['enableStats'] = False
        job = self.execute(self.plan())
        self.assertTrue(job['context']['old_cleanup_pending'])
        self.assertIn(config['name'],self.controls['a'*32].values)
        config['metadata']['enableStats'] = True
        config['metadata']['enablestats'] = True
        self.due()
        self.relays.switches.recover()
        self.assertIn(config['name'],self.controls['a'*32].values)
        self.assertTrue(self.relays.catalog()['tunnels'][0]['old_cleanup_pending'])

    def test_changed_forwarder_remains_protected_after_metadata_normalization(self):
        old = self.mapping()
        config = self.controls['a'*32].values[json.loads(old['config'])['name']]
        config['metadata'] = {key.lower():value for key,value in config['metadata'].items()}
        config['forwarder']['nodes'][0]['addr'] = '192.0.2.99:443'
        job = self.execute(self.plan())
        self.assertTrue(job['context']['old_cleanup_pending'])
        self.assertIn(config['name'],self.controls['a'*32].values)


if __name__ == '__main__':
    unittest.main()
