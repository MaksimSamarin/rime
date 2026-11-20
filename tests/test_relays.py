import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hy2bridge.provision import ProvisionError
from hy2bridge.proxy_secrets import ProxySecrets
from hy2bridge.relays import Relays
from hy2bridge.store import Store


class Control:
    def __init__(self):
        self.values = {}
        self.fail_on = None

    def services(self):return list(self.values.values())
    def add(self,value):
        if value['name'] == self.fail_on:raise OSError('Synthetic entry failure')
        if value['name'] in self.values:raise ValueError('Duplicate service')
        self.values[value['name']] = value
    def remove(self,name):self.values.pop(name,None)
    def save(self):pass


class RelayTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        sqlite3.connect(self.root/'db.sqlite3').close()
        self.store = Store(self.root/'db.sqlite3')
        with self.store.connection(write=True) as database:
            database.execute('CREATE TABLE fleet_host_nodes(host_id INTEGER,node TEXT)')
            database.execute("INSERT INTO fleet_host_nodes VALUES(1,'node-a')")
        self.source = {'node':'node-a','name':'Exit A','protocol':'hysteria2','identity':{'created_at':'fixture-generation','address':'192.0.2.20'},'native':None}
        provision = SimpleNamespace(store=self.store,settings={},lock=threading.Lock())
        transfer = SimpleNamespace(digest=lambda value:json.dumps(value,sort_keys=True),
                                   snapshot=lambda *_:self.source)
        proxies = SimpleNamespace(secrets=ProxySecrets(self.root/'private.key'))
        self.relays = Relays(provision,transfer,proxies)
        self.relays.reconnect = lambda _:None
        self.relays.source = lambda _: (self.source,{'vpn':{'protocol':'hysteria2'},'proxies':{}})
        self.relays.verify_route = lambda *_:{'passed':True,'checks':1}
        self.control = Control()
        self.relays.control = lambda _:self.control
        self.entry = {'id':'a'*32,'name':'Entry','domain':'entry.example','address':'192.0.2.10'}
        self.relays.entry = lambda _:self.entry
        with self.store.connection(write=True) as database:
            database.execute('''INSERT INTO fleet_relay_entries(id,name,host,address,domain,control_port,metrics_port,api_port,
                credential,ssh_port,username,fingerprint,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                ('a'*32,'Entry','entry.example','192.0.2.10','entry.example',62080,62081,62082,
                 'private-control-envelope',22,'root','SHA256:fixture','active',time.time()))

    def record(self,node='node-a'):
        source = {**self.source,'node':node}
        return {'entry':self.entry,'source':source,'origin':'192.0.2.20','services':[
            {'kind':'vpn','proxy':None,'origin_port':443,'public_port':10443,'protocol':'udp'},
            {'kind':'proxy','proxy':'c'*32,'origin_port':3128,'public_port':13128,'protocol':'tcp'}]}

    def test_verified_route_changes_only_public_endpoints(self):
        record = self.record()
        self.relays.install_route('b'*32,record)
        self.assertEqual(self.relays.job('b'*32)['state'],'succeeded')
        link = 'hysteria2://old-user-key@exit.example:443/?sni=exit.example#Existing'
        published = self.relays.published_link('node-a',link)
        self.assertEqual(published,'hysteria2://old-user-key@entry.example:10443/?sni=exit.example#Existing')
        self.assertEqual(self.source['identity']['address'],'192.0.2.20')
        self.assertEqual(len(self.control.services()),2)

    def test_failed_payload_removes_only_attempted_route(self):
        peer = {'name':'peer-node-route','addr':':14443'}
        self.control.add(peer)
        def fail(*_):raise ProvisionError('Synthetic payload failure')
        self.relays.verify_route = fail
        self.relays.install_route('b'*32,self.record())
        self.assertEqual(self.relays.job('b'*32)['state'],'rolled_back')
        self.assertEqual(self.control.services(),[peer])
        self.assertEqual(self.relays.endpoint_map('node-a'),{})

    def test_proxy_delete_detaches_its_rule_and_preserves_vpn(self):
        self.relays.install_route('b'*32,self.record())
        desired = self.relays.changes.prepare_proxy_delete('d'*32,'node-a','c'*32)
        self.relays.changes.apply('d'*32,desired)
        with self.store.connection(write=True) as database:
            self.relays.changes.publish('d'*32,database=database)
        self.relays.changes.finish('d'*32,True)
        self.assertEqual(len(self.control.services()),1)
        self.assertEqual(next(iter(self.relays.endpoint_map('node-a')))[0],'vpn')

    def test_proxy_delete_conflict_restores_selected_rules(self):
        self.relays.install_route('b'*32,self.record())
        snapshot = self.relays.proxy_routes('c'*32)
        desired = self.relays.changes.prepare_proxy_delete('d'*32,'node-a','c'*32)
        self.relays.changes.apply('d'*32,desired)
        self.relays.changes.finish('d'*32,False)
        self.assertEqual(len(self.control.services()),2)
        self.assertEqual(self.relays.proxy_routes('c'*32),snapshot)

    def test_removing_one_route_does_not_remove_peer_services(self):
        self.relays.install_route('b'*32,self.record())
        peer = {'name':'another-exit','addr':':24443'}
        self.control.add(peer)
        with self.store.connection() as database:
            route = dict(database.execute('SELECT * FROM fleet_tunnels WHERE id=?',('b'*32,)).fetchone())
        self.relays.remove_route_worker('d'*32,route)
        self.assertEqual(self.relays.job('d'*32)['state'],'succeeded')
        self.assertEqual(self.control.services(),[peer])
        self.assertEqual(self.relays.published_link('node-a','hysteria2://key@exit.example:443'), 'hysteria2://key@exit.example:443')

    def test_generation_change_before_publish_rolls_back(self):
        def change(*_):
            self.source = {**self.source,'name':'Changed concurrently'}
            return {'passed':True}
        self.relays.verify_route = change
        self.relays.install_route('b'*32,self.record())
        self.assertEqual(self.relays.job('b'*32)['state'],'rolled_back')
        self.assertEqual(self.control.services(),[])

    def test_starting_second_route_for_same_node_is_rejected(self):
        self.relays.install_route('b'*32,self.record())
        self.relays.install_route('d'*32,self.record())
        self.assertEqual(self.relays.job('d'*32)['state'],'rolled_back')
        self.assertEqual(len(self.control.services()),2)

    def test_catalog_never_returns_control_credentials(self):
        public = json.dumps(self.relays.catalog())
        self.assertNotIn('private-control-envelope',public)
        self.assertNotIn('credential',public)

    def test_transfer_retargets_forwarding_without_changing_public_ports(self):
        self.relays.install_route('b'*32,self.record())
        before=self.relays.changes.prepare('d'*32,'node-a','transfer')
        self.relays.changes.retarget('d'*32,{'address':'192.0.2.30','ssh_port':22,'_source':self.source,'_profile':{}})
        self.relays.changes.finish('d'*32,True)
        after=self.relays.endpoint_map('node-a')
        self.assertEqual(sorted(value['public_port'] for value in after.values()),
            sorted(value['public_port'] for value in before['services']))
        self.assertEqual(self.relays.direct_target('node-a'),'192.0.2.30')
        self.assertTrue(all(value['forwarder']['nodes'][0]['addr'].startswith('192.0.2.30:') for value in self.control.services()))
        self.assertEqual(self.relays.changes.read('d'*32)['phase'],'committed')
        self.assertNotIn('a'*32,self.relays.busy)

    def test_failed_transfer_restores_only_its_original_forwarding(self):
        self.relays.install_route('b'*32,self.record())
        peer={'name':'unrelated-exit','addr':':34443'}
        self.control.add(peer)
        self.relays.changes.prepare('d'*32,'node-a','transfer')
        self.relays.changes.retarget('d'*32,{'address':'192.0.2.30','ssh_port':22,'_source':self.source,'_profile':{}})
        self.relays.changes.finish('d'*32,False)
        self.assertEqual(self.relays.direct_target('node-a'),'192.0.2.20')
        self.assertIn(peer,self.control.services())
        self.assertEqual(self.relays.changes.read('d'*32)['phase'],'rolled_back')
        self.assertEqual(len(self.relays.endpoint_map('node-a')),2)

    def test_interrupted_transfer_recovery_restores_its_prior_origin(self):
        self.relays.install_route('b'*32,self.record())
        self.relays.changes.prepare('d'*32,'node-a','transfer')
        self.relays.changes.retarget('d'*32,{'address':'192.0.2.30','ssh_port':22,'_source':self.source,'_profile':{}})
        with self.store.connection(write=True) as database:
            database.execute('CREATE TABLE fleet_node_transfers(id TEXT,state TEXT)')
            database.execute('INSERT INTO fleet_node_transfers VALUES(?,?)',('d'*32,'rolled_back'))
        self.relays.busy.clear()
        from hy2bridge.relay_changes import RelayChanges
        self.relays.changes=RelayChanges(self.relays)
        self.relays.changes.recover()
        self.assertEqual(self.relays.direct_target('node-a'),'192.0.2.20')
        self.assertEqual(self.relays.changes.read('d'*32)['phase'],'rolled_back')

    def test_published_dns_cannot_turn_a_direct_probe_into_a_hidden_tunnel_probe(self):
        self.relays.install_route('b'*32,self.record())
        from hy2bridge.provision_probe import ProvisionProbe
        probe=ProvisionProbe(self.store,{},None,None)
        probe.target=lambda *_:{'node':'node-a','config':{'_hostname':'entry.example'}}
        with patch('hy2bridge.relay_routes.current',self.relays),patch('socket.getaddrinfo',side_effect=AssertionError('Published DNS must not route the direct probe')):
            target=probe.active_target('fixture',{})
        self.assertEqual(target['resolved_ip'],'192.0.2.20')

    def test_background_check_distinguishes_a_working_vpn_from_missing_proxy_access(self):
        self.relays.transfer.probe=SimpleNamespace(transfer_targets=lambda *_:[{
            'node':'node-a','expected_ip':'192.0.2.20','config':{'_kind':'hy2','_hostname':'exit.example','server':'192.0.2.20:443'}}])
        with self.store.connection(write=True) as database:
            database.execute('CREATE TABLE fleet_proxy_services(id TEXT,node TEXT,active INTEGER)')
            database.execute('INSERT INTO fleet_proxy_services VALUES(?,?,1)',('c'*32,'node-a'))
        def unavailable(_):raise ProvisionError('Synthetic missing vault credential')
        self.relays.proxies.clear_password=unavailable
        with patch('hy2bridge.client_probe.probe',return_value={'passed':True,'stage':'payload'}):
            result=Relays.verify_route(self.relays,self.source,{},self.entry,'192.0.2.20',self.record()['services'],False)
        self.assertTrue(result['vpn_passed'])
        self.assertFalse(result['proxies_passed'])
        self.assertFalse(result['passed'])
