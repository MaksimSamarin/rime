"""Durable certificate identity and independently delivered management source ACLs."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import ssl
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hy2bridge.control_firewall import apply as apply_firewall
from hy2bridge.native_sources import ManagementSources
from hy2bridge.native_trust import NativeTrust,NodeCertificateError
from hy2bridge.observer import Sender
from hy2bridge.observers import Observers
from hy2bridge.store import Store
from test_native_certificate_pinning import certificate
from test_native_api_bridge import certificate as tls_certificate


class NativeSecurityStateTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.path=self.root/'panel.sqlite3'
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE nodes(id INTEGER PRIMARY KEY,created_at TEXT NOT NULL)')
            db.execute("INSERT INTO nodes VALUES(1,'first-registration')")
            db.execute('''CREATE TABLE fleet_events(id INTEGER PRIMARY KEY,node TEXT,code TEXT,severity TEXT,
                first_at REAL,last_at REAL,occurrences INTEGER DEFAULT 1,resolved_at REAL)''')
        self.store=Store(self.path)
        self.original,_=certificate(self.root,'original');self.foreign,_=certificate(self.root,'foreign')
        self.profile={'vpn':{'management_tls':{'certificate':self.original.read_text()}}}
        self.recovery=SimpleNamespace(load=lambda node:self.profile)
        self.trust=NativeTrust(self.store,self.recovery)
        self.sources=ManagementSources(self.store,{'control_source':'192.0.2.2'})

    def test_authoritative_profile_pin_survives_controller_recreation(self):
        expected=self.trust.expected('xray:1')
        self.profile={}
        restarted=NativeTrust(self.store,self.recovery)
        self.assertEqual(restarted.expected('xray:1'),expected)
        with self.assertRaises(NodeCertificateError):
            restarted.verify('xray:1',expected,self.foreign.read_text())
        with self.store.connection() as db:
            event=db.execute("SELECT * FROM fleet_events WHERE code='native_tls_identity_changed'").fetchone()
            self.assertEqual(event['node'],'xray:1')
            self.assertEqual(db.execute('SELECT certificate FROM fleet_native_trust').fetchone()[0],expected)

    def test_existing_unenrolled_node_does_not_silently_trust_network_certificate(self):
        self.profile={}
        with self.assertRaises(NodeCertificateError):self.trust.expected('xray:1')
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM fleet_native_trust').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT code FROM fleet_events').fetchone()[0],'native_tls_unverified')

    def test_old_unverified_public_certificate_cache_cannot_seed_a_pin(self):
        self.profile={'vpn':{'management_server_certificate':self.foreign.read_text()}}
        with self.assertRaises(NodeCertificateError):self.trust.expected('xray:1')
        self.profile['vpn']['management_certificate_verified']=True
        self.assertEqual(self.trust.expected('xray:1'),self.foreign.read_text())

    def test_restored_original_identity_resolves_the_mismatch_event(self):
        expected=self.trust.expected('xray:1')
        with self.assertRaises(NodeCertificateError):self.trust.verify('xray:1',expected,self.foreign.read_text())
        self.trust.verify('xray:1',expected,expected)
        with self.store.connection() as db:
            self.assertIsNotNone(db.execute("SELECT resolved_at FROM fleet_events WHERE code='native_tls_identity_changed'").fetchone()[0])

    def test_reused_node_id_does_not_inherit_old_certificate(self):
        self.trust.expected('xray:1');self.profile={}
        with self.store.connection(write=True) as db:
            db.execute("UPDATE nodes SET created_at='second-registration' WHERE id=1")
        with self.assertRaises(NodeCertificateError):self.trust.expected('xray:1')
        self.trust.enroll('xray:1',self.foreign.read_text())
        self.assertEqual(self.trust.expected('xray:1'),self.foreign.read_text())

    def test_explicit_enrollment_cannot_silently_replace_registered_identity(self):
        self.trust.expected('xray:1')
        with self.assertRaises(NodeCertificateError):self.trust.enroll('xray:1',self.foreign.read_text())

    def test_only_exact_current_policy_ack_allows_activation(self):
        entry={'id':'entry-b','address':'192.0.2.11'}
        policy=self.sources.refresh('xray:1',entry)
        self.assertEqual(policy['sources'],['192.0.2.11','192.0.2.2'])
        with self.assertRaises(ValueError):self.sources.wait_applied(policy,timeout=.01)
        self.sources.response('xray:1',{'revision':policy['revision'],'digest':'foreign'})
        with self.assertRaises(ValueError):self.sources.wait_applied(policy,timeout=.01)
        self.sources.response('xray:1',{'revision':policy['revision'],'digest':policy['digest']})
        self.assertTrue(self.sources.wait_applied(policy,timeout=.1))

    def test_rollback_revokes_prepared_source_and_stale_ack_cannot_authorize_it(self):
        policy=self.sources.refresh('xray:1',{'id':'entry-b','address':'192.0.2.11'})
        rolled_back=self.sources.refresh('xray:1',clear_leases=True)
        self.assertEqual(rolled_back['sources'],['192.0.2.2'])
        self.assertGreater(rolled_back['revision'],policy['revision'])
        self.sources.response('xray:1',policy)
        with self.assertRaises(ValueError):self.sources.wait_applied(rolled_back,timeout=.01)

    def test_new_destination_observer_cannot_inherit_the_previous_hosts_firewall_ack(self):
        observers=Observers(self.store)
        observers.register_native('xray:1','a'*40,'node.invalid',443)
        old=self.sources.refresh('xray:1',{'id':'entry','address':'192.0.2.11'})
        self.sources.response('xray:1',old)
        self.assertTrue(self.sources.wait_applied(old,timeout=.1))
        observers.register_native('xray:1','b'*40,'node.invalid',443)
        new=self.sources.refresh('xray:1')
        self.assertGreater(new['revision'],old['revision'])
        self.sources.response('xray:1',old)
        with self.assertRaises(ValueError):self.sources.wait_applied(new,timeout=.01)
        self.sources.response('xray:1',new)
        self.assertTrue(self.sources.wait_applied(new,timeout=.1))

    def test_grace_and_pending_cleanup_keep_the_old_entry_until_owned_cleanup_finishes(self):
        with self.store.connection(write=True) as db:
            db.execute('CREATE TABLE fleet_relay_entries(id TEXT,address TEXT,state TEXT)')
            db.execute("INSERT INTO fleet_relay_entries VALUES('old','192.0.2.10','active')")
            db.execute('CREATE TABLE fleet_relay_switches(node TEXT,old_entry TEXT,phase TEXT)')
            db.execute("INSERT INTO fleet_relay_switches VALUES('xray:1','old','grace_pending')")
        self.assertIn('192.0.2.10',self.sources.refresh('xray:1')['sources'])
        with self.store.connection(write=True) as db:db.execute("UPDATE fleet_relay_switches SET phase='cleanup_pending'")
        self.assertIn('192.0.2.10',self.sources.refresh('xray:1')['sources'])
        with self.store.connection(write=True) as db:db.execute("UPDATE fleet_relay_switches SET phase='cleaned'")
        self.assertNotIn('192.0.2.10',self.sources.refresh('xray:1')['sources'])

    def test_https_observer_delivers_acl_and_ack_without_any_old_controller_connection(self):
        policy_dir=self.root/'policy';policy_dir.mkdir(mode=0o700)
        cert,key=tls_certificate(self.root,'localhost')
        owner=self;requests=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                if self.headers.get('Authorization')!='Bearer '+'a'*40:
                    self.send_response(401);self.end_headers();return
                data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append(data)
                policy=owner.sources.response('xray:1',data.get('management_policy_ack'))
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps({'received':True,'management_policy':policy}).encode())
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=2)))
        sender=Sender({'url':'https://localhost:'+str(server.server_address[1])+'/api/fleet/telemetry/xray%3A1',
            'token':'a'*40,'ca_file':str(cert),'management_policy_dir':str(policy_dir)})
        policy=self.sources.refresh('xray:1',{'id':'new-entry','address':'192.0.2.11'})
        sender.send({'service_healthy':True})
        self.assertEqual(json.loads((policy_dir/'sources.json').read_text())['sources'],policy['sources'])
        # The fixed host worker acknowledges only after its restore succeeds.
        with patch('hy2bridge.control_firewall.subprocess.run',return_value=SimpleNamespace(returncode=0)) as commands:
            apply_firewall({'id':'a'*32,'panel_source':'192.0.2.2','ports':[62050,62051],
                            'policy_file':str(policy_dir/'sources.json')})
        restore=next(call for call in commands.call_args_list if call.args[0][0]=='iptables-restore')
        self.assertIn('-s 192.0.2.11/32 -j RETURN',restore.kwargs['input'])
        self.assertIn('--ctorigdstport 62051 -j DROP',restore.kwargs['input'])
        sender.send({'service_healthy':True})
        self.assertTrue(self.sources.wait_applied(policy,timeout=.1))
        self.assertEqual(requests[-1]['management_policy_ack']['digest'],policy['digest'])


if __name__=='__main__':unittest.main()
