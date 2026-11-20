"""A replacement entry must never receive a control request for a pinned node."""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
from types import ModuleType
from types import SimpleNamespace,MethodType
import unittest
from unittest.mock import patch,Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import rpyc
from rpyc.utils.server import ThreadedServer
from rpyc.utils.authenticators import SSLAuthenticator


ROOT = Path(__file__).resolve().parents[1]


def certificate(root, name,common_name='Gozargah'):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]),critical=False)
            .sign(key,hashes.SHA256()))
    cert_path,key_path=root/(name+'.pem'),root/(name+'.key')
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return cert_path,key_path


def load_node():
    config=ModuleType('app.xray.config');config.XRayConfig=dict
    spec=importlib.util.spec_from_file_location('pinned_native_node',ROOT/'app/xray/node.py')
    module=importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules,{'app':ModuleType('app'),'app.xray':ModuleType('app.xray'),
                                 'app.xray.config':config}):
        spec.loader.exec_module(module)
    return module


class NativeCertificatePinningTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.directory=Path(temporary.name)
        self.trusted,self.trusted_key=certificate(self.directory,'trusted')
        self.foreign,self.foreign_key=certificate(self.directory,'foreign','foreign.invalid')
        self.panel,self.panel_key=certificate(self.directory,'panel')
        self.nodes=load_node();self.received=[]

    def rest_server(self, cert, key,switch_to=None):
        received=self.received
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                received.append((self.path,self.rfile.read(int(self.headers.get('Content-Length','0')))))
                self.send_response(200);self.end_headers()
                self.wfile.write(b'{"session_id":"synthetic","started":false}')
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        if switch_to:
            replacement=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);replacement.load_cert_chain(*switch_to)
            handshakes=[0]
            def select(connection,name,initial):
                handshakes[0]+=1
                if handshakes[0]>1:connection.context=replacement
            context.set_servername_callback(select)
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=2)))
        return server.server_address[1]

    def node(self, kind, port):
        node=getattr(self.nodes,kind)('127.0.0.1',port,62051,self.panel_key.read_text(),self.panel.read_text())
        node._trusted_server_certificate=self.trusted.read_text()
        self.addCleanup(lambda:node._keyfile.close())
        self.addCleanup(lambda:node._certfile.close())
        return node

    def test_rest_replacement_certificate_is_rejected_before_any_http_request(self):
        node=self.node('ReSTXRayNode',self.rest_server(self.foreign,self.foreign_key))
        with self.assertRaises((ConnectionError,ssl.SSLError)):
            node.connect()
        self.assertEqual(self.received,[])

    def test_rest_retains_pin_across_reconnection(self):
        node=self.node('ReSTXRayNode',self.rest_server(self.trusted,self.trusted_key))
        node.connect()
        self.assertEqual([path for path,_ in self.received],['/connect'])
        node.port=self.rest_server(self.foreign,self.foreign_key)
        node._rest_api_url='https://127.0.0.1:'+str(node.port)
        self.received.clear()
        with self.assertRaises((ConnectionError,ssl.SSLError)):
            node.connect()
        self.assertEqual(self.received,[])

    def test_certificate_bundle_cannot_expand_pin_trust_on_the_config_handshake(self):
        port=self.rest_server(self.trusted,self.trusted_key,(self.foreign,self.foreign_key))
        node=self.node('ReSTXRayNode',port)
        node._trusted_server_certificate=self.trusted.read_text()+self.foreign.read_text()
        with self.assertRaises((ConnectionError,ssl.SSLError,self.nodes.NodeAPIError)):
            node.connect()
        self.assertEqual(self.received,[])

    def test_rpyc_replacement_certificate_is_rejected_before_rpc_connect(self):
        received=self.received
        class Service(rpyc.Service):
            def on_connect(self, connection):received.append('control connected')
        server=ThreadedServer(Service,hostname='127.0.0.1',port=0,
            authenticator=SSLAuthenticator(str(self.foreign_key),str(self.foreign)))
        thread=threading.Thread(target=server.start,daemon=True);thread.start()
        self.addCleanup(lambda:(server.close(),thread.join(timeout=2)))
        node=self.node('RPyCXRayNode',server.port)
        with self.assertRaises((ConnectionError,ssl.SSLError)):
            node.connect()
        self.assertEqual(self.received,[])

    def test_legacy_wildcard_balancer_is_restricted_to_public_outbound_tags(self):
        config={'inbounds':[],'outbounds':[{'tag':'DIRECT','protocol':'freedom'}],
                'routing':{'balancers':[{'tag':'public','selector':['']} ]}}
        self.nodes.ReSTXRayNode._prepare_config(SimpleNamespace(_api_direct=False),config)
        self.assertEqual(config['routing']['balancers'][0]['selector'],['DIRECT'])

    def test_legacy_api_chain_is_rejected_before_config_or_private_files_are_sent(self):
        config={'inbounds':[],'routing':{},'outbounds':[{'tag':'DIRECT','protocol':'freedom',
                                                       'proxySettings':{'tag':'API'}}]}
        node=SimpleNamespace(connected=True,_api_direct=False,_started=True,make_request=Mock())
        node._prepare_config=MethodType(self.nodes.ReSTXRayNode._prepare_config,node)
        with self.assertRaises(ValueError):self.nodes.ReSTXRayNode._start_locked(node,config)
        node.make_request.assert_not_called()
        self.assertTrue(node._started)

    def test_qualified_direct_api_preserves_a_legitimate_wildcard_balancer(self):
        config={'inbounds':[],'outbounds':[{'tag':'DIRECT','protocol':'freedom'}],
                'routing':{'balancers':[{'tag':'public','selector':['']} ]}}
        self.nodes.ReSTXRayNode._prepare_config(SimpleNamespace(_api_direct=True),config)
        self.assertEqual(config['routing']['balancers'][0]['selector'],[''])

    def test_rejected_legacy_rpyc_restart_preserves_the_running_core_state(self):
        config={'inbounds':[],'outbounds':[{'tag':'DIRECT','protocol':'freedom'}],
                'routing':{'balancers':[{'tag':'public','selector':['API']}]}}
        node=SimpleNamespace(started=True,_api_direct=False,_capabilities=lambda:{},remote=Mock())
        node._prepare_config=MethodType(self.nodes.RPyCXRayNode._prepare_config,node)
        with self.assertRaises(ValueError):self.nodes.RPyCXRayNode._restart_locked(node,config)
        self.assertTrue(node.started)
        node.remote.restart.assert_not_called()

    def test_public_api_routing_rules_cannot_survive_a_legacy_config_send(self):
        for tags in (None,['VPN'],['API_INBOUND','VPN']):
            with self.subTest(tags=tags):
                rule={'outboundTag':'API'}
                if tags is not None:rule['inboundTag']=tags
                config={'inbounds':[],'outbounds':[{'tag':'DIRECT','protocol':'freedom'}],
                        'routing':{'rules':[dict(rule),dict(rule)]}}
                with self.assertRaises(ValueError):
                    self.nodes.ReSTXRayNode._prepare_config(SimpleNamespace(_api_direct=False),config)
        control={'inbounds':[],'outbounds':[{'tag':'DIRECT','protocol':'freedom'}],
                 'routing':{'rules':[{'inboundTag':['API_INBOUND'],'outboundTag':'API'}]}}
        self.nodes.ReSTXRayNode._prepare_config(SimpleNamespace(_api_direct=False),control)

    def test_stable_rpyc_api_transport_is_reused_and_a_changed_transport_is_retired(self):
        created=[]
        def create(**options):
            api=SimpleNamespace(_channel=SimpleNamespace(close=Mock()),get_sys_stats=Mock(return_value=object()))
            created.append(api);return api
        node=self.node('RPyCXRayNode',62050)
        node._node_cert=self.trusted.read_text()
        with patch.object(self.nodes,'XRayAPI',side_effect=create):
            for _ in range(5):node._initialize_api({'api_mtls':1})
            self.assertEqual(len(created),1)
            first=node._api
            first.usage_epoch=lambda:'old-core'
            node.api_port+=1
            node._initialize_api({'api_mtls':1})
        self.assertEqual(len(created),2)
        self.assertTrue(first.retired)
        self.assertIsNone(first.usage_epoch)
        first._channel.close.assert_called_once()

    def test_broken_same_endpoint_api_is_repaired_once_instead_of_trusting_ready_state(self):
        created=[]
        def create(**options):
            api=SimpleNamespace(_channel=SimpleNamespace(close=Mock()),get_sys_stats=Mock(return_value=object()))
            created.append(api);return api
        node=self.node('RPyCXRayNode',62050)
        node._node_cert=self.trusted.read_text()
        with patch.object(self.nodes,'XRayAPI',side_effect=create):
            node._initialize_api({'api_mtls':1})
            old=node._api
            old.get_sys_stats.side_effect=OSError('Synthetic stale gRPC transport after a core crash')
            node._initialize_api({'api_mtls':1})
            node._initialize_api({'api_mtls':1})
        self.assertEqual(len(created),2)
        self.assertTrue(old.retired)
        old._channel.close.assert_called_once()
        self.assertIs(node._api,created[1])


if __name__=='__main__':unittest.main()
