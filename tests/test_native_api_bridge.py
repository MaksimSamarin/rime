"""Real TLS and gRPC acceptance for the authenticated native API bridge."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import uuid
from unittest.mock import patch

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from xray_api.base import XRayBase
from xray_api.proto.app.stats.command import command_pb2, command_pb2_grpc

ROOT = Path(__file__).resolve().parents[1]


class VlessGrpcProxy:
    """Expose one real VLESS destination as a local gRPC transport in a test."""
    def __init__(self, vpn_port, auth, target_host, target_port):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    with socket.create_connection(('127.0.0.1',vpn_port),timeout=2) as remote:
                        host=target_host.encode()
                        header=b'\x00'+uuid.UUID(auth).bytes+b'\x00\x01'+target_port.to_bytes(2,'big')+b'\x02'+bytes([len(host)])+host
                        remote.sendall(header)
                        if remote.recv(2)!=b'\x00\x00':return
                        remote.settimeout(None)

                        def copy(source,destination):
                            try:
                                while data:=source.recv(65536):destination.sendall(data)
                            except OSError:
                                pass
                            finally:
                                for connection in (source,destination):
                                    try:connection.shutdown(socket.SHUT_RDWR)
                                    except OSError:pass

                        upstream=threading.Thread(target=copy,args=(self.request,remote),daemon=True)
                        upstream.start();copy(remote,self.request);upstream.join(timeout=2)
                except OSError:
                    pass

        self.server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler)
        self.server.daemon_threads=True
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.address='127.0.0.1:'+str(self.server.server_address[1])

    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)


def load_runtime(name):
    spec = importlib.util.spec_from_file_location('fixture_' + name, ROOT / 'node-runtime' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def certificate(directory, name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
            .not_valid_after(now+timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]),critical=False)
            .sign(key,hashes.SHA256()))
    cert_path, key_path = directory / (name+'.pem'), directory / (name+'.key')
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return cert_path,key_path


@unittest.skipUnless(sys.platform=='linux','The native Unix-socket runtime is qualified on Linux')
class NativeApiBridgeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.node_cert,self.node_key = certificate(self.directory,'node.test')
        self.panel_cert,self.panel_key = certificate(self.directory,'panel.test')
        self.foreign_cert,self.foreign_key = certificate(self.directory,'foreign.test')
        self.runtime = load_runtime('api_bridge')
        self.calls = []
        self.grpc = grpc.server(ThreadPoolExecutor(max_workers=2))

        def echo(request, context):
            self.calls.append(request)
            return request

        handler = grpc.method_handlers_generic_handler('fixture.API',{
            'Echo':grpc.unary_unary_rpc_method_handler(echo)})
        self.grpc.add_generic_rpc_handlers((handler,))
        self.internal_path = self.directory/'grpc.sock'
        self.grpc.add_insecure_port('unix:'+str(self.internal_path))
        self.fixture_tcp_port = self.grpc.add_insecure_port('127.0.0.1:0')
        self.grpc.start()
        self.internal_path.chmod(0o600)
        self.addCleanup(lambda:self.grpc.stop(0).wait())
        self.bridge = self.runtime.APIBridge('127.0.0.1',0,str(self.node_cert),str(self.node_key),
                                             str(self.panel_cert),self.internal_path)
        self.addCleanup(self.bridge.close)
        self.port = self.bridge.server.server_address[1]

    def client(self, kind='correct'):
        cert,key = (self.panel_cert,self.panel_key) if kind=='correct' else (self.foreign_cert,self.foreign_key)
        kwargs = {'ssl_cert':self.node_cert.read_bytes(),'ssl_target_name':'node.test',
                  'control_identity':('physical-exit.test',62051)}
        if kind!='missing':
            kwargs.update(client_cert=cert.read_bytes(),ssl_key=key.read_bytes())
        api = XRayBase('127.0.0.1',self.port,**kwargs)
        self.addCleanup(api._channel.close)
        return api

    def test_authenticated_controller_uses_real_grpc_through_bridge(self):
        api = self.client()
        call = api._channel.unary_unary('/fixture.API/Echo')
        self.assertEqual(call(b'authenticated payload',timeout=3),b'authenticated payload')
        self.assertEqual(self.calls,[b'authenticated payload'])

    def test_missing_controller_certificate_cannot_reach_api(self):
        api = self.client('missing')
        with self.assertRaises(grpc.RpcError):
            api._channel.unary_unary('/fixture.API/Echo')(b'forbidden',timeout=1)
        self.assertEqual(self.calls,[])

    def test_foreign_controller_certificate_cannot_reach_api(self):
        api = self.client('foreign')
        with self.assertRaises(grpc.RpcError):
            api._channel.unary_unary('/fixture.API/Echo')(b'forbidden',timeout=1)
        self.assertEqual(self.calls,[])

    def test_one_source_cannot_consume_every_api_handshake_slot(self):
        pending=[]
        try:
            for _ in range(5):
                connection=socket.create_connection(('127.0.0.1',self.port),timeout=1)
                connection.settimeout(.5);pending.append(connection)
            self.assertEqual(pending[-1].recv(1),b'')
            context=ssl.create_default_context(cafile=str(self.node_cert))
            context.load_cert_chain(self.panel_cert,self.panel_key)
            other=socket.create_connection(('127.0.0.1',self.port),timeout=1,
                                           source_address=('127.0.0.2',0))
            with context.wrap_socket(other,server_hostname='node.test') as verified:
                self.assertTrue(verified.getpeercert())
        finally:
            for connection in pending:connection.close()

    def test_old_and_new_entry_clients_share_physical_node_lock(self):
        first = self.client()
        second = XRayBase('127.0.0.2',self.port+1,control_identity=('physical-exit.test',62051))
        self.addCleanup(second._channel.close)
        self.assertIs(first.control_lock,second.control_lock)
        third = XRayBase('127.0.0.2',self.port+1,control_identity=('another-exit.test',62051))
        self.addCleanup(third._channel.close)
        self.assertIsNot(first.control_lock,third.control_lock)

    def test_partial_client_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            XRayBase('127.0.0.1',self.port,ssl_cert=b'fixture',ssl_key=b'key')
        with self.assertRaises(ValueError):
            XRayBase('127.0.0.1',self.port,ssl_key=b'key',client_cert=b'cert')

    def test_node_endpoint_is_stable_across_repeated_configuration(self):
        module = load_runtime('api_bridge')
        fake = types.SimpleNamespace(XRAY_API_HOST='127.0.0.1',XRAY_API_PORT=0,
            SSL_CERT_FILE=str(self.node_cert),SSL_KEY_FILE=str(self.node_key),
            SSL_CLIENT_CERT_FILE=str(self.panel_cert))
        with patch.dict(sys.modules,{'config':fake}):
            first = module.internal_endpoint()
            self.addCleanup(module._bridge.close)
            self.assertEqual(module.internal_endpoint(),first)
            self.assertEqual(first[1],0)
            self.assertTrue(first[0].endswith('/api.sock,0600'))
            self.assertEqual(module._bridge.directory.stat().st_mode&0o777,0o700)

    def test_only_owned_stale_unix_socket_is_removed_before_restart(self):
        module = load_runtime('api_bridge')
        fake = types.SimpleNamespace(XRAY_API_HOST='127.0.0.1',XRAY_API_PORT=0,
            SSL_CERT_FILE=str(self.node_cert),SSL_KEY_FILE=str(self.node_key),
            SSL_CLIENT_CERT_FILE=str(self.panel_cert))
        with patch.dict(sys.modules,{'config':fake}):
            module.internal_endpoint()
            bridge=module._bridge
            self.addCleanup(bridge.close)
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as previous:
                previous.bind(str(bridge.internal))
            self.assertTrue(bridge.internal.exists())
            module.internal_endpoint()
            self.assertFalse(bridge.internal.exists())
            bridge.internal.write_text('unexpected owned data')
            with self.assertRaises(ValueError):
                module.internal_endpoint()
            self.assertEqual(bridge.internal.read_text(),'unexpected owned data')
            bridge.internal.unlink()

    @unittest.skipUnless(Path('/opt/rime-probe/xray').is_file(),'The qualified Xray binary is required')
    def test_real_vless_user_cannot_invoke_private_api_by_ip_dns_or_socket_path(self):
        bridge=self.runtime.APIBridge('127.0.0.1',0,str(self.node_cert),str(self.node_key),str(self.panel_cert))
        self.addCleanup(bridge.close)
        listen,_=bridge.prepare_endpoint()
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0));vpn_port=reserved.getsockname()[1]
        auth='11111111-1111-4111-8111-111111111111'
        config={'log':{'loglevel':'warning'},'api':{'tag':'API','listen':listen,'services':['StatsService']},'stats':{},
            'inbounds':[{'tag':'VPN','listen':'127.0.0.1','port':vpn_port,'protocol':'vless',
                 'settings':{'decryption':'none','clients':[{'id':auth}]}}],
            'routing':{'domainStrategy':'AsIs','rules':[
                        {'type':'field','domain':['full:api-selector.invalid'],'balancerTag':'TRY_API'},
                        {'type':'field','inboundTag':['VPN'],'balancerTag':'PUBLIC'}],
                       'balancers':[{'tag':'TRY_API','selector':['API']},{'tag':'PUBLIC','selector':['']}]},
            'outbounds':[{'tag':'DIRECT','protocol':'freedom','settings':{'finalRules':[{'action':'allow'}]}}]}
        path=self.directory/'core.json';path.write_text(json.dumps(config))
        with (self.directory/'core.log').open('w') as log:
            process=subprocess.Popen(['/opt/rime-probe/xray','run','-c',str(path)],stdout=log,stderr=log)
            try:
                deadline=time.monotonic()+4
                while not bridge.internal.exists() and time.monotonic()<deadline and process.poll() is None:time.sleep(.05)
                self.assertTrue(bridge.internal.is_socket(),(self.directory/'core.log').read_text()[-1500:])
                self.assertEqual(bridge.internal.stat().st_mode&0o777,0o600)
                controller=XRayBase('127.0.0.1',bridge.server.server_address[1],ssl_cert=self.node_cert.read_bytes(),
                    ssl_target_name='node.test',ssl_key=self.panel_key.read_bytes(),client_cert=self.panel_cert.read_bytes())
                self.addCleanup(controller._channel.close)
                stub=command_pb2_grpc.StatsServiceStub(controller._channel)
                self.assertGreaterEqual(stub.GetSysStats(command_pb2.SysStatsRequest(),timeout=3).Uptime,0)
                allowed=VlessGrpcProxy(vpn_port,auth,'localhost',self.fixture_tcp_port)
                self.addCleanup(allowed.close)
                channel=grpc.insecure_channel(allowed.address);self.addCleanup(channel.close)
                self.assertEqual(channel.unary_unary('/fixture.API/Echo')(b'allowed loopback service',timeout=3),b'allowed loopback service')
                hidden=VlessGrpcProxy(vpn_port,auth,'api-selector.invalid',self.fixture_tcp_port)
                self.addCleanup(hidden.close)
                hidden_channel=grpc.insecure_channel(hidden.address);self.addCleanup(hidden_channel.close)
                with self.assertRaises(grpc.RpcError):
                    command_pb2_grpc.StatsServiceStub(hidden_channel).GetSysStats(command_pb2.SysStatsRequest(),timeout=1)
                for host,port,encrypted in [(str(bridge.internal),1,False),('127.0.0.1',bridge.server.server_address[1],True),
                                             ('localhost',bridge.server.server_address[1],True)]:
                    with self.subTest(host=host):
                        hop=VlessGrpcProxy(vpn_port,auth,host,port)
                        if encrypted:
                            channel=grpc.secure_channel(hop.address,grpc.ssl_channel_credentials(root_certificates=self.node_cert.read_bytes()),
                                options=[('grpc.ssl_target_name_override','node.test')])
                        else:channel=grpc.insecure_channel(hop.address)
                        try:
                            with self.assertRaises(grpc.RpcError):
                                command_pb2_grpc.StatsServiceStub(channel).GetSysStats(command_pb2.SysStatsRequest(),timeout=1)
                        finally:channel.close();hop.close()
                self.assertGreaterEqual(stub.GetSysStats(command_pb2.SysStatsRequest(),timeout=2).Uptime,0)
            finally:
                process.terminate();process.wait(timeout=3)


class NativeApiPatchTests(unittest.TestCase):
    def test_staged_api_config_is_unix_only_and_independent_of_peer(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'xray.py').write_text('''class XRayConfig(dict):
    def _apply_api(self):
        inbound={'tag':'API_INBOUND','listen':self.api_host,'port':self.api_port,
                 'streamSettings':{'security':'tls','tlsSettings':{'certificates':['node-cert']}}}
        rule={'source':['127.0.0.1',self.peer_ip],'outboundTag':'API'}
        self.update(inbound=inbound,rule=rule)
''')
            (root/'node_autonomy.py').write_text("def capabilities(config):\n    return {'user_reconcile':1}\n")
            patcher = load_runtime('patch_api')
            self.assertTrue(patcher.patch_api(root))
            fake = types.SimpleNamespace(internal_endpoint=lambda:('/private/api.sock,0600',0))
            namespace = {}
            with patch.dict(sys.modules,{'api_bridge':fake}):
                exec(compile((root/'xray.py').read_text(),str(root/'xray.py'),'exec'),namespace)
            first,second = namespace['XRayConfig'](),namespace['XRayConfig']()
            for config,peer in [(first,'192.0.2.10'),(second,'192.0.2.20')]:
                config.update({'inbounds':[{'tag':'API_INBOUND'},{'tag':'VPN'}],
                               'api':{'tag':'PREVIOUS_API'},'routing':{'rules':[
                                   {'outboundTag':'PREVIOUS_API'},{'outboundTag':'DIRECT'}]}})
                config.peer_ip=peer
                config._apply_api()
            self.assertEqual(first,second)
            self.assertEqual(first['api']['listen'],'/private/api.sock,0600')
            self.assertEqual(first['api']['tag'],'API')
            self.assertEqual(first['inbounds'],[{'tag':'VPN'}])
            self.assertEqual(first['routing']['rules'],[{'outboundTag':'DIRECT'}])
            direct=[]
            for host in ('first.invalid','second.invalid'):
                config=namespace['XRayConfig']({'api':{'tag':'API','listen':'/previous/direct.sock,0600'},
                    'inbounds':[{'tag':'VPN'}],
                    'outbounds':[{'tag':'API','protocol':'freedom'}],
                    'routing':{'rules':[{'domain':['full:'+host],'outboundTag':'API'}]}})
                config._apply_api();direct.append(config)
            self.assertNotEqual(direct[0],direct[1])
            self.assertEqual(direct[0]['routing']['rules'][0]['outboundTag'],'API')
            caps = {}
            exec((root/'node_autonomy.py').read_text(),caps)
            with patch.dict(sys.modules,{'xray':types.SimpleNamespace(RIME_API_MTLS=True,RIME_API_DIRECT=True,RIME_MANAGEMENT_SOURCES=1)}):
                self.assertEqual(caps['capabilities'](None)['api_mtls'],1)
                self.assertEqual(caps['capabilities'](None)['api_direct'],1)
                self.assertEqual(caps['capabilities'](None)['management_sources'],1)
            with patch.dict(sys.modules,{'xray':types.SimpleNamespace()}):
                self.assertEqual(caps['capabilities'](None)['api_mtls'],0)
                self.assertEqual(caps['capabilities'](None)['api_direct'],0)
            with patch.dict(sys.modules,{'xray':types.SimpleNamespace(RIME_API_MTLS=False)}):
                self.assertEqual(caps['capabilities'](None)['api_mtls'],0)
            self.assertTrue((root/'api_bridge.py').is_file())
            with self.assertRaises(ValueError):
                patcher.patch_api(root)


if __name__=='__main__':
    unittest.main()
