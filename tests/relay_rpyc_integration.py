"""Real RPyC and gRPC management across two isolated GOST entries."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import sys
import threading
import time
from types import ModuleType
from unittest.mock import patch
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ALICE = '11111111-1111-4111-8111-111111111111'
BOB = '22222222-2222-4222-8222-222222222222'
BOB_NEW = '33333333-3333-4333-8333-333333333333'


def wait(check, message, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.1)
    raise AssertionError(message)


def certificates(root):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'RPyC qualification CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
          .not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
          .sign(ca_key,hashes.SHA256()))
    for name, common in [('server','Gozargah'),('client','fixture-panel')]:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,common)])
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject if name=='server' else ca_name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
                   .not_valid_after(now+timedelta(days=1)))
        if name == 'server':
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('Gozargah'),
                x509.IPAddress(ipaddress.ip_address('172.30.99.2'))]),critical=False)
        cert = builder.sign(key if name == 'server' else ca_key,hashes.SHA256())
        (root/(name+'.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root/(name+'.key')).write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (root/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))


class PanelConfig(dict):
    def to_json(self):
        return json.dumps(self)


def wrapper():
    annotation = ModuleType('app.xray.config')
    annotation.XRayConfig = PanelConfig
    sys.modules['app.xray.config'] = annotation
    path = Path(__file__).resolve().parents[1]/'app/xray/node.py'
    spec = importlib.util.spec_from_file_location('rpyc_qualification_controller',path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.RPyCXRayNode


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


def opened(address, identity, payload=b'initial-payload'):
    stream = socket.create_connection((address,16443),timeout=3)
    stream.settimeout(3)
    try:
        stream.sendall(bytes([0])+uuid.UUID(identity).bytes+bytes([0,1])+(18080).to_bytes(2,'big')+
                       bytes([1,127,0,0,1])+payload)
        assert stream.recv(2) == b'\x00\x00'
        result = b''
        while len(result) < len(payload):
            block = stream.recv(len(payload)-len(result))
            if not block:
                break
            result += block
        assert result == payload
        return stream
    except BaseException:
        stream.close()
        raise


def fresh(address, identity):
    try:
        opened(address,identity).close()
        return True
    except (OSError,AssertionError):
        return False


def continuing(stream):
    try:
        stream.sendall(b'continuing')
        return stream.recv(10) == b'continuing'
    except OSError:
        return False


def main(args):
    root = Path(args.work)
    root.mkdir(parents=True,exist_ok=True)
    certificates(root)
    os.environ.update(SSL_CERT_FILE=str(root/'server.pem'),SSL_KEY_FILE=str(root/'server.key'),
        SSL_CLIENT_CERT_FILE=str(root/'ca.pem'),XRAY_API_HOST='0.0.0.0',XRAY_API_PORT='62051',
        XRAY_EXECUTABLE_PATH='/opt/rime-probe/xray',INBOUNDS='vpn')
    sys.path.insert(0,args.native)
    import rpyc_service
    from rpyc.utils.authenticators import SSLAuthenticator
    from rpyc.utils.server import ThreadedServer
    from xray_api.types import VLESSAccount

    service = rpyc_service.XrayService()
    authenticator = SSLAuthenticator(keyfile=str(root/'server.key'),certfile=str(root/'server.pem'),
                                     ca_certs=str(root/'ca.pem'))
    rpc = ThreadedServer(service,hostname='0.0.0.0',port=62050,authenticator=authenticator)
    rpc_thread = threading.Thread(target=rpc.start,daemon=True)
    rpc_thread.start()
    echo = socketserver.ThreadingTCPServer(('127.0.0.1',18080),Echo)
    echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever,daemon=True).start()
    node_type = wrapper()
    config = PanelConfig({'log':{'loglevel':'warning'},'inbounds':[{'listen':'0.0.0.0','port':16443,
        'tag':'vpn','protocol':'vless','settings':{'clients':[{'id':ALICE,'email':'alice','level':0}],'decryption':'none'}}],
        'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
        'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'type':'field','ip':['127.0.0.1/32'],'action':'allow'}]}}]})
    results = []
    nodes = []
    held = []

    def passed(message):
        results.append(message)
        print('PASS '+message,flush=True)

    def controller(address):
        node = node_type(address,62450,62451,(root/'client.key').read_text(),(root/'client.pem').read_text(),
                         control_address='172.30.99.2',control_api_port=62051)
        nodes.append(node)
        return node

    def counters(node):
        return {(value.name,value.link):value.value for value in node.api.get_users_stats(reset=False,timeout=3)}

    def usage_epoch(node):
        epoch = node.api.usage_epoch
        return epoch() if callable(epoch) else epoch

    def management_check(qualified=True, api_port=62451):
        from hy2bridge.native_management import probe_management
        profile = {'vpn':{'management_protocol':'rpyc','management_tls':{'certificate':(root/'server.pem').read_text()}}}
        if qualified:
            profile['vpn']['management_auth'] = 'controller-mtls-v1'
        services = [{'id':'rpc','kind':'management','origin_port':62050,'public_port':62450},
                    {'id':'api','kind':'management','origin_port':62051,'public_port':api_port}]
        source = {'native':{'id':1,'address':'172.30.99.2','port':62050,'api_port':62051}}
        with patch('hy2bridge.native_management.cached_node',return_value=None):
            return probe_management(source,profile,{'address':'172.30.99.4'},services,
                lambda:((root/'client.key').read_text(),(root/'client.pem').read_text()))

    try:
        wait(lambda: rpc.active, 'RPyC listener did not start')
        node = controller('172.30.99.3')
        node.start(copy.deepcopy(config))
        wait(lambda:fresh('172.30.99.3',ALICE),'Initial VLESS did not pass through entry A')
        assert service.connection.peer == '172.30.99.3'
        pid = service.core.process.pid
        a = opened('172.30.99.3',ALICE)
        held.append(a)
        if args.baseline:
            assert node._api_mtls is False
            assert node._stats_epoch is None
            result = management_check(qualified=False)
            assert result['passed'] is False and result['stage']=='configuration'
            assert node.connected and continuing(a)
            passed('legacy RPyC management is rejected before a side-effecting validation connection')
            node.disconnect()
            wait(lambda:not service.core or not service.core.started,'Original RPyC did not reproduce its disconnect defect')
            assert not continuing(a)
            passed('original RPyC disconnect stops the real VLESS core and held stream')
        else:
            assert node._api_mtls is True
            epoch = node._stats_epoch
            assert isinstance(epoch,str) and epoch and usage_epoch(node)==epoch
            passed('real RPyC and mTLS gRPC connect through the first GOST entry')
            node.api.add_inbound_user('vpn',VLESSAccount(email='bob',id=BOB),timeout=3)
            wait(lambda:fresh('172.30.99.3',BOB),'Added user cannot connect')
            node.api.remove_inbound_user('vpn','bob',timeout=3)
            node.api.add_inbound_user('vpn',VLESSAccount(email='bob',id=BOB_NEW),timeout=3)
            assert not fresh('172.30.99.3',BOB) and fresh('172.30.99.3',BOB_NEW)
            node.api.remove_inbound_user('vpn','bob',timeout=3)
            assert not fresh('172.30.99.3',BOB_NEW)
            assert continuing(a)
            passed('real user add UUID change and removal enforce new VLESS sessions')
            before = counters(node)
            assert sum(before.values()) > 0
            passed('real user traffic counters are available through the forwarded mTLS API')
            context = ssl.create_default_context(cafile=str(root/'server.pem'))
            context.check_hostname = False
            context.load_cert_chain(str(root/'client.pem'),str(root/'client.key'))
            with socket.create_connection(('172.30.99.4',62450),timeout=3) as raw:
                with context.wrap_socket(raw,server_hostname='Gozargah'):
                    pass
            time.sleep(.3)
            assert node.connected and service.core.process.pid == pid and continuing(a)
            passed('a read-only mTLS probe through another entry preserves controller ownership and VPN')
            checked = management_check()
            assert checked['passed'] is True and checked['management_passed'] is True
            assert node.connected and service.core.process.pid == pid and continuing(a)
            passed('prepublication management gate reads real RPyC capabilities and mTLS gRPC stats without claiming ownership')
            failed = management_check(api_port=62459)
            assert failed['passed'] is False and failed['stage']=='api'
            assert node.connected and service.core.process.pid == pid and continuing(a)
            passed('a failed candidate API port leaves the existing RPyC controller and payload untouched')
            previous = node
            node = controller('172.30.99.4')
            node.start(copy.deepcopy(config))
            assert node.connected and service.core.process.pid == pid and continuing(a)
            try:
                previous.stop()
            except (ConnectionError,EOFError,OSError):
                pass
            else:
                raise AssertionError('The former controller retained mutation ownership')
            previous.disconnect()
            assert node.connected and service.core.process.pid == pid and continuing(a)
            passed('explicit takeover fences the former controller while its read-only reconnect preserves the new owner')
            node.disconnect()
            wait(lambda:service.connection is None,'Disconnected controller session was not released')
            assert continuing(a) and fresh('172.30.99.3',ALICE)
            desired = copy.deepcopy(config)
            desired['inbounds'][0]['settings']['clients'].append({'id':BOB,'email':'bob','level':0})
            node = controller('172.30.99.3')
            node.start(desired)
            assert service.core.process.pid == pid and continuing(a) and fresh('172.30.99.3',BOB)
            assert node._stats_epoch==epoch and usage_epoch(node)==epoch
            passed('reconnected RPyC reconciles an offline user addition without restarting Xray')
            node.disconnect()
            wait(lambda:service.connection is None,'Controller release for revocation failed')
            node = controller('172.30.99.3')
            node.start(copy.deepcopy(config))
            assert service.core.process.pid == pid and continuing(a) and not fresh('172.30.99.3',BOB)
            passed('reconnected RPyC enforces an offline revocation without restarting Xray')
            b = opened('172.30.99.4',ALICE)
            held.append(b)
            stats_before_failure = counters(node)
            (root/'stop-old-entry.request').write_text('ready')
            wait(lambda:(root/'old-entry-stopped.ack').exists(),'Host did not stop old GOST entry',seconds=45)
            wait(lambda:service.connection is None,'Lost old entry did not release control session')
            assert service.core.process.pid == pid and continuing(b) and fresh('172.30.99.4',ALICE)
            replacement = controller('172.30.99.4')
            replacement.start(copy.deepcopy(config))
            assert replacement.connected and service.core.process.pid == pid and continuing(b)
            assert service.connection.peer == '172.30.99.4'
            assert replacement._stats_epoch==epoch and usage_epoch(replacement)==epoch
            after = counters(replacement)
            assert all(after.get(key,0) >= value for key,value in stats_before_failure.items())
            passed('dead old entry is replaced through the second entry with the same core key and unread counters')
            replacement.api.add_inbound_user('vpn',VLESSAccount(email='bob',id=BOB_NEW),timeout=3)
            assert fresh('172.30.99.4',BOB_NEW)
            replacement.api.remove_inbound_user('vpn','bob',timeout=3)
            assert not fresh('172.30.99.4',BOB_NEW)
            passed('user management and statistics continue through the replacement entry')
            replacement.stop()
            wait(lambda:service.core is None or not service.core.started,'Explicit stop failed')
            assert not fresh('172.30.99.4',ALICE)
            replacement.start(copy.deepcopy(config))
            assert fresh('172.30.99.4',ALICE) and service.core.process.pid != pid
            assert replacement._stats_epoch and replacement._stats_epoch!=epoch
            passed('explicit stop remains effective and a subsequent start restores the original key')
            passed('counter epoch persists across entry takeover and changes only with the real Xray process')
        report = {'passed':results,'baseline':args.baseline,'closed_network':True,
                  'real_rpyc':True,'real_xray':True,'distinct_entry_source_ips':True,'production_touched':False}
        (root/'result.json').write_text(json.dumps(report,indent=2))
    finally:
        for stream in held:
            stream.close()
        for node in nodes:
            try:node.disconnect()
            except Exception:pass
        if service.core and service.core.started:
            service.core.stop()
        rpc.close()
        echo.shutdown()
        echo.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--native',required=True)
    parser.add_argument('--work',required=True)
    parser.add_argument('--baseline',action='store_true')
    main(parser.parse_args())
