"""Full synthetic panel HTTP control loop across real native REST/GOST hops.

Run inside the panel container of the dedicated internal-network fixture.
No production access records or certificates are used by this qualification.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
import hashlib
import os
from pathlib import Path
import secrets
import shlex
import signal
import socket
import socketserver
import sqlite3
import ssl
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

import grpc
import paramiko
import http.client
import websocket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from xray_api.proto.app.stats.command import command_pb2, command_pb2_grpc


ALICE = '11111111-1111-4111-8111-111111111111'
BOB = '22222222-2222-4222-8222-222222222222'
BOB_NEW = '33333333-3333-4333-8333-333333333333'
PANEL = '172.31.199.2'
NODE = '172.31.199.30'


def wait(check, message, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError):
            pass
        time.sleep(.4)
    raise AssertionError(message)


def exact(stream, size):
    result = b''
    while len(result) < size:
        part = stream.recv(size - len(result))
        if not part:
            raise OSError('Incomplete fixture response')
        result += part
    return result


def opened(address, port, identity, payload=b'hello'):
    stream = socket.create_connection((address, port), timeout=2)
    stream.settimeout(2)
    try:
        request = (b'\x00' + uuid.UUID(identity).bytes + b'\x00\x01' + (18080).to_bytes(2,'big') +
                   b'\x01' + ipaddress.ip_address(PANEL).packed)
        stream.sendall(request + payload)
        assert exact(stream, 2) == b'\x00\x00'
        assert exact(stream, len(payload)) == payload
        return stream
    except BaseException:
        stream.close()
        raise


def allowed(address, port, identity):
    try:
        opened(address, port, identity).close()
        return True
    except (OSError, AssertionError):
        return False


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class UserRpcRelay(socketserver.BaseRequestHandler):
    """Carry a genuine gRPC client's TCP stream through an ordinary VLESS user."""
    def handle(self):
        incoming=self.request
        incoming.settimeout(5)
        remote=None
        try:
            first=incoming.recv(65536)
            if not first:return
            remote=socket.create_connection(self.server.vpn,timeout=3)
            host,port=self.server.destination
            try:encoded=b'\x01'+ipaddress.ip_address(host).packed
            except ValueError:
                domain=host.encode()
                assert 0<len(domain)<256
                encoded=b'\x03'+bytes([len(domain)])+domain
            header=(b'\x00'+uuid.UUID(self.server.identity).bytes+b'\x00\x01'+
                    port.to_bytes(2,'big')+encoded)
            remote.sendall(header+first)
            assert exact(remote,2)==b'\x00\x00'
            def copy(source,destination):
                try:
                    while data:=source.recv(65536):destination.sendall(data)
                except OSError:pass
                finally:
                    for stream in (source,destination):
                        try:stream.shutdown(socket.SHUT_RDWR)
                        except OSError:pass
            thread=threading.Thread(target=copy,args=(incoming,remote),daemon=True)
            thread.start()
            copy(remote,incoming)
            thread.join(timeout=2)
        except (OSError,AssertionError):
            pass
        finally:
            if remote:remote.close()


def verify_user_api_isolation(root, entry, vpn_port):
    transport=grpc.server(ThreadPoolExecutor(max_workers=2))
    handler=grpc.unary_unary_rpc_method_handler(lambda request,context:request)
    transport.add_generic_rpc_handlers((grpc.method_handlers_generic_handler('fixture.Transport',{'Echo':handler}),))
    assert transport.add_insecure_port('0.0.0.0:18444')==18444
    transport.start()

    def channel_to(destination, secure=False):
        relay=socketserver.ThreadingTCPServer(('127.0.0.1',0),UserRpcRelay)
        relay.daemon_threads=True
        relay.vpn=(entry['address'],vpn_port)
        relay.identity=ALICE
        relay.destination=destination
        threading.Thread(target=relay.serve_forever,daemon=True).start()
        address='127.0.0.1:'+str(relay.server_address[1])
        if secure:
            credentials=grpc.ssl_channel_credentials((root/'cert.pem').read_bytes())
            return relay,grpc.secure_channel(address,credentials,options=[('grpc.ssl_target_name_override','Gozargah')])
        return relay,grpc.insecure_channel(address)

    try:
        relay,channel=channel_to((PANEL,18444))
        try:
            assert channel.unary_unary('/fixture.Transport/Echo')(b'user-transport-control',timeout=5)==b'user-transport-control'
        finally:
            channel.close();relay.shutdown();relay.server_close()
        relay,channel=channel_to((NODE,62051),secure=True)
        try:
            command_pb2_grpc.StatsServiceStub(channel).GetSysStats(command_pb2.SysStatsRequest(),timeout=4)
        except grpc.RpcError:
            pass
        else:
            raise AssertionError('A VPN credential bypassed the public API controller-certificate requirement')
        finally:
            channel.close();relay.shutdown();relay.server_close()
        observed=json.loads((root/'node-observation.json').read_text())
        assert not observed['internal_api_ports'],'Native API still exposes a core loopback TCP listener'
        assert set(observed['core_tcp_ports'])=={24443},'Native core exposes an unexpected TCP listener'
        sockets=observed['internal_api_sockets']
        assert len(sockets)==1,'Actual Xray-owned Unix API listener could not be identified'
        endpoint=sockets[0]
        assert endpoint['mode']==0o600 and endpoint['parent_mode']==0o700
        for address in ['unix:'+endpoint['path'],'unix://'+endpoint['path']]:
            relay,channel=channel_to((address,1))
            try:
                command_pb2_grpc.StatsServiceStub(channel).GetSysStats(command_pb2.SysStatsRequest(),timeout=4)
            except grpc.RpcError:
                pass
            else:
                raise AssertionError('Ordinary VLESS user reached the private Unix control API')
            finally:
                channel.close();relay.shutdown();relay.server_close()
    finally:
        transport.stop(0).wait()


class Api:
    def __init__(self, root):
        self.root = root
        self.context = ssl.create_default_context(cafile=str(root/'cert.pem'))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPSHandler(context=self.context))
        self.token = None

    def call(self, path, data=None, method=None, raw=False):
        headers = {}
        body = None
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        if data is not None:
            if path == '/api/admin/token':
                body = urllib.parse.urlencode(data).encode()
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            elif isinstance(data, bytes):
                body = data
                headers['Content-Type'] = 'application/gzip'
            else:
                body = json.dumps(data).encode()
                headers['Content-Type'] = 'application/json'
        request = urllib.request.Request('https://' + PANEL + ':8000' + path, data=body,
                                         headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors='replace')
            raise AssertionError('HTTP ' + str(error.code) + ' for ' + path + ': ' + detail) from None
        with response:
            value = response.read()
        return value if raw else json.loads(value)

    def login(self):
        value = self.call('/api/admin/token', {'username':'fixture_admin',
                                              'password':'Synthetic-REST-Management-Password'})
        self.token = value['access_token']
        return True

    def job(self, identity, expected='succeeded'):
        def finished():
            value = self.call('/api/fleet/relays/jobs/' + identity)
            return value if value['state'] != 'running' else None
        value = wait(finished, 'Relay operation did not finish', 120)
        assert value['state'] == expected, value['message']
        return value


def verify_api_mtls(root, address, rest_port, api_port):
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Untrusted fixture client')])
    now = datetime.now(timezone.utc)
    wrong_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(wrong_key.public_key())
                  .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
                  .not_valid_after(now+timedelta(days=1)).sign(wrong_key,hashes.SHA256()))
    cert = wrong_cert.public_bytes(serialization.Encoding.PEM)
    key = wrong_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    (root/'untrusted-cert.pem').write_bytes(cert)
    (root/'untrusted-key.pem').write_bytes(key)
    for wrong in (False, True):
        context = ssl.create_default_context(cafile=str(root/'cert.pem'))
        context.check_hostname = False
        if wrong:
            context.load_cert_chain(root/'untrusted-cert.pem',root/'untrusted-key.pem')
        connection = http.client.HTTPSConnection(address,rest_port,context=context,timeout=3)
        try:
            connection.request('POST','/ping','{}',{'Content-Type':'application/json'})
            response = connection.getresponse()
            response.read()
        except (ssl.SSLError,ConnectionResetError):
            pass
        else:
            raise AssertionError('Native REST accepted an absent or foreign client certificate')
        finally:
            connection.close()
        credentials = grpc.ssl_channel_credentials((root/'cert.pem').read_bytes(),
            private_key=key if wrong else None, certificate_chain=cert if wrong else None)
        channel = grpc.secure_channel(address+':'+str(api_port),credentials,
            options=[('grpc.ssl_target_name_override','Gozargah')])
        try:
            command_pb2_grpc.StatsServiceStub(channel).GetSysStats(command_pb2.SysStatsRequest(),timeout=3)
        except grpc.RpcError:
            pass
        else:
            raise AssertionError('Native Xray API accepted an absent or foreign client certificate')
        finally:
            channel.close()
    credentials = grpc.ssl_channel_credentials((root/'cert.pem').read_bytes(),
        private_key=(root/'key.pem').read_bytes(),certificate_chain=(root/'cert.pem').read_bytes())
    channel = grpc.secure_channel(address+':'+str(api_port),credentials,
        options=[('grpc.ssl_target_name_override','Gozargah')])
    try:
        command_pb2_grpc.StatsServiceStub(channel).GetSysStats(command_pb2.SysStatsRequest(),timeout=5)
    finally:
        channel.close()


def main(args):
    root = Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    assert os.environ.get('RIME_REST_MANAGEMENT_FIXTURE') in ('20261119','20261120')
    assert Path('/.dockerenv').is_file() and '/work/rest/bootstrap_panel.py' in Path('/proc/1/cmdline').read_bytes().decode()
    results = []
    api = Api(root)

    def passed(message, **extra):
        results.append({'name':message,'passed':True,**extra})
        print('PASS ' + message, flush=True)
        (root/'qualification.json').write_text(json.dumps({'checks':results,'closed_network':True},indent=2))

    class Payload(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            body = json.dumps({'ip':self.client_address[0]}).encode()
            self.send_response(200)
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    echo = socketserver.ThreadingTCPServer(('0.0.0.0',18080),Echo)
    echo.daemon_threads = True
    payload = ThreadingHTTPServer(('0.0.0.0',18443),Payload)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root/'cert.pem',root/'key.pem')
    payload.socket = context.wrap_socket(payload.socket,server_side=True)
    for server in [echo,payload]:
        threading.Thread(target=server.serve_forever,daemon=True).start()
    held = None
    stopped = None
    try:
        wait(api.login, 'The real fixture panel did not become ready', 90)
        native = api.call('/api/node', {'name':'REST fixture','address':NODE,'port':62050,
                                       'api_port':62051,'add_as_new_host':True,'expected_server_certificate':(root/'cert.pem').read_text()})
        node_id = native['id']
        node = 'xray:' + str(node_id)
        api.call('/_fixture/observer/'+str(node_id),{},method='POST')
        wait(lambda: api.call('/api/node/' + str(node_id))['status'] == 'connected',
             'Native REST did not connect directly')
        for name,identity in [('fixture_probe',str(uuid.uuid4())),('alice',ALICE)]:
            api.call('/api/user', {'username':name,'proxies':{'vless':{'id':identity}},
                                  'inbounds':{'vless':['LAB_VLESS']},'status':'active','data_limit':0,'expire':0})
        wait(lambda:allowed(NODE,24443,ALICE), 'HTTP-created Alice did not reach native Xray')
        held = opened(NODE,24443,ALICE)
        pid = wait(lambda:json.loads((root/'node-observation.json').read_text())['core_pids'],
                   'Native core process was not observed')
        with sqlite3.connect(root/'panel/db.sqlite3') as db:
            hosts = [row[0] for row in db.execute('SELECT id FROM hosts WHERE address=?',(NODE,))]
        assert hosts
        api.call('/api/fleet/nodes/' + node, {'name':'REST fixture','host_ids':hosts},method='PUT')
        config = json.loads((root/'panel-xray.json').read_text())
        config['inbounds'][0]['listen'] = '0.0.0.0'
        package = io.BytesIO()
        with tarfile.open(fileobj=package,mode='w:gz') as archive:
            raw = json.dumps(config).encode()
            member = tarfile.TarInfo('node/xray_config.json');member.size=len(raw)
            archive.addfile(member,io.BytesIO(raw))
        api.call('/api/fleet/nodes/' + node + '/recovery/import', package.getvalue())
        old_url = api.call('/api/user/alice')['subscription_url']
        old_path = urllib.parse.urlsplit(old_url).path
        assert api.call(old_path,raw=True)
        passed('full panel HTTP creates a native '+args.protocol.upper()+' connection and a real VLESS user')

        password = json.loads((root/'credentials.json').read_text())['password']
        entries = []
        for index,address in enumerate(['172.31.199.10','172.31.199.11']):
            identity = wait(lambda:api.call('/api/fleet/provision/host-key', {'host':address,'ssh_port':22}),
                            'Fixture entry SSH did not become ready')
            access = {'host':address,'address':address,'ssh_port':22,'username':'root',
                      'password':password,'fingerprint':identity['fingerprint']}
            plan = api.call('/api/fleet/relays/entry/plan', {**access,'name':'Entry '+str(index+1),'domain':address,
                                                           'control_port':62080,'metrics_port':62081,'api_port':62082})
            job = api.call('/api/fleet/relays/deploy', {'plan_id':plan['id']})
            api.job(job['id'])
            entries.append({'id':plan['id'],'address':address,'access':access})
        wait(lambda:all(e.get('fresh') for e in api.call('/api/fleet/relays')['entries']),
             'Entry telemetry did not arrive', 35)
        def entry_commands(target, commands):
            class ApprovedFixtureKey(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, client, hostname, key):
                    fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
                    assert fingerprint==target['access']['fingerprint'],'Fixture SSH host key changed'
            client=paramiko.SSHClient()
            client.set_missing_host_key_policy(ApprovedFixtureKey())
            client.connect(target['address'],username='root',password=password,allow_agent=False,look_for_keys=False,timeout=10)
            try:
                for command in commands:
                    _,out,err=client.exec_command(shlex.join(command),timeout=20)
                    out.read()
                    assert out.channel.recv_exit_status()==0,err.read().decode(errors='replace')
            finally:
                client.close()
        plan = api.call('/api/fleet/relays/route/plan', {'node':node,'entry':entries[0]['id'],
            'origin':NODE,'include_proxies':False,'management':True,'ssh_port':None})
        route = plan['id']
        api.job(api.call('/api/fleet/relays/deploy',{'plan_id':route})['id'])

        def mapping():
            catalog=api.call('/api/fleet/relays')
            current=next(value for value in catalog['tunnels'] if value['id']==route)
            entry=next(value for value in catalog['entries'] if value['id']==current['entry'])
            return current,entry,{(value['kind'],value['origin_port']):value['public_port'] for value in current['services']}

        def native_connected():
            return api.call('/api/node/'+str(node_id))['status']=='connected'

        def management_usable(message):
            current,entry,ports=mapping()
            def selected_controller():
                actual=api.call('/_fixture/controller').get(str(node_id),{})
                return actual.get('address')==entry['address'] and actual.get('port')==ports['management',62050] and actual.get('api_port')==ports['management',62051] and actual.get('started') and native_connected()
            wait(selected_controller, 'Panel controller stayed on the previous entry endpoint', 45)
            probe_user='probe_'+secrets.token_hex(4)
            identity=str(uuid.uuid4())
            api.call('/api/user',{'username':probe_user,'proxies':{'vless':{'id':identity}},
                'inbounds':{'vless':['LAB_VLESS']},'status':'active','data_limit':0,'expire':0})
            wait(lambda:allowed(entry['address'],ports['vpn',24443],identity), message, 25)
            api.call('/api/user/'+probe_user,method='DELETE')
            wait(lambda:not allowed(entry['address'],ports['vpn',24443],identity), 'Deleted test user remains allowed')
            return current,entry,ports

        current,entry,ports=management_usable('User RPC did not pass through the first entry')
        usage_epoch=api.call('/_fixture/controller')[str(node_id)]['usage_epoch']
        assert isinstance(usage_epoch,str) and usage_epoch,'Qualified cumulative usage epoch is unavailable'
        passed('real panel control and Xray gRPC user mutations travel through the first entry')
        verify_user_api_isolation(root,entry,ports['vpn',24443])
        passed('ordinary VLESS user transports gRPC echo but cannot access the private Unix API and its restricted socket')
        verify_api_mtls(root,entry['address'],ports['management',62050],ports['management',62051])
        passed('native control and gRPC reject missing or foreign client certificates and accept the panel certificate')

        # User changes must reach the native core while another user keeps a stream.
        api.call('/api/user',{'username':'bob','proxies':{'vless':{'id':BOB}},
            'inbounds':{'vless':['LAB_VLESS']},'status':'active','data_limit':0,'expire':0})
        wait(lambda:allowed(entry['address'],ports['vpn',24443],BOB),'Bob create was not applied')
        api.call('/api/user/bob',{'proxies':{'vless':{'id':BOB_NEW}}},method='PUT')
        wait(lambda:allowed(entry['address'],ports['vpn',24443],BOB_NEW) and not allowed(entry['address'],ports['vpn',24443],BOB),'UUID update was not applied')
        api.call('/api/user/bob',{'status':'disabled'},method='PUT')
        wait(lambda:not allowed(entry['address'],ports['vpn',24443],BOB_NEW),'Disabled Bob remains admitted')
        api.call('/api/user/bob',{'status':'active'},method='PUT')
        wait(lambda:allowed(entry['address'],ports['vpn',24443],BOB_NEW),'Re-enabled Bob remains blocked')
        api.call('/api/user/bob',method='DELETE')
        wait(lambda:not allowed(entry['address'],ports['vpn',24443],BOB_NEW),'Deleted Bob remains admitted')
        held.sendall(b'unchanged-alice');assert exact(held,15)==b'unchanged-alice'
        assert json.loads((root/'node-observation.json').read_text())['core_pids']==pid
        assert api.call('/_fixture/controller')[str(node_id)]['usage_epoch']==usage_epoch
        passed('HTTP create, UUID change, disable, enable and delete apply without restarting the native core')

        before=api.call('/api/user/alice')['used_traffic']
        payload_data=secrets.token_bytes(65536)
        held.sendall(payload_data);assert exact(held,len(payload_data))==payload_data
        wait(lambda:api.call('/api/user/alice')['used_traffic']>before,'The real usage job did not persist traffic',15)
        time.sleep(3)
        counted=api.call('/api/user/alice')['used_traffic']
        time.sleep(5)
        assert api.call('/api/user/alice')['used_traffic']==counted
        epoch_hash=hashlib.sha256(usage_epoch.encode()).hexdigest()
        with sqlite3.connect(root/'panel/db.sqlite3') as db:
            rows=db.execute('SELECT epoch,kind,value FROM fleet_native_usage_cursors WHERE node_id=?',(node_id,)).fetchall()
        assert rows and {row[0] for row in rows}=={epoch_hash}
        assert {row[1] for row in rows}=={'users','outbound'}
        passed('the real scheduled usage collector persists traffic and repeated idle polls do not double-charge')

        def switch(target):
            plan=api.call('/api/fleet/relays/routes/'+route+'/switch/plan',{'entry':target['id'],'grace_seconds':0})
            return api.job(api.call('/api/fleet/relays/deploy',{'plan_id':plan['id']})['id'])

        switch(entries[1])
        current,entry,ports=management_usable('Healthy switch did not rebind actual controller RPCs to Entry B')
        assert current['entry']==entries[1]['id']
        assert api.call(old_path,raw=True)
        assert api.call('/api/user/alice')['proxies']['vless']['id']==ALICE
        assert json.loads((root/'node-observation.json').read_text())['core_pids']==pid
        assert api.call('/_fixture/controller')[str(node_id)]['usage_epoch']==usage_epoch
        held.sendall(b'healthy-switch');assert exact(held,14)==b'healthy-switch'
        passed('a healthy entry switch moves real '+args.protocol.upper()+' and gRPC control while old entry still exists and preserves signed URL and core PID')
        logs=websocket.create_connection('wss://'+PANEL+':8000/api/node/'+str(node_id)+'/logs?token='+api.token+'&interval=0.1',
            sslopt={'ca_certs':str(root/'cert.pem')},timeout=8,http_no_proxy=['*'])
        try:
            opened(NODE,24443,ALICE).close()
            message=logs.recv()
            assert isinstance(message,str) and message
        finally:
            logs.close()
        passed('the actual panel logs websocket receives native core logs through the replacement entry')
        limited_id=str(uuid.uuid4())
        api.call('/api/user',{'username':'limited_user','proxies':{'vless':{'id':limited_id}},
            'inbounds':{'vless':['LAB_VLESS']},'status':'active','data_limit':1024,'expire':0})
        wait(lambda:allowed(entry['address'],ports['vpn',24443],limited_id),'Quota fixture user was not admitted')
        opened(entry['address'],ports['vpn',24443],limited_id,b'x'*8192).close()
        wait(lambda:api.call('/api/user/limited_user')['status']=='limited','Quota review did not disable exhausted user',20)
        wait(lambda:not allowed(entry['address'],ports['vpn',24443],limited_id),'Exhausted user still opens native sessions')
        api.call('/api/user/limited_user',method='DELETE')
        expiring_id=str(uuid.uuid4())
        api.call('/api/user',{'username':'expiring_user','proxies':{'vless':{'id':expiring_id}},
            'inbounds':{'vless':['LAB_VLESS']},'status':'active','data_limit':0,'expire':int(time.time()+5)})
        wait(lambda:allowed(entry['address'],ports['vpn',24443],expiring_id),'Expiry fixture user was not admitted')
        wait(lambda:api.call('/api/user/expiring_user')['status']=='expired','Expiry review did not change user status',20)
        wait(lambda:not allowed(entry['address'],ports['vpn',24443],expiring_id),'Expired user still opens native sessions')
        api.call('/api/user/expiring_user',method='DELETE')
        held.sendall(b'quota-neighbor');assert exact(held,14)==b'quota-neighbor'
        passed('the real usage and expiry reviewers revoke exhausted and expired users through the new entry')

        for blocked_origin in (62050,62051):
            current_before,_,_=mapping()
            plan=api.call('/api/fleet/relays/routes/'+route+'/switch/plan',{'entry':entries[0]['id'],'grace_seconds':0})
            public_port=next(service['public_port'] for service in plan['services']
                             if service['kind']=='management' and service['origin_port']==blocked_origin)
            reject=['iptables','-I','INPUT','1','-p','tcp','--dport',str(public_port),'-j','REJECT']
            entry_commands(entries[0],[reject])
            try:
                api.job(api.call('/api/fleet/relays/deploy',{'plan_id':plan['id']})['id'],expected='rolled_back')
            finally:
                entry_commands(entries[0],[['iptables','-D','INPUT',*reject[4:]]])
            current,entry,ports=management_usable('Failed management precheck changed the working controller')
            assert current['entry']==current_before['entry']==entries[1]['id']
            held.sendall(b'management-failure');assert exact(held,18)==b'management-failure'
            passed('a new entry with working VPN but blocked management port '+str(blocked_origin)+' is rejected before publication')

        old=entries[1]
        entry_commands(old,[['systemctl','stop','rime-relay-'+old['id']],
                            ['iptables','-I','INPUT','1','-p','tcp','--dport','62080','-j','DROP']])
        stopped=old
        held.sendall(b'control-gone');assert exact(held,12)==b'control-gone'
        outcome=switch(entries[0])
        assert outcome['context']['old_cleanup_pending']
        current,entry,ports=management_usable('Dead-old switch did not restore real controller RPCs')
        assert current['entry']==entries[0]['id']
        assert json.loads((root/'node-observation.json').read_text())['core_pids']==pid
        assert api.call('/_fixture/controller')[str(node_id)]['usage_epoch']==usage_epoch
        assert api.call(old_path,raw=True)
        idle=api.call('/api/user/alice')['used_traffic'];time.sleep(5)
        assert api.call('/api/user/alice')['used_traffic']==idle
        with sqlite3.connect(root/'panel/db.sqlite3') as db:
            epochs={row[0] for row in db.execute('SELECT DISTINCT epoch FROM fleet_native_usage_cursors WHERE node_id=?',(node_id,))}
        assert epochs=={epoch_hash},'Entry switch changed the durable native counter epoch'
        held.sendall(b'dead-switch');assert exact(held,11)==b'dead-switch'
        passed('old entry outage keeps native VLESS alive and emergency switch restores HTTP CRUD and statistics without counter reset')
        entry_commands(old,[['iptables','-D','INPUT','-p','tcp','--dport','62080','-j','DROP'],
                            ['systemctl','start','rime-relay-'+old['id']]])
        wait(lambda:socket.create_connection((old['address'],62080),timeout=.5).close() is None,
             'Returned old entry control listener did not start',15)
        before_cleanup=json.loads((root/'node-observation.json').read_text())['connect_requests']
        with sqlite3.connect(root/'panel/db.sqlite3') as db:
            db.execute("UPDATE fleet_relay_switches SET retry_at=0 WHERE phase='cleanup_pending'")
        api.job(api.call('/api/fleet/relays/routes/'+route+'/check',{},method='POST')['id'])
        wait(lambda:not mapping()[0].get('old_cleanup_pending'), 'Returned old rules were not cleaned',15)
        assert json.loads((root/'node-observation.json').read_text())['connect_requests']==before_cleanup
        current,entry,ports=management_usable('Old cleanup disturbed the selected control endpoint')
        assert current['entry']==entries[0]['id']
        assert json.loads((root/'node-observation.json').read_text())['core_pids']==pid
        assert api.call('/_fixture/controller')[str(node_id)]['usage_epoch']==usage_epoch
        passed('returning old entry cleanup preserves the replacement controller connection and native core')
        time.sleep(3)
        before_pause=api.call('/api/user/alice')['used_traffic']
        offline_payload=secrets.token_bytes(32768)
        try:
            os.kill(1,signal.SIGSTOP)
            held.sendall(b'panel-paused');assert exact(held,12)==b'panel-paused'
            opened(entry['address'],ports['vpn',24443],ALICE,offline_payload).close()
            time.sleep(5)
            held.sendall(b'panel-still-paused');assert exact(held,18)==b'panel-still-paused'
            assert json.loads((root/'node-observation.json').read_text())['core_pids']==pid
        finally:
            os.kill(1,signal.SIGCONT)
        wait(api.login,'The paused panel did not resume',15)
        wait(lambda:api.call('/api/user/alice')['used_traffic']>=before_pause+65536,'Cumulative traffic while panel was paused was not recovered',20)
        time.sleep(3)
        resumed_usage=api.call('/api/user/alice')['used_traffic'];time.sleep(5)
        assert api.call('/api/user/alice')['used_traffic']==resumed_usage
        assert api.call('/_fixture/controller')[str(node_id)]['usage_epoch']==usage_epoch
        passed('paused actual panel leaves existing and new VPN sessions working and cumulative usage catches up once')
        result={'checks':results,'closed_network':True,'production_touched':False,'actual_panel_http':True,
                'durable_native_usage_cursors':True,'stats_epoch_preserved':True,
                'node_protocol':args.protocol,'node':NODE,'old_entry':entries[1]['address'],'new_entry':entries[0]['address']}
        (root/'qualification.json').write_text(json.dumps(result,indent=2))
    finally:
        if held:held.close()
        for server in [echo,payload]:server.shutdown();server.server_close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path,required=True);parser.add_argument('--protocol',choices=['rest','rpyc'],default='rest')
    main(parser.parse_args())
