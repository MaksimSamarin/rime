"""Closed-network qualification against an SSH/systemd target and real GOST/Squid.

Run inside the network namespace of the disposable systemd SSH arena. The arena
must have the qualified proxy image loaded and no external network interface.
All credentials, certificates, accounts and endpoints are generated fixtures.
"""
import argparse
import copy
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from hy2bridge.provision import Provisioner
from hy2bridge.provision import ProvisionError
from hy2bridge.proxy_delete import ProxyDeletion
from hy2bridge.proxy_service import ProxyService
from hy2bridge.registry import Registry
from hy2bridge.relays import Relays
from hy2bridge.relay_control import forwarding_service
from hy2bridge.store import Store


def wait(check,message,seconds=45):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if check():return
        time.sleep(.5)
    raise AssertionError(message)


def certificate(root):
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Isolated relay fixture')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
        .not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('exit.lab.invalid'),
            *[x509.IPAddress(ipaddress.ip_address(value)) for value in ['127.0.0.1','127.0.0.2','127.0.0.3','172.17.0.1']]]),critical=False)
        .sign(key,hashes.SHA256()))
    (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))


def qualify_switches(relays, provision, store, access, entry_id, route_id, sources, profiles, proxy_id, passed):
    """Exercise entry replacement using two actual systemd forwarding services."""
    entry_a = relays.entry(entry_id)
    entry_access = {**access, 'host':'127.0.0.3'}
    entry_access.update(provision.scan('127.0.0.3', 22))
    plan = relays.plan_entry({**entry_access, 'name':'Replacement entry', 'domain':'127.0.0.3',
                             'control_port':62180, 'metrics_port':62181, 'api_port':62182})
    relays.deploy(plan['id'])
    wait(lambda: relays.job(plan['id'])['state'] != 'running', 'Second entry installation timed out')
    if relays.job(plan['id'])['state'] != 'succeeded':
        raise AssertionError(relays.job(plan['id'])['message'])
    entry_b_id = plan['id']
    wait(lambda: bool(relays.entry(entry_b_id)['seen_at']), 'Second entry observations did not arrive', 40)

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            while value := self.request.recv(65536):
                self.request.sendall(value)

    echo = socketserver.ThreadingTCPServer(('127.0.0.2', 28443), Echo)
    echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    control_a = relays.control(entry_a)
    control_a.add(forwarding_service('switch-peer', 28444, '127.0.0.2', 28443, 'tcp'))
    control_a.save()
    prior_endpoint = copy.deepcopy(relays.endpoint_map('xray:1'))
    prior_password = relays.proxies.connection_info(proxy_id)['password']
    peer_endpoint = copy.deepcopy(relays.endpoint_map('xray:2'))
    blocked_old_control = False

    def run_on_arena(arguments, required=True):
        with provision.connect(dict(access)) as client:
            _, output, errors = client.exec_command(shlex.join(arguments), timeout=20)
            output.read(); errors.read()
            if required and output.channel.recv_exit_status():
                raise AssertionError('The isolated arena command failed')

    def switch(target, identity=route_id, grace_seconds=0):
        plan = relays.switches.plan(identity, target, grace_seconds)
        relays.deploy(plan['id'])
        wait(lambda: relays.job(plan['id'])['state'] != 'running', 'Entry switch timed out', 100)
        value = relays.job(plan['id'])
        if value['state'] != 'succeeded':
            raise AssertionError(value['message'])
        progress = value['context']['progress']
        if progress['completed'] != progress['total'] or progress['total'] != 7:
            raise AssertionError('A finished switch did not complete its published progress')
        return value

    def verify_current():
        with store.connection() as database:
            route = dict(database.execute('SELECT * FROM fleet_tunnels WHERE id=?', (route_id,)).fetchone())
        relays.verify_route(sources['xray:1'], profiles['xray:1'], relays.entry(route['entry']),
                            '127.0.0.2', list(relays.endpoint_map('xray:1').values()))
        if relays.proxies.connection_info(proxy_id)['password'] != prior_password:
            raise AssertionError('Entry switch changed the saved proxy password')
        if relays.direct_target('xray:1') != '127.0.0.2':
            raise AssertionError('Entry switch changed the physical exit')
        with store.connection() as database:
            if database.execute('SELECT used_traffic FROM users WHERE id=1').fetchone()[0] != 12345:
                raise AssertionError('Entry switch charged the VPN user a second time')

    try:
        with socket.create_connection(('127.0.0.1', 28444)) as held:
            held.settimeout(5)
            held.sendall(b'healthy-switch-before')
            if held.recv(4096) != b'healthy-switch-before':
                raise AssertionError('Peer stream did not start before switch')
            result = switch(entry_b_id,grace_seconds=86400)
            verify_current()
            if {row['entry'] for row in relays.endpoint_map('xray:1').values()} != {entry_b_id}:
                raise AssertionError('The verified replacement entry was not published')
            if relays.endpoint_map('xray:2') != peer_endpoint:
                raise AssertionError('Entry switch changed the peer exit mapping')
            held.sendall(b'healthy-switch-peer-survived')
            if held.recv(4096) != b'healthy-switch-peer-survived':
                raise AssertionError('Entry switch interrupted the peer TCP stream')
            if relays.switches.read(result['id'])['phase']!='grace_pending':
                raise AssertionError('Planned switch did not preserve its grace period')
            relays.verify_route(sources['xray:1'],profiles['xray:1'],entry_a,'127.0.0.2',list(prior_endpoint.values()))
            with store.connection(write=True) as database:
                database.execute("UPDATE fleet_relay_switches SET retry_at=0 WHERE phase='grace_pending'")
            relays.switches.recover()
            if relays.switches.read(result['id'])['phase']!='complete':
                raise AssertionError('Expired grace period did not clean its owned former rules')
            passed('planned switch keeps real old VPN and HTTP/HTTPS payload working until grace expires')
        passed('entry switch publishes verified VLESS and HTTP/HTTPS through the new entry while a peer TCP stream survives')

        hy2_node = next(node for node, source in sources.items() if source['protocol'] == 'hysteria2')
        with store.connection() as database:
            hy2_route = database.execute("SELECT id FROM fleet_tunnels WHERE node=? AND state='active'", (hy2_node,)).fetchone()['id']
        switch(entry_b_id, hy2_route)
        relays.verify_route(sources[hy2_node], profiles[hy2_node], relays.entry(entry_b_id),
                            '127.0.0.2', list(relays.endpoint_map(hy2_node).values()))
        passed('Hysteria2 QUIC payload follows the replacement entry using the original client credential')

        temporary_node='xray:99'
        sources[temporary_node]=copy.deepcopy(sources['xray:2'])
        sources[temporary_node].update(node=temporary_node,name='Forced direct fixture')
        sources[temporary_node]['identity']['created_at']='fixture-99'
        profiles[temporary_node]=copy.deepcopy(profiles['xray:2'])
        with store.connection(write=True) as database:
            database.execute("INSERT INTO nodes VALUES(99,'Forced direct fixture','127.0.0.2',62950,62951,'fixture-99')")
        temporary=relays.plan_route({'entry':entry_b_id,'node':temporary_node,'origin':'127.0.0.2','include_proxies':False,'management':False})
        relays.deploy(temporary['id'])
        wait(lambda:relays.job(temporary['id'])['state']!='running','Forced direct fixture setup timed out',80)
        if relays.job(temporary['id'])['state']!='succeeded':raise AssertionError(relays.job(temporary['id'])['message'])

        # The replacement's API and forwarding service disappear together.
        unit = 'rime-relay-' + entry_b_id
        run_on_arena(['systemctl', 'stop', unit])
        run_on_arena(['iptables', '-I', 'OUTPUT', '1', '-d', '127.0.0.3', '-p', 'tcp',
                      '--dport', '62180', '-j', 'DROP'])
        blocked_old_control = True
        interrupted=secrets.token_hex(16)
        relays.changes.prepare(interrupted,temporary_node,'native-edit')
        relays.update(interrupted,'running','Synthetic orphaned controller job',{'node':temporary_node})
        with store.connection(write=True) as database:
            database.execute("UPDATE fleet_relay_changes SET phase='needs_reconcile' WHERE id=?",(interrupted,))
            database.execute("INSERT INTO fleet_relay_edits VALUES(?,?,'prepared')",(interrupted,temporary_node))
        # A controller restart loses RAM ownership, not the durable orphan row.
        relays.busy.clear()
        from hy2bridge.relay_changes import RelayChanges
        relays.changes=RelayChanges(relays)
        detached=relays.detach_route(temporary['id'],temporary['id'])
        wait(lambda:relays.job(detached['id'])['state']!='running','Forced direct publication timed out',35)
        if relays.job(detached['id'])['state']!='succeeded' or relays.endpoint_map(temporary_node):
            raise AssertionError('Dead entry still appears in the forced direct publication')
        direct={'id':'direct-fixture','name':'Direct exit','domain':'exit.lab.invalid','address':'127.0.0.2'}
        relays.verify_route(sources[temporary_node],profiles[temporary_node],direct,'127.0.0.2',[
            {'kind':'vpn','proxy':None,'origin_port':24444,'public_port':24444,'protocol':'tcp'}])
        if relays.retirements.pending_entry(entry_b_id)!=1:raise AssertionError('Forced withdrawal lost its deferred owned cleanup')
        if relays.changes.read(interrupted)['phase']!='abandoned' or relays.job(interrupted)['state']!='failed':
            raise AssertionError('Forced withdrawal did not fence the orphaned durable job')
        relays.changes.finish(interrupted,True,recheck=True)
        relays.changes.recover()
        if relays.endpoint_map(temporary_node):raise AssertionError('Recovery resurrected the abandoned publication')
        passed('dead entry force withdrawal fences orphaned running changes restores real direct VLESS and journals owned cleanup')
        result = switch(entry_id)
        verify_current()
        if not result['context']['old_cleanup_pending']:
            raise AssertionError('The switch hid deferred old-entry cleanup')
        if {row['entry'] for row in relays.endpoint_map('xray:1').values()} != {entry_id}:
            raise AssertionError('Emergency switch still publishes the unavailable entry')
        switch(entry_id, hy2_route)
        relays.verify_route(sources[hy2_node], profiles[hy2_node], entry_a,
                            '127.0.0.2', list(relays.endpoint_map(hy2_node).values()))
        with store.connection() as database:
            journals = [dict(row) for row in database.execute('SELECT * FROM fleet_relay_switches')]
        if not any(row['phase'] == 'cleanup_pending' for row in journals):
            raise AssertionError('Unavailable old entry cleanup was not retained durably')
        passed('an unavailable old entry does not block VLESS, Hysteria2 and HTTP/HTTPS switching and retains owned cleanup journals')

        run_on_arena(['iptables', '-D', 'OUTPUT', '-d', '127.0.0.3', '-p', 'tcp',
                      '--dport', '62180', '-j', 'DROP'])
        blocked_old_control = False
        run_on_arena(['systemctl', 'start', unit])
        control_b = relays.control(relays.entry(entry_b_id))
        def ready():
            try:
                return bool(control_b.services())
            except (ProvisionError, OSError):
                return False
        wait(ready, 'Restarted old entry API did not become ready')
        with store.connection(write=True) as database:
            database.execute("UPDATE fleet_relay_switches SET retry_at=0 WHERE phase='cleanup_pending'")
            database.execute("UPDATE fleet_relay_retirements SET retry_at=0 WHERE phase='cleanup_pending'")
        relays.switches.recover()
        relays.retirements.recover()
        verify_current()
        if relays.endpoint_map('xray:2') != peer_endpoint:
            raise AssertionError('Deferred cleanup changed the peer route')
        if any(value['name'] != 'rime-control' for value in control_b.services()):
            raise AssertionError('Deferred cleanup left the old exit forwarding rules')
        passed('returning old entry is cleaned without changing the current publication or peer exit')

        # A live control API with rejected VPN payload must retain the old route.
        before = copy.deepcopy(relays.endpoint_map('xray:1'))
        plan = relays.switches.plan(route_id, entry_b_id)
        services = relays.plans[plan['id']]['services']
        ports = [service['public_port'] for service in services if service['kind'] == 'vpn']
        rules = [['iptables', '-I', 'OUTPUT', '1', '-d', '127.0.0.3', '-p', 'tcp', '--dport', str(port), '-j', 'REJECT']
                 for port in ports]
        try:
            for command in rules:
                run_on_arena(command)
            relays.deploy(plan['id'])
            wait(lambda: relays.job(plan['id'])['state'] != 'running', 'Rejected switch did not finish', 100)
            if relays.job(plan['id'])['state'] not in ('failed', 'rolled_back'):
                raise AssertionError('A rejected VPN payload was published')
            if relays.endpoint_map('xray:1') != before:
                raise AssertionError('Failed replacement changed the original publication')
        finally:
            for command in rules:
                run_on_arena(['iptables', '-D', 'OUTPUT', *command[4:]], required=False)
        verify_current()
        passed('failed new-entry VPN payload rolls back prepared forwarding while the previous VPN and proxies remain usable')

        before_rows = [row['id'] for row in prior_endpoint.values()]
        with store.connection() as database:
            placeholders = ','.join('?' for _ in before_rows)
            retained = {row['id']:row['entry'] for row in database.execute(
                'SELECT id,entry FROM fleet_tunnel_services WHERE id IN (' + placeholders + ')', before_rows)}
        if any(retained.get(row['id']) != row['entry'] for row in prior_endpoint.values()):
            raise AssertionError('Entry switch removed ownership needed for delayed telemetry')
        passed('retired transport generations retain their original ownership and preserve VPN user quota')
        return entry_b_id, entry_access
    finally:
        if blocked_old_control:
            run_on_arena(['iptables', '-D', 'OUTPUT', '-d', '127.0.0.3', '-p', 'tcp',
                          '--dport', '62180', '-j', 'DROP'], required=False)
        try:
            control_a.remove('rime-switch-peer'); control_a.save()
        finally:
            echo.shutdown(); echo.server_close()


def main(args):
    root=Path(tempfile.mkdtemp(prefix='rime-relay-qualification-'))
    certificate(root)
    results=[]
    def passed(message):results.append(message);print('PASS '+message,flush=True)
    sqlite3.connect(root/'db.sqlite3').close()
    store=Store(root/'db.sqlite3')
    with store.connection(write=True) as database:
        database.execute('CREATE TABLE nodes(id INTEGER PRIMARY KEY,name TEXT,address TEXT,port INTEGER,api_port INTEGER,created_at TEXT)')
        database.execute("INSERT INTO nodes VALUES(1,'Exit A','127.0.0.2',62050,62051,'fixture-a'),(2,'Exit B','127.0.0.2',62052,62053,'fixture-b')")
        database.execute('CREATE TABLE fleet_inventory(id TEXT PRIMARY KEY,created_at TEXT,address TEXT)')
        database.execute('CREATE TABLE fleet_host_nodes(host_id INTEGER,node TEXT)')
        database.execute('CREATE TABLE users(id INTEGER PRIMARY KEY,used_traffic INTEGER)')
        database.execute('INSERT INTO users VALUES(1,12345)')
    Registry(store)
    settings={'allowed_hosts':['127.0.0.1','127.0.0.2','127.0.0.3'],'lab_network':True,
        'relay_switch_grace_seconds':0,
        'panel_url':'https://127.0.0.1:18443','panel_ca_file':str(root/'cert.pem'),
        'relay_binary':args.binary,'xray_binary':args.xray_binary,
        'relay_probe':{'probe_host':'172.17.0.1','probe_port':18443,'probe_path':'/?format=json','probe_ca_file':str(root/'cert.pem')},
        'proxy':{'probe_host':'172.17.0.1','probe_port':18443,'probe_path':'/?format=json',
            'panel_ca_file':str(root/'cert.pem'),'image':args.proxy_image,
            'image_bundle':args.proxy_bundle,'image_bundle_sha256':__import__('hashlib').sha256(Path(args.proxy_bundle).read_bytes()).hexdigest()}}
    hysteria=root/'hysteria'
    shutil.copyfile(args.hysteria_binary,hysteria);hysteria.chmod(0o755)
    settings['hysteria_binary']=str(hysteria)
    provision=Provisioner(store,settings,None,None,None)
    proxies=ProxyService(store,provision)
    production_configuration=proxies.configuration
    def isolated_configuration(identity,value):
        configuration,password_hash=production_configuration(identity,value)
        configuration['files']['squid.conf']=configuration['files']['squid.conf'].replace('http_access deny private_dst','')
        configuration['files']['squid.conf']=configuration['files']['squid.conf'].replace('acl Safe_ports port 80 443','acl Safe_ports port 80 443 18443').replace('acl SSL_ports port 443','acl SSL_ports port 443 18443')
        return configuration,password_hash
    proxies.configuration=isolated_configuration
    access={'host':'127.0.0.1','ssh_port':22,'username':'root','password':args.password,
        **provision.scan('127.0.0.1',22)}
    processes=[]
    relays=None
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def send(self,value,status=200):
            raw=json.dumps(value).encode();self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_GET(self):self.send({'ip':self.client_address[0] if self.client_address[0].startswith('127.') else '127.0.0.2'})
        def do_POST(self):
            try:
                value=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                identity=self.path.split('/')[-2]
                self.send(relays.ingest(identity,self.headers.get('Authorization',''),value))
            except Exception:self.send({'received':False},409)
    server=ThreadingHTTPServer(('0.0.0.0',18443),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'cert.pem',root/'key.pem')
    server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    user=secrets.token_hex(16)
    uuid=f'{user[:8]}-{user[8:12]}-{user[12:16]}-{user[16:20]}-{user[20:]}'
    profiles={}
    sources={}
    for index,port in [(1,24443),(2,24444)]:
        stream={'network':'grpc','security':'tls','tlsSettings':{'certificates':[{'certificateFile':str(root/'cert.pem'),'keyFile':str(root/'key.pem')}]},
                'grpcSettings':{'serviceName':'fixture'}}
        config={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.2','port':port,'protocol':'vless',
            'settings':{'clients':[{'id':uuid}],'decryption':'none'},'streamSettings':stream}],
            'outbounds':[{'protocol':'freedom','tag':'DIRECT','sendThrough':'127.0.0.2',
                'settings':{'finalRules':[{'action':'allow','ip':['172.17.0.1/32']}]}}]}
        path=root/f'xray-{index}.json';path.write_text(json.dumps(config))
        log=(root/f'xray-{index}.log').open('w')
        process=subprocess.Popen([args.xray_binary,'run','-c',str(path)],stdout=log,stderr=log)
        processes.append(process)
        node='xray:'+str(index)
        profiles[node]={'version':1,'vpn':{'protocol':'vless','publish':[[port,port,'tcp']],'config':{'inbounds':[]}},'proxies':{}}
        sources[node]={'node':node,'name':'Exit '+str(index),'identity':{'address':'127.0.0.2','created_at':'fixture-'+str(index)},
            'native':{'port':62048+index*2,'api_port':62049+index*2},'protocol':'vless','vpn_port':port,'domain':'exit.lab.invalid'}
    hy2_node='e'*32
    hy2_password=secrets.token_urlsafe(24)
    hy2_config={'listen':'127.0.0.2:24445','tls':{'cert':str(root/'cert.pem'),'key':str(root/'key.pem')},
        'auth':{'type':'password','password':hy2_password}}
    hy2_path=root/'hy2.json';hy2_path.write_text(json.dumps(hy2_config))
    log=(root/'hy2.log').open('w')
    processes.append(subprocess.Popen([str(hysteria),'server','-c',str(hy2_path)],stdout=log,stderr=log))
    profiles[hy2_node]={'version':1,'vpn':{'protocol':'hysteria2','publish':[[24445,24445,'udp']],'config':hy2_config},'proxies':{}}
    sources[hy2_node]={'node':hy2_node,'name':'UDP exit','identity':{'address':'127.0.0.2','created_at':'fixture-hy2'},
        'native':None,'protocol':'hysteria2','vpn_port':24445,'domain':'exit.lab.invalid'}
    def targets(source,profile,data):
        port=source['vpn_port']
        if source['protocol']=='hysteria2':
            return [{'node':source['node'],'expected_ip':'127.0.0.2','config':{'_kind':'hy2','_hostname':'exit.lab.invalid',
                'server':'127.0.0.2:'+str(port),'auth':hy2_password,'tls':{'sni':'exit.lab.invalid','ca':str(root/'cert.pem')}}}]
        config={'_hostname':'exit.lab.invalid','inbounds':[{'listen':'127.0.0.1','port':0,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
                'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.2','port':port,'users':[{'id':uuid,'encryption':'none'}]}]},
                    'streamSettings':{'network':'grpc','security':'tls','tlsSettings':{'serverName':'exit.lab.invalid',
                        'certificates':[{'certificateFile':str(root/'cert.pem'),'usage':'verify'}]},'grpcSettings':{'serviceName':'fixture'}}}]}
        return [{'node':source['node'],'expected_ip':'127.0.0.2','config':config}]
    transfer=SimpleNamespace(prepare_profile=lambda node:copy.deepcopy(profiles[node]),snapshot=lambda node,*_:copy.deepcopy(sources[node]),
        digest=lambda value:json.dumps(value,sort_keys=True),probe=SimpleNamespace(transfer_targets=targets))
    relays=Relays(provision,transfer,proxies)
    relays.reconnect=lambda _:None
    production_control = relays.control

    class ArenaControl:
        """Model independent hosts on distinct IPs inside one closed namespace."""
        def __init__(self, entry):
            self.inner = production_control(entry)
            self.address = entry['address']

        @property
        def timeout(self):
            return self.inner.timeout

        @timeout.setter
        def timeout(self, value):
            self.inner.timeout = value

        def services(self):
            values = self.inner.services()
            for value in values:
                if value['name'] != 'rime-control' and value['addr'].startswith(self.address + ':'):
                    value['addr'] = '0.0.0.0:' + value['addr'].rsplit(':', 1)[1]
            return values

        def add(self, value):
            physical = copy.deepcopy(value)
            if physical['name'] != 'rime-control':
                physical['addr'] = self.address + ':' + physical['addr'].rsplit(':', 1)[1]
            return self.inner.add(physical)

        def remove(self, name):
            return self.inner.remove(name)

        def save(self):
            return self.inner.save()

    relays.control = lambda entry: ArenaControl(entry)
    proxies.relays=relays
    proxies.deletion=ProxyDeletion(proxies);proxies.deletion.relays=relays
    proxy_id=secrets.token_hex(16)
    data={'node':'xray:1','domain':'127.0.0.1','http_port':3128,'https_port':8443,'proxy_username':'fixture',
          'proxy_password':secrets.token_urlsafe(24),'certificate':(root/'cert.pem').read_text(),'certificate_key':(root/'key.pem').read_text()}
    config,password_hash=proxies.configuration(proxy_id,data)
    config['files']['squid.conf']=config['files']['squid.conf'].replace('http_access deny private_dst','')
    config['files']['squid.conf']=config['files']['squid.conf'].replace('acl Safe_ports port 80 443','acl Safe_ports port 80 443 18443').replace('acl SSL_ports port 443','acl SSL_ports port 443 18443')
    try:
        with provision.connect(dict(access)) as client:
            proxies.remote(client,config)
        host,generation=proxies.node_identity('xray:1')
        envelope=proxies.encrypted_password(proxy_id,data['proxy_password'])
        with store.connection(write=True) as database:
            database.execute('''INSERT INTO fleet_proxy_services(id,node,host,address,domain,http_port,https_port,username,
                password_hash,created_at,checked_at,result,active,node_generation,password_secret)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(proxy_id,'xray:1','127.0.0.2','127.0.0.2','127.0.0.1',3128,8443,
                'fixture',password_hash,time.time(),time.time(),'{}',1,generation,envelope))
            proxies.recovery.remember_proxy('xray:1',proxy_id,config,data['domain'],database,password=data['proxy_password'])
        proxies.update(proxy_id,'xray:1','succeeded','Fixture proxy ready')
        profiles['xray:1']['proxies'][proxy_id]={'files':config['files'],'publish':config['publish'],'domain':data['domain']}
        direct_id=secrets.token_hex(16)
        direct_data={**data,'http_port':3129,'https_port':None,'proxy_username':'direct_fixture'}
        direct_config,direct_hash=proxies.configuration(direct_id,direct_data)
        with provision.connect(dict(access)) as client:proxies.remote(client,direct_config)
        direct_secret=proxies.encrypted_password(direct_id,direct_data['proxy_password'])
        with store.connection(write=True) as database:
            database.execute('''INSERT INTO fleet_proxy_services(id,node,host,address,domain,http_port,https_port,username,
                password_hash,created_at,checked_at,result,active,node_generation,password_secret)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(direct_id,'xray:1','127.0.0.2','127.0.0.2','127.0.0.1',3129,None,
                'direct_fixture',direct_hash,time.time(),time.time(),'{}',1,generation,direct_secret))
            proxies.recovery.remember_proxy('xray:1',direct_id,direct_config,direct_data['domain'],database,password=direct_data['proxy_password'])
        proxies.update(direct_id,'xray:1','succeeded','Direct fixture ready')
        direct_access={**access,'host':'127.0.0.2','address':'127.0.0.2'}
        direct_plan=proxies.deletion.plan(direct_id,direct_access)
        proxies.deletion.deploy(direct_plan['id'])
        wait(lambda:proxies.job(direct_plan['id'])['state']!='running','Direct proxy deletion timed out')
        if proxies.job(direct_plan['id'])['state']!='succeeded':raise AssertionError(proxies.job(direct_plan['id'])['message'])
        with store.connection() as database:
            if database.execute('SELECT active FROM fleet_proxy_services WHERE id=?',(proxy_id,)).fetchone()[0]!=1:
                raise AssertionError('Direct deletion changed the peer proxy')
        passed('direct proxy deletion removes its real container while the peer proxy remains registered')
        entry_request={**access,'name':'Shared entry','domain':'127.0.0.1','control_port':62080,'metrics_port':62081,'api_port':62082}
        plan=relays.plan_entry(entry_request)
        relays.deploy(plan['id'])
        wait(lambda:relays.job(plan['id'])['state']!='running','Entry installation timed out')
        if relays.job(plan['id'])['state']!='succeeded':raise AssertionError(relays.job(plan['id'])['message'])
        entry_id=plan['id']
        wait(lambda:bool(relays.entry(entry_id)['seen_at']),'Entry metrics did not arrive',40)
        passed('real systemd entry installed through direct pinned SSH and delivered TLS-verified observations')
        route_ids=[]
        for node in ['xray:1','xray:2',hy2_node]:
            plan=relays.plan_route({'entry':entry_id,'node':node,'origin':'127.0.0.2','include_proxies':True,'management':False,'ssh_port':22})
            relays.deploy(plan['id'])
            wait(lambda:relays.job(plan['id'])['state']!='running','Route installation timed out',80)
            if relays.job(plan['id'])['state']!='succeeded':raise AssertionError(relays.job(plan['id'])['message'])
            route_ids.append(plan['id'])
        passed('one entry carries two VLESS gRPC TLS exits, real Hysteria2 and existing authenticated HTTP/HTTPS proxies')
        with provision.connect(dict(access)) as client:
            _,out,err=client.exec_command('systemctl restart rime-relay-'+entry_id,timeout=20)
            out.read();err.read()
            if out.channel.recv_exit_status():raise AssertionError('Synthetic GOST restart failed')
        def restarted_control():
            try:return relays.control(relays.entry(entry_id)).services()
            except Exception:return None
        wait(restarted_control,'Restarted GOST control did not return',20)
        actual=restarted_control()
        if not any('enablestats' in value.get('metadata',{}) for value in actual):
            raise AssertionError('GOST restart did not expose normalized metadata for the regression')
        passed('actual GOST restart normalizes metadata before subsequent proxy edit delete and recovery')
        original_public=relays.proxy_endpoint(proxy_id,'http',3128)['public_port']
        operation_access=relays.origin_access('xray:1')
        edited={**data,**access,'host':operation_access['host'],'ssh_port':operation_access['ssh_port'],
            'replace_service':proxy_id,'http_port':3130,'proxy_username':'','proxy_password':''}
        edited.update(provision.scan(edited['host'],edited['ssh_port']))
        edit_plan=proxies.preflight(edited)
        if not edit_plan['ready']:raise AssertionError('Proxy change preflight rejected the isolated source')
        proxies.deploy(edit_plan['id'])
        wait(lambda:proxies.job(edit_plan['id'])['state']!='running','Tunnelled proxy change timed out',80)
        if proxies.job(edit_plan['id'])['state']!='succeeded':raise AssertionError(proxies.job(edit_plan['id'])['message'])
        proxy_id=edit_plan['id']
        if relays.proxy_endpoint(proxy_id,'http',3130)['public_port']!=original_public:raise AssertionError('Proxy change replaced the public entry port')
        with store.connection() as database:
            active={row['id'] for row in database.execute("SELECT id FROM fleet_proxy_services WHERE node='xray:1' AND active=1")}
        profiles['xray:1']['proxies']={key:value for key,value in proxies.recovery.load('xray:1')['proxies'].items() if key in active}
        copied=proxies.connection_info(proxy_id)
        if copied['password']!=data['proxy_password']:raise AssertionError('Proxy edit changed the preserved password')
        if not copied['urls']['http'].endswith(':'+str(original_public)):raise AssertionError('Copied proxy URI omits the entry endpoint')
        passed('proxy change uses the explicit SSH route, preserves the public port and password, and updates its copied URI')
        with store.connection(write=True) as database:
            database.execute("UPDATE fleet_relay_changes SET phase='applied' WHERE id=?",(proxy_id,))
        proxies.update(proxy_id,'xray:1','failed','Synthetic controller interruption after source commit')
        relays.changes.recover()
        reconcile_access={**access,'host':operation_access['host'],'ssh_port':operation_access['ssh_port']}
        reconcile_access.update(provision.scan(reconcile_access['host'],reconcile_access['ssh_port']))
        proxies.reconcile(proxy_id,reconcile_access)
        wait(lambda:proxies.job(proxy_id)['state']!='running','Proxy recovery did not finish',80)
        if proxies.job(proxy_id)['state']!='succeeded':raise AssertionError(proxies.job(proxy_id)['message'])
        if relays.proxy_endpoint(proxy_id,'http',3130)['public_port']!=original_public:raise AssertionError('Recovery changed the preserved public port')
        passed('an interrupted committed proxy change recovers its existing runtime and entry mapping without replacing access')
        crash=secrets.token_hex(16)
        proxies.update(crash,'xray:1','running','Synthetic interruption before proxy deletion publication')
        desired=relays.changes.prepare_proxy_delete(crash,'xray:1',proxy_id)
        relays.changes.apply(crash,desired)
        if any(value['name']==json.loads(row['config'])['name'] for row in relays.proxy_routes(proxy_id)
               for value in relays.control(relays.entry(entry_id)).services()):
            raise AssertionError('Deletion preparation did not remove its actual selected rules')
        relays.busy.clear()
        relays.changes.recover()
        if relays.changes.read(crash)['phase']!='rolled_back':raise AssertionError('Interrupted proxy deletion did not recover its journal')
        relays.verify_route(sources['xray:1'],profiles['xray:1'],relays.entry(entry_id),'127.0.0.2',list(relays.endpoint_map('xray:1').values()))
        passed('crash after actual proxy rule withdrawal restores journaled forwarding and authenticated HTTP/HTTPS payload')
        additional={**data,**access,'host':operation_access['host'],'ssh_port':operation_access['ssh_port'],
            'http_port':3132,'https_port':None,'proxy_username':'another_fixture','proxy_password':secrets.token_urlsafe(24)}
        additional.update(provision.scan(additional['host'],additional['ssh_port']))
        additional_plan=proxies.preflight(additional)
        proxies.deploy(additional_plan['id'])
        wait(lambda:proxies.job(additional_plan['id'])['state']!='running','Additional proxy creation timed out',80)
        if proxies.job(additional_plan['id'])['state']!='succeeded':raise AssertionError(proxies.job(additional_plan['id'])['message'])
        if relays.proxy_endpoint(additional_plan['id'],'http',3132) is None:raise AssertionError('New proxy did not receive an entry route')
        additional_access={**access,'host':operation_access['host'],'ssh_port':operation_access['ssh_port']}
        additional_access.update(provision.scan(additional_access['host'],additional_access['ssh_port']))
        additional_delete=proxies.deletion.plan(additional_plan['id'],additional_access)
        proxies.deletion.deploy(additional_delete['id'])
        wait(lambda:proxies.job(additional_delete['id'])['state']!='running','Additional proxy removal timed out')
        if proxies.job(additional_delete['id'])['state']!='succeeded':raise AssertionError(proxies.job(additional_delete['id'])['message'])
        if relays.proxy_endpoint(proxy_id,'http',3130) is None:raise AssertionError('Removing new proxy changed its peer')
        passed('a new proxy on an already tunnelled exit is published through the entry and removed without changing its peer')
        replacement_entry, replacement_access = qualify_switches(relays, provision, store, access, entry_id,
            route_ids[0], sources, profiles, proxy_id, passed)
        entry=relays.entry(entry_id);control=relays.control(entry)
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.2',26443));stop=threading.Event()
        def echo():
            udp.settimeout(.5)
            while not stop.is_set():
                try:
                    packet,peer=udp.recvfrom(65535);udp.sendto(packet,peer)
                except socket.timeout:pass
        threading.Thread(target=echo,daemon=True).start()
        udp_name='fixture-udp'
        control.add(forwarding_service(udp_name,26444,'127.0.0.2',26443,'udp'))
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            for size in [1,100,1200,6000,32000]:
                packet=secrets.token_bytes(size);client.sendto(packet,('127.0.0.1',26444))
                received=client.recvfrom(65535)[0]
                if received!=packet:raise AssertionError(f'UDP datagram changed from {size} to {len(received)} bytes')
        passed('UDP forwarding preserves full datagrams including fragmented 32 KB payloads')
        control.remove('rime-'+udp_name);control.save();stop.set();udp.close()
        # A stable peer stream survives a different route's removal.
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                while data:=self.request.recv(65536):self.request.sendall(data)
        echo_server=socketserver.ThreadingTCPServer(('127.0.0.2',27443),Echo)
        echo_server.daemon_threads=True
        threading.Thread(target=echo_server.serve_forever,daemon=True).start()
        control.add(forwarding_service('fixture-peer',27444,'127.0.0.2',27443,'tcp'))
        with socket.create_connection(('127.0.0.1',27444)) as held:
            held.settimeout(5)
            held.sendall(b'before-removal')
            if held.recv(4096)!=b'before-removal':raise AssertionError('Peer stream did not start')
            job=relays.remove_route(route_ids[0])
            wait(lambda:relays.job(job['id'])['state']!='running','Route removal timed out')
            relays.verify_route(sources['xray:2'],profiles['xray:2'],entry,'127.0.0.2',list(relays.endpoint_map('xray:2').values()))
            held.sendall(b'peer-stream-still-open')
            if held.recv(4096)!=b'peer-stream-still-open':raise AssertionError('Peer stream was interrupted')
        control.remove('rime-fixture-peer');control.save();echo_server.shutdown();echo_server.server_close()
        passed('removing one exit preserves the other VPN and its established peer TCP stream')
        # Recreate the proxy route, then remove the actual proxy through its explicit SSH forwarding.
        plan=relays.plan_route({'entry':entry_id,'node':'xray:1','origin':'127.0.0.2','include_proxies':True,'management':False,'ssh_port':22})
        relays.deploy(plan['id']);wait(lambda:relays.job(plan['id'])['state']!='running','Route recreation timed out',80)
        if relays.job(plan['id'])['state']!='succeeded':raise AssertionError(relays.job(plan['id'])['message'])
        route_ids[0]=plan['id']
        via=relays.origin_access('xray:1')
        deletion_access={**access,'host':via['host'],'ssh_port':via['ssh_port']}
        deletion_access.update(provision.scan(deletion_access['host'],deletion_access['ssh_port']))
        deletion_plan=proxies.deletion.plan(proxy_id,deletion_access)
        proxies.deletion.deploy(deletion_plan['id'])
        wait(lambda:proxies.job(deletion_plan['id'])['state']!='running','Proxy deletion timed out')
        if proxies.job(deletion_plan['id'])['state']!='succeeded':raise AssertionError(proxies.job(deletion_plan['id'])['message'])
        if relays.proxy_routes(proxy_id):raise AssertionError('Deleted proxy still has relay rules')
        relays.verify_route(sources['xray:2'],profiles['xray:2'],entry,'127.0.0.2',list(relays.endpoint_map('xray:2').values()))
        passed('proxy deletion removes its real container and selected entry rules while peer VPN remains available')
        replacement=json.loads((root/'xray-2.json').read_text())
        replacement['inbounds'][0]['listen']='127.0.0.3'
        replacement['outbounds'][0]['sendThrough']='127.0.0.3'
        replacement_path=root/'xray-replacement.json';replacement_path.write_text(json.dumps(replacement))
        replacement_log=(root/'xray-replacement.log').open('w')
        processes.append(subprocess.Popen([args.xray_binary,'run','-c',str(replacement_path)],stdout=replacement_log,stderr=replacement_log))
        def replacement_ready():
            try:
                with socket.create_connection(('127.0.0.3',24444),timeout=.2):return True
            except OSError:return False
        wait(replacement_ready,'Replacement exit did not start')
        public_ports=sorted(value['public_port'] for value in relays.endpoint_map('xray:2').values())
        proxies.recovery.remember_vpn('xray:2',profiles['xray:2']['vpn'])
        change=relays.edits.prepare_native(SimpleNamespace(id=2,address='127.0.0.2',port=62052,api_port=62053),
            SimpleNamespace(address='127.0.0.3',port=None,api_port=None))
        with store.connection(write=True) as database:
            database.execute("UPDATE nodes SET address='127.0.0.3' WHERE id=2")
            relays.edits.mark(change['id'],database.execute)
        relays.edits.finish(change,True)
        sources['xray:2']['identity']['address']='127.0.0.3'
        if sorted(value['public_port'] for value in relays.endpoint_map('xray:2').values())!=public_ports:raise AssertionError('Transfer changed public entry ports')
        passed('exit replacement preserves the entry endpoint and old VLESS key while reaching the new exit IP')
        wait(lambda:sum(row['traffic']['rx']+row['traffic']['tx'] for tunnel in relays.catalog()['tunnels'] for row in tunnel['services'])>0,'Transport counters did not arrive',35)
        with store.connection() as database:
            if database.execute('SELECT used_traffic FROM users WHERE id=1').fetchone()[0]!=12345:raise AssertionError('Relay double-charged the user')
        passed('real per-service counters arrive without changing VPN user balances')
        server.shutdown()
        before=proxies.settings.copy()
        # Payload responder remains available on a second fixture port while the panel endpoint is stopped.
        payload=ThreadingHTTPServer(('0.0.0.0',18444),Handler);payload.socket=context.wrap_socket(payload.socket,server_side=True)
        threading.Thread(target=payload.serve_forever,daemon=True).start()
        settings['relay_probe']['probe_port']=18444
        relays.verify_route(sources['xray:2'],profiles['xray:2'],entry,relays.direct_target('xray:2'),list(relays.endpoint_map('xray:2').values()))
        relays.verify_route(sources[hy2_node],profiles[hy2_node],entry,'127.0.0.2',list(relays.endpoint_map(hy2_node).values()))
        payload.shutdown();proxies.settings=before
        passed('stopping the panel endpoint does not stop the forwarding data plane')
        for route in relays.catalog()['tunnels']:
            job=relays.remove_route(route['id'])
            wait(lambda:relays.job(job['id'])['state']!='running','Final route removal timed out')
            if relays.job(job['id'])['state']!='succeeded':raise AssertionError(relays.job(job['id'])['message'])
        removal=relays.plan_entry_remove(entry_id,dict(access))
        relays.deploy(removal['id'])
        wait(lambda:relays.job(removal['id'])['state']!='running','Entry removal timed out')
        if relays.job(removal['id'])['state']!='succeeded':raise AssertionError(relays.job(removal['id'])['message'])
        if relays.entry(entry_id)['state']!='deleted':raise AssertionError('Entry registration survived removal')
        passed('entry removal stops only its owned services and revokes its stored control credential')
        with provision.connect(dict(replacement_access)) as client:
            _,out,err=client.exec_command('systemctl stop rime-relay-'+replacement_entry,timeout=15)
            out.read();err.read()
            if out.channel.recv_exit_status():raise AssertionError('Could not stop synthetic entry for forget acceptance')
        forgotten=relays.forget_entry(replacement_entry,relays.entry(replacement_entry)['domain'])
        if not forgotten['forgotten'] or forgotten['remote_cleanup_performed']:
            raise AssertionError('Forgetting dead entry attempted remote changes')
        if relays.entry(replacement_entry)['credential'] or relays.entry(replacement_entry)['state']!='deleted':
            raise AssertionError('Forgotten entry kept its registration credential')
        passed('explicit forget removes a stopped entry registration without remote access and revokes its token')
        # The closed arena remains under our control; remove its forgotten
        # runtime separately, exactly as a real returned server must be cleaned.
        with provision.connect(dict(replacement_access)) as client:
            relays.remote(client,{'id':replacement_entry,'action':'remove'})
        report={'passed':results,'closed_network':True,'production_touched':False}
        Path(args.report).write_text(json.dumps(report,ensure_ascii=False,indent=2))
    finally:
        for process in processes:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        server.server_close()


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',required=True)
    parser.add_argument('--proxy-image',required=True)
    parser.add_argument('--proxy-bundle',required=True)
    parser.add_argument('--hysteria-binary',required=True)
    parser.add_argument('--xray-binary',default='/usr/local/bin/xray')
    parser.add_argument('--password',required=True)
    parser.add_argument('--report',required=True)
    main(parser.parse_args())
