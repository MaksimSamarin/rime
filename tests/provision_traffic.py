"""Real payload and subscription checks for nodes created through the UI."""
import base64
import json
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import subprocess
import threading
import time
import urllib.request
import urllib.parse

ROOT=Path('/lab/release/wizard')
HTTP=urllib.request.build_opener(urllib.request.ProxyHandler({}))
results=[];processes=[];logs=[]
def req(path,data=None,token=None,form=False):
    body=(urllib.parse.urlencode(data) if form else json.dumps(data)).encode() if data is not None else None
    r=urllib.request.Request('http://127.0.0.1:18800'+path,data=body,headers={
        'Content-Type':'application/x-www-form-urlencoded' if form else 'application/json','Authorization':'Bearer '+(token or '')})
    with HTTP.open(r,timeout=10) as response:
        raw=response.read();return json.loads(raw) if 'application/json' in response.headers.get('Content-Type','') else raw
def check(name,ok,**data):
    results.append({'name':name,'passed':bool(ok),**data});print(name,bool(ok),flush=True);assert ok,name
def start(name,args):
    f=(ROOT/(name+'.log')).open('w');logs.append(f)
    p=subprocess.Popen(args,stdout=f,stderr=f);processes.append(p);return p
def cfg(name,data):
    p=ROOT/(name+'.json');p.write_text(json.dumps(data));return str(p)
def echo(port,payload):
    with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
        s.settimeout(3);s.sendall(payload);got=b''
        while len(got)<len(payload):
            part=s.recv(len(payload)-len(got))
            if not part:return False
            got+=part
        return got==payload
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data:=self.request.recv(65536):self.request.sendall(data)
try:
    server=socketserver.ThreadingTCPServer(('0.0.0.0',18080),Echo);server.daemon_threads=True
    threading.Thread(target=server.serve_forever,daemon=True).start()
    token=req('/api/admin/token',{'username':'labadmin','password':'Synthetic-lab-password-2026'},form=True)['access_token']
    user=req('/api/user/bob',token=token)
    auth=user['proxies']['vless']['id'];before=user['used_traffic'];url=user['subscription_url']
    lines=base64.b64decode(req(url)).decode().splitlines()
    check('old_subscription_has_legacy_links',any('legacy-a.example.invalid' in x and auth in x for x in lines) and any('legacy-b.example.invalid' in x and auth in x for x in lines))
    check('new_hy2_in_existing_subscription',any('hysteria2://' in x and 'lab.invalid:25443' in x for x in lines))
    check('new_vless_in_existing_subscription',any('vless://' in x and 'lab.invalid:25443' in x for x in lines))
    with sqlite3.connect(ROOT/'db.sqlite3') as db:address=db.execute("SELECT address FROM nodes WHERE status='connected' ORDER BY id DESC LIMIT 1").fetchone()[0]
    hy=cfg('provision-hy-client',{'server':'127.0.0.1:24443','auth':auth,'tls':{'sni':'lab.invalid','ca':'/lab/config/cert.pem'},
        'tcpForwarding':[{'listen':'127.0.0.1:18501','remote':'127.0.0.1:18080'}]})
    start('provision-hy-client',['/lab/bin/hysteria','client','-c',hy])
    xr=cfg('provision-vless-client',{'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':18502,'protocol':'dokodemo-door','settings':{'address':'127.0.0.1','port':18080,'network':'tcp'}}],
        'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':address,'port':16443,'users':[{'id':auth,'encryption':'none'}]}]},
        'streamSettings':{'network':'grpc','grpcSettings':{'serviceName':'fleet-test'},'security':'tls','tlsSettings':{'serverName':'lab.invalid','certificates':[{'certificateFile':'/lab/config/cert.pem','usage':'verify'}]}}}]})
    start('provision-vless-client',['/lab/bin/xray','run','-c',xr])
    for port in (18501,18502):
        end=time.monotonic()+15
        while True:
            try:
                if echo(port,b'test'):break
            except OSError:pass
            if time.monotonic()>end:raise RuntimeError('Client not ready: '+str(port))
            time.sleep(.25)
    check('provisioned_hy2_payload',echo(18501,b'h'*65536))
    check('provisioned_vless_grpc_tls_payload',echo(18502,b'v'*65536))
    end=time.monotonic()+40
    while req('/api/user/bob',token=token)['used_traffic']-before<262144 and time.monotonic()<end:time.sleep(1)
    check('both_new_nodes_charge_existing_user',req('/api/user/bob',token=token)['used_traffic']-before>=262144)
    # Marzban may mint a new JWT with a different iat when serializing a user.
    # Seamlessness means the previously issued URL still returns valid links.
    check('previously_issued_subscription_still_valid',set(base64.b64decode(req(url)).decode().splitlines())==set(lines))
finally:
    for p in processes:p.terminate()
    for p in processes:
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    for f in logs:f.close()
    (ROOT/'provision-traffic-results.json').write_text(json.dumps(results,indent=2))
