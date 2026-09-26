"""Crash qualification of the patched real Hysteria binary, network=none only."""
import http.server
import json
import os
from pathlib import Path
import signal
import socketserver
import sys
import threading
import time
import urllib.request

sys.path.insert(0,'/lab')
import probe as p

ROOT=Path('/lab/release')/os.environ.get('CORE_RUN_ID','core-run')
ROOT.mkdir(exist_ok=False)
p.RESULT=ROOT
A='11111111-1111-4111-8111-111111111111'
B='22222222-2222-4222-8222-222222222222'
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
results=[]


def check(name,passed,**detail):
    results.append({'name':name,'passed':bool(passed),**detail})
    print(name,passed,flush=True)
    assert passed,(name,detail)


class Auth(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        body=json.dumps({'ok':data.get('auth') in (A,B),'id':data.get('auth')}).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass


def api(path,data=None):
    req=urllib.request.Request('http://127.0.0.1:19999/'+path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Authorization':'synthetic-stats','Content-Type':'application/json'})
    with opener.open(req,timeout=3) as r:return json.loads(r.read())


def server(name):
    return p.launch(name,['/lab/release/bin/hysteria-fleet','server','-c',str(ROOT/'server.json')])


def main():
    os.environ['FLEET_TRAFFIC_WAL']=str(ROOT/'usage.wal')
    for cls,port,handler in [(socketserver.ThreadingTCPServer,18080,p.TCP),
                            (socketserver.ThreadingUDPServer,18090,p.UDP),
                            (http.server.ThreadingHTTPServer,18888,Auth)]:
        cls.allow_reuse_address=True;srv=cls(('127.0.0.1',port),handler);srv.daemon_threads=True
        threading.Thread(target=srv.serve_forever,daemon=True).start()
    (ROOT/'server.json').write_text(json.dumps({'listen':'127.0.0.1:14443',
        'tls':{'cert':'/lab/config/cert.pem','key':'/lab/config/key.pem'},
        'auth':{'type':'http','http':{'url':'http://127.0.0.1:18888/auth'}},
        'trafficStats':{'listen':'127.0.0.1:19999','secret':'synthetic-stats'}}))
    core=server('core');time.sleep(.8)
    p.client('a1',A,18081,18091);p.client('a2',A,18082,18092);p.client('b1',B,18083,18093)
    time.sleep(1)
    a1,a2,b=p.tcp_open(18081),p.tcp_open(18082),p.tcp_open(18083)
    check('initial_tcp',all(p.tcp_check(s) for s in (a1,a2,b)))
    result=api('fleet/kick',[A])
    a1.settimeout(2);a2.settimeout(2)
    check('single_kick_closes_both_idle_clients',result['closed']==2 and a1.recv(1)==b'' and a2.recv(1)==b'')
    check('control_user_unaffected',p.tcp_check(b))
    before=api('fleet/snapshot')
    packets=100
    start=time.monotonic()
    for _ in range(packets):assert p.tcp_check(b,16384)
    elapsed=time.monotonic()-start
    core.kill();core.wait(timeout=3)
    core=server('core-recovered');time.sleep(.8)
    after=api('fleet/snapshot')
    delta=after['totals'][B]['tx']-before['totals'][B]['tx']
    check('sigkill_preserves_unpolled_tcp_bytes',delta==packets*16384 and
          after['totals'][B]['rx']-before['totals'][B]['rx']==delta,bytes_each_direction=delta,
          roundtrip_payload_mib_s=round(delta*2/elapsed/1024/1024,2))
    check('ledger_identity_survives_process_restart',after['ledger']==before['ledger'])
    core.kill();core.wait(timeout=3)
    with (ROOT/'usage.wal').open('ab') as f:f.write(b'\x00\x00\x00');f.flush();os.fsync(f.fileno())
    core=server('core-tail-recovered');time.sleep(.8)
    check('partial_write_tail_recovered',api('fleet/snapshot')==after)
    try:api('traffic?clear=1');denied=False
    except urllib.error.HTTPError as e:denied=e.code==409
    check('destructive_counter_reset_rejected',denied)
    p.client('udp-after-restart',B,18084,18094);time.sleep(1)
    before_udp=api('fleet/snapshot')
    import socket
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        for _ in range(20):
            s.sendto(b'u'*1024,('127.0.0.1',18094));assert s.recv(2048)==b'u'*1024
    core.kill();core.wait(timeout=3);core=server('core-udp-recovered');time.sleep(.8)
    after_udp=api('fleet/snapshot')
    check('sigkill_preserves_unpolled_udp_bytes',all(after_udp['totals'][B][k]-before_udp['totals'][B][k]==20480 for k in ('tx','rx')))
    if os.environ.get('SOAK_SECONDS'):
        duration=int(os.environ['SOAK_SECONDS'])
        workers=int(os.environ.get('SOAK_WORKERS','1'))
        for i in range(workers):p.client('soak-'+str(i),B if i%2==0 else A,18100+i,18200+i)
        time.sleep(1);before=api('fleet/snapshot');start=time.monotonic()
        def transfer(i):
            s=p.tcp_open(18100+i);total=0
            try:
                while time.monotonic()-start<duration:
                    assert p.tcp_check(s,65536);total+=65536
                    time.sleep(.02 if workers>1 else .1)
                return (B if i%2==0 else A),total
            finally:s.close()
        from concurrent.futures import ThreadPoolExecutor
        expected={A:0,B:0}
        with ThreadPoolExecutor(workers) as pool:
            for auth,total in pool.map(transfer,range(workers)):expected[auth]+=total
        core.kill();core.wait(timeout=3);core=server('core-soak-recovered');time.sleep(.8)
        after=api('fleet/snapshot')
        check('soak_exact_durable_counters',all(after['totals'][auth][k]-before['totals'].get(auth,{}).get(k,0)==expected[auth] for auth in expected for k in ('tx','rx')),
            seconds=duration,workers=workers,bytes_each_direction=sum(expected.values()),wal_bytes=(ROOT/'usage.wal').stat().st_size)


try:main()
finally:
    for proc in reversed(p.processes):
        if proc.poll() is None:proc.terminate()
    for proc in p.processes:
        try:proc.wait(timeout=3)
        except Exception:proc.kill();proc.wait()
    (ROOT/'results.json').write_text(json.dumps(results,indent=2))
