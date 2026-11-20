"""Real legacy Hy2 payload and HTTP-auth outage regression; isolated lab only."""
import http.server
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import e2e as t
from hy2bridge.policy import LocalPolicy
from hy2bridge.spool import Spool
from hy2bridge.meter import source_epoch


def main():
    import socketserver
    for cls,port,handler in [(socketserver.ThreadingTCPServer,18080,t.TCP),(socketserver.ThreadingUDPServer,18090,t.UDP)]:
        cls.allow_reuse_address=True;s=cls(('127.0.0.1',port),handler);s.daemon_threads=True
        threading.Thread(target=s.serve_forever,daemon=True).start()
    hycfg=t.save('legacy-hy.json',{'listen':'127.0.0.1:14443','tls':{'cert':'/lab/config/cert.pem','key':'/lab/config/key.pem'},
        'auth':{'type':'http','http':{'url':'http://127.0.0.1:18888/auth'}},'trafficStats':{'listen':'127.0.0.1:19998','secret':'synthetic-stats-secret'}})
    hy=t.start('legacy-hy',['/lab/bin/hysteria','server','-c',hycfg]);(t.STATE/'hy.pid').write_text(str(hy.pid))
    settings={'spool':str(t.STATE/'meter.db'),'pid_file':str(t.STATE/'hy.pid'),'token':t.TOKEN}
    spool=Spool(settings['spool'])
    policy={'version':1,'allowed':[t.A,t.B],'rules':{t.A:{'expire':0,'remaining_bytes':1000000,'accounted_bytes':0},t.B:{'expire':0,'remaining_bytes':None,'accounted_bytes':0}}}
    class Panel(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            raw=json.dumps(policy).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def log_message(self,*args):pass
    panel=http.server.ThreadingHTTPServer(('127.0.0.1',18801),Panel)
    threading.Thread(target=panel.serve_forever,daemon=True).start()
    cfg=t.save('legacy-auth.json',{'meter':settings,'stats_url':'http://127.0.0.1:19998','stats_secret':'synthetic-stats-secret',
        'auth_policy_db':str(t.STATE/'policy.db'),'auth_port':18888,'auth_policy_url':'http://127.0.0.1:18801/api/fleet/meters/lab/policy','allow_loopback_http':True,'auth_sync_interval':2})
    def sample():
        epoch=source_epoch(settings)[0]
        import urllib.request
        req=urllib.request.Request('http://127.0.0.1:19998/traffic',headers={'Authorization':'synthetic-stats-secret'})
        with t.HTTP.open(req,timeout=2) as r:stats=json.loads(r.read())
        spool.observe(epoch,stats)
    # Seed the observer's existing cursor before starting its independent reader.
    t.wait(lambda:(sample() or True))
    agent=t.start('legacy-auth',[sys.executable,'-m','hy2bridge.legacy_auth','--config',cfg])
    t.wait(lambda:t.request('http://127.0.0.1:18888/auth',{'auth':t.A})['ok'])
    t.check('legacy_original_root_auth_path_preserved',t.request('http://127.0.0.1:18888/',{'auth':t.A})['ok'])
    t.hyclient('known',t.A,14443,18101);t.wait(lambda:t.fresh(18101));conn=t.conn(18101)
    t.check('legacy_initial_real_tcp_udp',t.echo(conn) and t.udp(18201))
    panel.shutdown();panel.server_close()
    time.sleep(3)
    started=time.monotonic();ok=t.request('http://127.0.0.1:18888/auth',{'auth':t.A})['ok']
    t.check('legacy_offline_auth_does_not_wait_for_panel',ok and time.monotonic()-started<.5)
    t.check('legacy_offline_existing_tcp_udp_survive',t.echo(conn) and t.udp(18201))
    t.hyclient('offline-new',t.A,14443,18102);t.wait(lambda:t.fresh(18102))
    t.check('legacy_offline_new_real_client_works',t.fresh(18102))
    t.stop(agent)
    agent=t.start('legacy-auth-reboot',[sys.executable,'-m','hy2bridge.legacy_auth','--config',cfg])
    t.wait(lambda:t.request('http://127.0.0.1:18888/health')['ready'])
    t.check('legacy_offline_agent_reboot_keeps_policy_and_existing_payload',t.echo(conn) and t.fresh(18102))
    t.check('legacy_unknown_denied',not t.request('http://127.0.0.1:18888/auth',{'auth':'unknown'})['ok'])
    # Refresh a rule locally to emulate a delivered finite budget, then test its
    # enforcement with the controller still unreachable and another user active.
    t.stop(agent);sample();used=spool.charged().get(t.A,0)
    policy['version']=2;policy['rules'][t.A].update(remaining_bytes=1000,accounted_bytes=used)
    LocalPolicy(t.STATE/'policy.db').replace(policy)
    agent=t.start('legacy-budget',[sys.executable,'-m','hy2bridge.legacy_auth','--config',cfg])
    t.wait(lambda:t.request('http://127.0.0.1:18888/health')['ready'])
    t.hyclient('other',t.B,14443,18103);t.wait(lambda:t.fresh(18103))
    t.echo(conn,2048);t.wait(lambda:not t.request('http://127.0.0.1:18888/auth',{'auth':t.A})['ok'])
    t.check('legacy_offline_local_quota_blocks_only_that_user',not t.fresh(18101) and t.fresh(18103))
    # A full engine restart changes its raw epoch; observed totals remain durable.
    sample();t.stop(hy)
    hy=t.start('legacy-core-reboot',['/lab/bin/hysteria','server','-c',hycfg]);(t.STATE/'hy.pid').write_text(str(hy.pid))
    t.hyclient('other-after-core-reboot',t.B,14443,18104);t.wait(lambda:t.fresh(18104))
    t.check('legacy_node_reboot_without_panel_uses_saved_credentials',t.fresh(18104) and not t.request('http://127.0.0.1:18888/auth',{'auth':t.A})['ok'])


if __name__=='__main__':
    try:main()
    finally:
        for proc in reversed(t.PROCESSES):t.stop(proc)
        for log in t.LOGS:log.close()
        (t.STATE/'results.json').write_text(json.dumps(t.RESULTS,indent=2))
        print(json.dumps({'passed':sum(x['passed'] for x in t.RESULTS),'checks':len(t.RESULTS)}),flush=True)
