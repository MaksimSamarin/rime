"""Real Marzban/Xray/Hysteria integration in a network=none Docker container."""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT=Path(os.environ.get('LAB_SUITE_ROOT','/lab/prototype'))
STATE=ROOT/os.environ.get('RUN_ID','run1')
STATE.mkdir(exist_ok=False)
PROCESSES=[]
LOGS=[]
RESULTS=[]
HTTP=urllib.request.build_opener(urllib.request.ProxyHandler({}))
BASE='http://127.0.0.1:18800'
A='11111111-1111-4111-8111-111111111111'
B='22222222-2222-4222-8222-222222222222'
TOKEN='synthetic-node-token-0000000000000001'
ENV=dict(os.environ, PYTHONPATH=str(ROOT/'source')+':/code',
    SQLALCHEMY_DATABASE_URL='sqlite:///'+str(STATE/'db.sqlite3'),
    XRAY_JSON=str(STATE/'xray.json'),XRAY_EXECUTABLE_PATH='/lab/bin/xray',
    SUDO_USERNAME='labadmin',SUDO_PASSWORD='Synthetic-lab-password-2026',
    UVICORN_HOST='127.0.0.1',UVICORN_PORT='18800',
    JOB_RECORD_USER_USAGES_INTERVAL='1',JOB_REVIEW_USERS_INTERVAL='1',
    JOB_RECORD_NODE_USAGES_INTERVAL='1',
    HY2_PANEL_CONFIG=str(STATE/'panel.json'),NO_PROXY='*',no_proxy='*',
    HTTP_PROXY='',HTTPS_PROXY='',ALL_PROXY='',http_proxy='',https_proxy='',all_proxy='')


def check(name, condition, **detail):
    RESULTS.append({'name':name,'passed':bool(condition),**detail})
    print(('PASS ' if condition else 'FAIL ')+name,flush=True)
    if not condition:raise AssertionError(name+': '+str(detail))


def save(name, data):
    path=STATE/name;path.write_text(json.dumps(data,indent=2));return str(path)


def start(name,args):
    log=(STATE/(name+'.log')).open('w');LOGS.append(log)
    proc=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT,env=ENV,cwd='/code',start_new_session=True)
    PROCESSES.append(proc);return proc


def stop(proc):
    if proc.poll() is None:
        os.killpg(proc.pid,signal.SIGTERM)
        try:proc.wait(timeout=8)
        except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()


def request(path, data=None, method=None, token=None, form=False):
    headers={}
    if token:headers['Authorization']='Bearer '+token
    if data is not None:
        headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
        data=(urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
    req=urllib.request.Request(path if path.startswith('http') else BASE+path,data=data,headers=headers,method=method)
    with HTTP.open(req,timeout=30) as response:
        raw=response.read()
        return json.loads(raw) if 'application/json' in response.headers.get('Content-Type','') else raw


def wait(predicate,timeout=15):
    end=time.monotonic()+timeout
    last=None
    while time.monotonic()<end:
        try:
            result=predicate()
            if result:return result
        except Exception as exc:last=type(exc).__name__
        time.sleep(.2)
    raise TimeoutError('Condition not reached: '+str(last))


def panel(name,extended=True):
    proc=start(name,[sys.executable,'-m','uvicorn','main:app' if extended else 'app:app',
                    '--host','127.0.0.1','--port','18800','--log-level','warning'])
    token=wait(lambda:request('/api/admin/token',{'username':'labadmin','password':ENV['SUDO_PASSWORD']},form=True)['access_token'])
    return proc,token


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        while data:=self.request.recv(65536):self.request.sendall(data)


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request;sock.sendto(data,self.client_address)


def conn(port):
    s=socket.create_connection(('127.0.0.1',port),timeout=1);s.settimeout(.5);return s


def echo(s,size=1024):
    try:
        payload=b'x'*size;s.sendall(payload);got=b''
        while len(got)<size:
            part=s.recv(size-len(got))
            if not part:return False
            got+=part
        return got==payload
    except OSError:return False


def fresh(port):
    try:
        with conn(port) as s:return echo(s)
    except OSError:return False


def udp(port):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(.5)
        try:s.sendto(b'u'*512,('127.0.0.1',port));return s.recv(1024)==b'u'*512
        except OSError:return False


def hyclient(name,auth,server,port):
    config=save(name+'.json',{'server':f'127.0.0.1:{server}','auth':auth,
        'tls':{'sni':'lab.invalid','ca':'/lab/config/cert.pem'},
        'tcpForwarding':[{'listen':f'127.0.0.1:{port}','remote':'127.0.0.1:18080'}],
        'udpForwarding':[{'listen':f'127.0.0.1:{port+100}','remote':'127.0.0.1:18090'}]})
    return start(name,['/lab/bin/hysteria','client','-c',config])


def node(n):
    config=save(f'hy{n}.json',{'listen':f'127.0.0.1:{14442+n}',
        'tls':{'cert':'/lab/config/cert.pem','key':'/lab/config/key.pem'},
        'auth':{'type':'http','http':{'url':f'http://127.0.0.1:{18887+n}/auth'}},
        'trafficStats':{'listen':f'127.0.0.1:{19999-n}','secret':'synthetic-stats-secret'}})
    if os.environ.get('DURABLE_CORE'):
        ENV['FLEET_TRAFFIC_WAL']=str(STATE/f'hy{n}.wal')
    proc=start(f'hy{n}',[os.environ.get('DURABLE_CORE','/lab/bin/hysteria'),'server','-c',config])
    ENV.pop('FLEET_TRAFFIC_WAL',None)
    (STATE/f'hy{n}.pid').write_text(str(proc.pid))
    cfg=save(f'agent{n}.json',{'panel_url':BASE+f'/api/hy2/nodes/node{n}',
        'node_token':TOKEN if n==1 else TOKEN[:-1]+'2',
        'stats_url':f'http://127.0.0.1:{19999-n}','stats_secret':'synthetic-stats-secret',
        'auth_port':18887+n,'spool':str(STATE/f'spool{n}.db'),'pid_file':str(STATE/f'hy{n}.pid'),
        'interval':.25,'policy_ttl':2,'durable':bool(os.environ.get('DURABLE_CORE')),'heartbeat_interval':1})
    agent=start(f'agent{n}',[sys.executable,'-m','hy2bridge.node','--config',cfg])
    wait(lambda:request(f'http://127.0.0.1:{18887+n}/health')['fresh'])
    return proc,agent


def main():
    for cls,port,handler in [(socketserver.ThreadingTCPServer,18080,TCP),(socketserver.ThreadingUDPServer,18090,UDP)]:
        cls.allow_reuse_address=True;srv=cls(('127.0.0.1',port),handler);srv.daemon_threads=True
        threading.Thread(target=srv.serve_forever,daemon=True).start()
    save('xray.json',{'log':{'loglevel':'warning'},'inbounds':[{'tag':'VLESS_TEST','listen':'127.0.0.1',
        'port':16443,'protocol':'vless','settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'tcp'}}],
        'outbounds':[{'tag':'DIRECT','protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}}]})
    save('panel.json',{'safe_period_reset':bool(os.environ.get('DURABLE_CORE')),'node_tokens':{'node1':TOKEN,'node2':TOKEN[:-1]+'2','node3':TOKEN[:-1]+'3'}})
    migrate=start('alembic',[sys.executable,'-m','alembic','upgrade','head']);check('upstream_migration',migrate.wait(timeout=40)==0)
    pp,admin=panel('baseline',False)
    request('/api/admin',{'username':'labadmin','password':ENV['SUDO_PASSWORD'],'is_sudo':True},token=admin)
    users={}
    for name,auth in [('alice',A),('bob',B)]:
        users[name]=request('/api/user',{'username':name,'proxies':{'vless':{'id':auth}},'inbounds':{'vless':['VLESS_TEST']},'data_limit':0},token=admin)
    oldurl=users['alice']['subscription_url']
    baseline=request(oldurl)
    check('baseline_subscription_has_vless',b'vless://' in base64.b64decode(baseline))
    if os.environ.get('LEGACY_SHARE')=='1':
        lines=base64.b64decode(baseline).decode().splitlines()
        hy=[line for line in lines if line.startswith('hysteria2://')]
        check('legacy_patch_preserves_both_hy2_urls_and_uuid',len(hy)==2 and all(A+'@' in line for line in hy))
    with sqlite3.connect(STATE/'db.sqlite3') as db:
        identity_before=db.execute('SELECT username,created_at,sub_revoked_at FROM users ORDER BY id').fetchall()
        secret_before=db.execute('SELECT * FROM jwt').fetchall()
    stop(pp);pp,admin=panel('extended')
    check('old_subscription_url_and_payload_unchanged',request(oldurl)==baseline)
    with sqlite3.connect(STATE/'db.sqlite3') as db:
        check('user_dates_and_signing_key_unchanged',identity_before==db.execute('SELECT username,created_at,sub_revoked_at FROM users ORDER BY id').fetchall()
              and secret_before==db.execute('SELECT * FROM jwt').fetchall())
    for path,token in [('/api/hy2/nodes/node2/policy',TOKEN),('/api/hy2/report',TOKEN)]:
        try:request(path,token=token);denied=False
        except urllib.error.HTTPError as e:denied=e.code in (401,403)
        check('scoped_token_denied_'+path.rsplit('/',1)[-1],denied)
    hy1,ag1=node(1);hy2,ag2=node(2)
    for name,auth,server,port in [('a1',A,14443,18101),('a2',A,14443,18102),('a3',A,14444,18103),('b1',B,14443,18104)]:
        hyclient(name,auth,server,port)
    wait(lambda:fresh(18104))
    a1,a2,a3,b=conn(18101),conn(18102),conn(18103),conn(18104)
    check('hy2_multi_node_multi_device_tcp',all(echo(s) for s in [a1,a2,a3,b]))
    check('hy2_udp',udp(18201) and udp(18204))
    wait(lambda:request('/api/user/alice',token=admin)['used_traffic']>=7168)
    report=request('/api/hy2/report',token=admin)
    check('hy2_usage_in_panel_and_per_node_report',{'node1','node2'} <= {r['node'] for r in report['usage']})
    # Stop one node agent to replay its last acknowledged cumulative snapshot exactly.
    stop(ag2)
    with sqlite3.connect(STATE/'spool2.db') as db:
        spool,seq=db.execute('SELECT id,seq FROM meta').fetchone()
        batch={'spool':spool,'seq':seq,'totals':{a:{'tx':tx,'rx':rx} for a,tx,rx in db.execute('SELECT * FROM totals')}}
    ack=request('/api/hy2/nodes/node2/usage',batch,token=TOKEN[:-1]+'2')
    # It can be the first acceptance if the agent stopped between durable capture and HTTP delivery.
    duplicate=request('/api/hy2/nodes/node2/usage',batch,token=TOKEN[:-1]+'2')
    check('http_replay_after_lost_ack_no_double_charge',duplicate['duplicate'] and duplicate['added']==0)
    changed=json.loads(json.dumps(batch));changed['totals'][A]['tx']+=1
    try:request('/api/hy2/nodes/node2/usage',changed,token=TOKEN[:-1]+'2');rejected=False
    except urllib.error.HTTPError as e:rejected=e.code==409
    check('altered_replay_http_409',rejected)
    invalid=json.loads(json.dumps(batch));invalid['seq']=True
    try:request('/api/hy2/nodes/node2/usage',invalid,token=TOKEN[:-1]+'2');rejected=False
    except urllib.error.HTTPError as e:rejected=e.code==422
    check('malformed_counter_batch_http_422',rejected)
    ag2=start('agent2-restarted',[sys.executable,'-m','hy2bridge.node','--config',str(STATE/'agent2.json')])
    wait(lambda:request('http://127.0.0.1:18889/health')['fresh'])
    before=request('/api/user/alice',token=admin)['used_traffic']
    vconfig=save('vless-client.json',{'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':18110,
        'protocol':'dokodemo-door','settings':{'address':'127.0.0.1','port':18080,'network':'tcp'}}],
        'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':16443,
            'users':[{'id':A,'encryption':'none'}]}]}}]})
    start('vless-client',['/lab/bin/xray','run','-c',vconfig])
    wait(lambda:fresh(18110))
    wait(lambda:request('/api/user/alice',token=admin)['used_traffic']>before)
    hy_usage=sum(r['tx']+r['rx'] for r in request('/api/hy2/report',token=admin)['usage'] if r['username']=='alice')
    check('native_vless_and_hy2_combined_usage',request('/api/user/alice',token=admin)['used_traffic']>hy_usage)
    used=request('/api/user/alice',token=admin)['used_traffic']
    request('/api/user/alice',{'data_limit':used+4000},method='PUT',token=admin)
    quota_started=time.monotonic()
    check('traffic_crosses_limit',echo(a1,4096))
    wait(lambda:request('/api/user/alice',token=admin)['status']=='limited')
    blocked={}
    def all_blocked():
        for name,s in [('a1',a1),('a2',a2),('a3',a3)]:
            if name not in blocked and not echo(s):blocked[name]=True
        return len(blocked)==3
    wait(all_blocked,20)
    check('quota_disconnects_all_three_hy2_sessions',len(blocked)==3,
          elapsed_seconds=round(time.monotonic()-quota_started,3),
          observed_overrun_bytes=max(0,request('/api/user/alice',token=admin)['used_traffic']-(used+4000)))
    check('quota_blocks_udp_and_new_connections',not udp(18201) and not fresh(18101) and not fresh(18110))
    check('other_user_existing_connection_survives',echo(b) and udp(18204))
    request('/api/user/alice/reset',method='POST',token=admin)
    request('/api/user/alice',{'data_limit':0,'status':'active'},method='PUT',token=admin)
    wait(lambda:request('http://127.0.0.1:18888/auth',{'auth':A})['ok'])
    hyclient('a-restored',A,14443,18105)
    wait(lambda:fresh(18105))
    check('same_uuid_and_old_subscription_after_reset',request(oldurl)==baseline)
    restored=conn(18105);check('restored_tcp',echo(restored))
    request('/api/user/alice',{'status':'disabled'},method='PUT',token=admin)
    wait(lambda:not echo(restored))
    check('manual_disable_disconnects',not fresh(18105) and echo(b))
    if os.environ.get('RESET_FIX')=='1':
        reset=request('/api/user/alice/reset',method='POST',token=admin)
        check('reset_does_not_reenable_disabled_user',reset['status']=='disabled')
    request('/api/user/alice',{'status':'active','expire':int(time.time())+5},method='PUT',token=admin)
    wait(lambda:request('http://127.0.0.1:18888/auth',{'auth':A})['ok'])
    hyclient('a-expiring',A,14443,18106);wait(lambda:fresh(18106))
    exp=conn(18106)
    wait(lambda:request('/api/user/alice',token=admin)['status']=='expired')
    wait(lambda:not echo(exp))
    check('expiration_disconnects',not fresh(18106) and echo(b))
    request('/api/user/alice',{'status':'active','expire':0,'data_limit':0},method='PUT',token=admin)
    # Agent restart must preserve both accounting cursors and accumulated totals.
    time.sleep(1)
    used=request('/api/user/bob',token=admin)['used_traffic']
    stop(ag1)
    ag1=start('agent1-restarted',[sys.executable,'-m','hy2bridge.node','--config',str(STATE/'agent1.json')])
    wait(lambda:request('http://127.0.0.1:18888/health')['fresh'])
    check('agent_restart_does_not_rebill',request('/api/user/bob',token=admin)['used_traffic']==used)
    check('agent_restart_preserves_other_user_session',echo(b))
    time.sleep(1)
    used=request('/api/user/bob',token=admin)['used_traffic']
    stop(ag1)
    check('traffic_during_collector_outage',echo(b,2048))
    ag1=start('agent1-buffer-recovered',[sys.executable,'-m','hy2bridge.node','--config',str(STATE/'agent1.json')])
    wait(lambda:request('/api/user/bob',token=admin)['used_traffic']==used+4096)
    check('collector_outage_catches_up_exact_bytes',request('/api/user/bob',token=admin)['used_traffic']==used+4096)
    # Panel outage: no indefinite cached authorization; existing sessions are reconciled.
    stop(pp);time.sleep(3)
    wait(lambda:not echo(b),10)
    check('panel_outage_expires_cached_auth_and_kicks',not fresh(18104))
    pp,admin=panel('panel-recovered')
    wait(lambda:request('http://127.0.0.1:18888/health')['fresh'])
    hyclient('b-recovered',B,14443,18107);wait(lambda:fresh(18107))
    check('panel_recovery_restores_same_credentials',request(oldurl)==baseline)
    # A new Hysteria process epoch can start from zero without replaying old usage.
    time.sleep(1)
    before=request('/api/user/bob',token=admin)['used_traffic']
    stop(hy1)
    if os.environ.get('DURABLE_CORE'):ENV['FLEET_TRAFFIC_WAL']=str(STATE/'hy1.wal')
    hy1=start('hy1-restarted',[os.environ.get('DURABLE_CORE','/lab/bin/hysteria'),'server','-c',str(STATE/'hy1.json')])
    ENV.pop('FLEET_TRAFFIC_WAL',None)
    (STATE/'hy1.pid').write_text(str(hy1.pid))
    wait(lambda:request('http://127.0.0.1:18888/health')['fresh'])
    hyclient('b-new-epoch',B,14443,18108);wait(lambda:fresh(18108))
    wait(lambda:request('/api/user/bob',token=admin)['used_traffic']>before)
    after=request('/api/user/bob',token=admin)['used_traffic']
    check('hysteria_restart_new_epoch_accounted',0<after-before<20000,delta=after-before)
    check('final_old_subscription_works',request(oldurl)==baseline)
    if os.environ.get('DURABLE_CORE'):
        stop(ag2)
        before_reset=request('/api/user/alice',token=admin)['used_traffic']
        try:request('/api/user/alice/reset',method='POST',token=admin);deferred=False
        except urllib.error.HTTPError as e:deferred=e.code==409
        check('offline_node_defers_reset_without_losing_usage',deferred and request('/api/user/alice',token=admin)['used_traffic']==before_reset)
        ag2=start('agent2-after-deferred-reset',[sys.executable,'-m','hy2bridge.node','--config',str(STATE/'agent2.json')])
        wait(lambda:request('http://127.0.0.1:18889/health')['fresh'])
        hold='44444444-4444-4444-8444-444444444444'
        user=request('/api/user',{'username':'onhold','status':'on_hold','on_hold_expire_duration':600,
            'proxies':{'vless':{'id':hold}},'inbounds':{'vless':['VLESS_TEST']},'data_limit':0},token=admin)
        hold_url=user['subscription_url']
        wait(lambda:request('http://127.0.0.1:18888/auth',{'auth':hold})['ok'])
        check('on_hold_auth_does_not_start_expiry',request('/api/user/onhold',token=admin)['status']=='on_hold')
        hyclient('onhold-client',hold,14443,18117);wait(lambda:fresh(18117))
        wait(lambda:request('/api/user/onhold',token=admin)['status']=='active')
        held=request('/api/user/onhold',token=admin)
        check('on_hold_first_payload_starts_native_expiry',time.time()+550<held['expire']<time.time()+610)
        request('/api/user/onhold',{'data_limit':held['used_traffic']+1024,'next_plan':{
            'data_limit':1000000,'expire':int(time.time())+600,'add_remaining_traffic':True,'fire_on_either':True}},method='PUT',token=admin)
        stop(ag2)
        request('/api/user',{'username':'reviewprobe','expire':int(time.time())+3,
            'proxies':{'vless':{'id':'55555555-5555-4555-8555-555555555555'}},
            'inbounds':{'vless':['VLESS_TEST']},'data_limit':0},token=admin)
        with conn(18117) as s:check('next_plan_trigger_payload',echo(s,8192))
        wait(lambda:request('/api/user/reviewprobe',token=admin)['status']=='expired',10)
        check('waiting_next_plan_does_not_starve_other_user_expiry',request('/api/user/onhold',token=admin)['next_plan'] is not None)
        ag2=start('agent2-after-next-plan-wait',[sys.executable,'-m','hy2bridge.node','--config',str(STATE/'agent2.json')])
        wait(lambda:request('/api/user/onhold',token=admin)['next_plan'] is None,25)
        renewed=request('/api/user/onhold',token=admin)
        check('next_plan_drained_then_reset',renewed['status']=='active' and renewed['data_limit']==1000000 and renewed['used_traffic']==0)
        check('next_plan_old_subscription_valid',bool(request(hold_url)))
    # Own-process supervision: neither a dead collector nor a dead stats API can
    # leave the dedicated Hysteria daemon forwarding indefinitely.
    hyclient('b-control-node2',B,14444,18111);wait(lambda:fresh(18111))
    control=conn(18111)
    outage={'active':False}
    class StatsProxy(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if outage['active']:
                self.send_error(503);return
            req=urllib.request.Request('http://127.0.0.1:19996'+self.path,
                headers={'Authorization':'synthetic-stats-secret'})
            with HTTP.open(req,timeout=2) as r:raw=r.read()
            self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_POST(self):
            if outage['active']:
                self.send_error(503);return
            raw=self.rfile.read(int(self.headers.get('Content-Length',0)))
            req=urllib.request.Request('http://127.0.0.1:19996'+self.path,data=raw,
                headers={'Authorization':'synthetic-stats-secret','Content-Type':'application/json'})
            with HTTP.open(req,timeout=2) as r:body=r.read()
            self.send_response(200);self.send_header('Content-Length',str(len(body)))
            self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    proxy=http.server.ThreadingHTTPServer(('127.0.0.1',19995),StatsProxy)
    threading.Thread(target=proxy.serve_forever,daemon=True).start()
    hycfg=save('supervised-hy.json',{'listen':'127.0.0.1:14445',
        'tls':{'cert':'/lab/config/cert.pem','key':'/lab/config/key.pem'},
        'auth':{'type':'http','http':{'url':'http://127.0.0.1:18890/auth'}},
        'trafficStats':{'listen':'127.0.0.1:19996','secret':'synthetic-stats-secret'}})
    agentcfg=save('supervised-agent.json',{'panel_url':BASE+'/api/hy2/nodes/node3',
        'node_token':TOKEN[:-1]+'3','stats_url':'http://127.0.0.1:19995','stats_secret':'synthetic-stats-secret',
        'auth_port':18890,'spool':str(STATE/'spool3.db'),'pid_file':str(STATE/'hy3.pid'),
        'interval':.25,'policy_ttl':2})
    args=[sys.executable,'-m','hy2bridge.supervisor','--node-config',agentcfg,
          '--hysteria','/lab/bin/hysteria','--hysteria-config',hycfg,'--grace','4']
    supervisor=start('supervisor-1',args)
    wait(lambda:request('http://127.0.0.1:18890/health')['fresh'])
    hyclient('b-supervised',B,14445,18112);wait(lambda:fresh(18112));owned=conn(18112)
    os.kill(int((STATE/'hy3.pid.agent').read_text()),signal.SIGKILL)
    wait(lambda:supervisor.poll() is not None)
    check('collector_crash_stops_owned_hysteria',supervisor.returncode==1 and not echo(owned) and echo(control))
    supervisor=start('supervisor-2',args)
    wait(lambda:request('http://127.0.0.1:18890/health')['fresh'])
    hyclient('b-stats-outage',B,14445,18113);wait(lambda:fresh(18113));owned=conn(18113)
    outage['active']=True
    wait(lambda:supervisor.poll() is not None,15)
    check('stats_api_outage_stops_owned_hysteria',supervisor.returncode==1 and not echo(owned) and echo(control))
    outage['active']=False
    supervisor=start('supervisor-3',args)
    wait(lambda:request('http://127.0.0.1:18890/health')['fresh'])
    hyclient('b-parent-death',B,14445,18114);wait(lambda:fresh(18114));owned=conn(18114)
    os.kill(supervisor.pid,signal.SIGKILL);supervisor.wait(timeout=3)
    wait(lambda:not echo(owned),10)
    check('supervisor_crash_terminates_children',not fresh(18114) and echo(control))
    # Deletion must not poison the entire node's cumulative ledger with tail usage.
    c='33333333-3333-4333-8333-333333333333'
    request('/api/user',{'username':'charlie','proxies':{'vless':{'id':c}},
                        'inbounds':{'vless':['VLESS_TEST']},'data_limit':0},token=admin)
    wait(lambda:request('http://127.0.0.1:18889/auth',{'auth':c})['ok'])
    hyclient('c-deleted',c,14444,18115);wait(lambda:fresh(18115));deleted=conn(18115)
    check('deleted_user_initial_traffic',echo(deleted))
    request('/api/user/charlie',method='DELETE',token=admin)
    wait(lambda:not echo(deleted))
    wait(lambda:request('http://127.0.0.1:18889/health')['fresh'])
    check('user_deletion_kicks_without_poisoning_other_users',not fresh(18115) and echo(control))
    check('deleted_user_audit_retained',any(r['username']=='charlie' for r in request('/api/hy2/report',token=admin)['usage']))
    final=request('/api/hy2/report',token=admin)
    fleet=request('/api/fleet/overview',token=admin)
    check('fleet_live_health',any(n['state']=='healthy' for n in fleet['nodes']))
    traffic=request('/api/fleet/traffic',token=admin)
    check('fleet_real_usage_report',traffic['total']>0 and traffic['totals']['hysteria2']>0)
    check('native_report_retained_across_user_resets',traffic['totals']['xray']>0)
    check('fleet_csv_export',b'username' in request('/api/fleet/traffic.csv',token=admin))
    check('rime_ui_served',b'Rime' in request('/fleet'))
    try:request('/api/fleet/traffic');denied=False
    except urllib.error.HTTPError as e:denied=e.code in (401,403)
    check('fleet_requires_admin',denied)
    save('accounting-report.json',final)
    save('restore-proof.json',{'old_url':oldurl,'payload':base64.b64encode(baseline).decode()})
    with sqlite3.connect(STATE/'db.sqlite3') as db:
        check('sqlite_integrity',db.execute('PRAGMA integrity_check').fetchone()[0]=='ok')


if __name__=='__main__':
    try:main()
    finally:
        for proc in reversed(PROCESSES):stop(proc)
        for log in LOGS:log.close()
        (STATE/'results.json').write_text(json.dumps(RESULTS,indent=2))
        print(json.dumps({'passed':sum(x['passed'] for x in RESULTS),'checks':len(RESULTS),'state':str(STATE)}),flush=True)
