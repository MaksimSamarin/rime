"""Local auth + statistics reconciler. API traffic bypasses environment proxies."""
import argparse
import fcntl
import http.server
import json
import logging
import os
from pathlib import Path
import threading
import time
import urllib.request
import ssl
from urllib.parse import urlsplit

from .spool import Spool


LOG = logging.getLogger('hy2bridge')


class HTTP:
    def __init__(self,ca_file=None):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,req,fp,code,msg,headers,newurl):return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))

    def request(self, url, token, data=None, bearer=True):
        request = urllib.request.Request(url,
            data=json.dumps(data).encode() if data is not None else None,
            headers={'Authorization': ('Bearer ' if bearer else '')+token,'Content-Type':'application/json'})
        with self.opener.open(request,timeout=2) as response:
            raw = response.read(4*1024*1024+1)
            if len(raw)>4*1024*1024:
                raise ValueError('Response too large')
            return json.loads(raw) if raw else {}


class Agent:
    def __init__(self, config):
        self.config = config
        # Non-TLS transport is allowed only within this local test topology.
        for name in ('panel_url','stats_url'):
            url=urlsplit(config[name])
            if url.scheme not in ('http','https') or (url.scheme=='http' and url.hostname not in ('127.0.0.1','localhost','::1')):
                raise ValueError('Remote endpoints must use verified HTTPS')
        if config.get('auth_host','127.0.0.1') != '127.0.0.1':
            raise ValueError('Local auth endpoint must bind loopback')
        self.http = HTTP(config.get('panel_ca'))
        self.spool = Spool(config['spool'])
        self.allowed = frozenset()
        self.last_success = 0.0
        self.last_error = None
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.kick_attempts = 0
        self.started_at=time.monotonic()
        self.last_heartbeat=0.0
        self.accounting_durable=False
        self.barrier_seen={}

    def epoch(self):
        pid=int(Path(self.config['pid_file']).read_text().strip())
        stat=Path(f'/proc/{pid}/stat').read_text()
        # comm can contain spaces and parentheses; fields after the final ')' start with state.
        rest=stat.rsplit(')',1)[1].split()
        if rest[0]=='Z':
            raise RuntimeError('Hysteria process is a zombie')
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+str(pid)+':'+rest[19]

    def permits(self, auth):
        with self.lock:
            return time.monotonic()-self.last_success < self.config.get('policy_ttl',5) and auth in self.allowed

    def cycle(self):
        cfg=self.config
        barriers=[]
        try:
            if cfg.get('durable',False):
                snapshot=self.http.request(cfg['stats_url']+'/fleet/snapshot',cfg['stats_secret'],bearer=False)
                if snapshot.get('durable') is not True:raise RuntimeError('Durable ledger is required')
                epoch='ledger:'+snapshot['ledger'];stats=snapshot['totals'];self.accounting_durable=True
            else:
                epoch=self.epoch()
                stats=self.http.request(cfg['stats_url']+'/traffic',cfg['stats_secret'],bearer=False)
                if epoch != self.epoch():
                    raise RuntimeError('Hysteria restarted during snapshot')
            batch=self.spool.observe(epoch,stats)
            response=self.http.request(cfg['panel_url']+'/usage',cfg['node_token'],batch)
            if response.get('accepted') != batch['seq']:
                raise ValueError('Panel did not acknowledge sequence')
            policy=self.http.request(cfg['panel_url']+'/policy',cfg['node_token'])
            allowed=policy['allowed']
            barriers=policy.get('barriers',[])
            if not isinstance(allowed,list) or not all(isinstance(x,str) for x in allowed):
                raise ValueError('Invalid policy')
            with self.lock:
                self.allowed=frozenset(allowed)
                self.last_success=time.monotonic()
                self.last_error=None
        except Exception as exc:
            with self.lock:
                changed=self.last_error != type(exc).__name__
                self.last_error=type(exc).__name__
            if changed:
                LOG.warning('Reconciliation failed (%s); authorization expires after policy TTL',type(exc).__name__)
        # Enforcement is independent of whether accounting/panel access succeeded.
        # A fresh denial is effective before a kick, preventing reconnect races.
        try:
            online=self.http.request(cfg['stats_url']+'/online',cfg['stats_secret'],bearer=False)
            blocked=[auth for auth in online if not self.permits(auth)]
            if blocked:
                path='/fleet/kick' if cfg.get('durable',False) else '/kick'
                self.http.request(cfg['stats_url']+path,cfg['stats_secret'],blocked,bearer=False)
                self.kick_attempts += 1
        except Exception as exc:
            LOG.warning('Session enforcement unavailable (%s)',type(exc).__name__)
            online=None
            with self.lock:
                self.last_error='EnforcementUnavailable'
                self.last_success=0.0
        if cfg.get('durable') and online is not None and not self.last_error:
            active_ids={b['id'] for b in barriers}
            self.barrier_seen={k:v for k,v in self.barrier_seen.items() if k in active_ids}
            for barrier in barriers:
                try:
                    # Deny first, close idle sessions too, and outwait any auth
                    # request already in flight before acknowledging the drain.
                    self.http.request(cfg['stats_url']+'/fleet/kick',cfg['stats_secret'],barrier['auths'],bearer=False)
                    since=self.barrier_seen.setdefault(barrier['id'],time.monotonic())
                    if time.monotonic()-since<cfg.get('policy_ttl',5)+2:continue
                    snapshot=self.http.request(cfg['stats_url']+'/fleet/snapshot',cfg['stats_secret'],bearer=False)
                    batch=self.spool.observe('ledger:'+snapshot['ledger'],snapshot['totals'])
                    result=self.http.request(cfg['panel_url']+'/usage',cfg['node_token'],batch)
                    if result.get('accepted')!=batch['seq']:continue
                    self.http.request(cfg['panel_url']+'/barrier',cfg['node_token'],{'id':barrier['id'],'seq':batch['seq']})
                except Exception:pass
        if time.monotonic()-self.last_heartbeat>=cfg.get('heartbeat_interval',5):
            self.last_heartbeat=time.monotonic()
            try:
                memory={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc/meminfo').read_text().splitlines()}
                fs=os.statvfs(Path(cfg['spool']).parent)
                payload={'error':('stats_unavailable' if self.last_error=='EnforcementUnavailable' else 'accounting_failed') if self.last_error else None,
                    'uptime_seconds':int(time.monotonic()-self.started_at),'accounting_durable':self.accounting_durable,
                    'core_version':cfg.get('core_version','unknown'),'kick_attempts':self.kick_attempts,
                    'online_users':len(online) if online is not None else None,
                    'online_connections':sum(online.values()) if online is not None else None,
                    'mem_available_bytes':int(memory['MemAvailable'].split()[0])*1024,
                    'disk_free_bytes':fs.f_bavail*fs.f_frsize,'cpu_load1':os.getloadavg()[0]}
                self.http.request(cfg['panel_url']+'/health',cfg['node_token'],payload)
            except Exception:
                # A telemetry failure must not discard already durable usage or
                # overwrite the control lease; stale heartbeats are visible centrally.
                pass

    def run(self):
        while not self.stop.is_set():
            self.cycle()
            self.stop.wait(self.config.get('interval',1))

    def handler(self):
        agent=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != '/auth':
                    self.send_error(404);return
                try:
                    size=int(self.headers.get('Content-Length','0'))
                    if not 0<size<=4096:
                        self.send_error(413);return
                    self.connection.settimeout(2)
                    data=json.loads(self.rfile.read(size))
                    auth=data.get('auth','')
                    ok=isinstance(auth,str) and agent.permits(auth)
                    raw=json.dumps({'ok':ok,'id':auth if ok else ''}).encode()
                    self.send_response(200)
                    self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(raw)))
                    self.end_headers();self.wfile.write(raw)
                except (ValueError,TypeError,AttributeError):
                    self.send_error(400)
            def do_GET(self):
                if self.path!='/health':
                    self.send_error(404);return
                with agent.lock:
                    healthy=time.monotonic()-agent.last_success < agent.config.get('policy_ttl',5)
                    raw=json.dumps({'fresh':healthy,'error':agent.last_error,'kick_attempts':agent.kick_attempts}).encode()
                self.send_response(200 if healthy else 503)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(raw)))
                self.end_headers();self.wfile.write(raw)
            def log_message(self,*args):
                pass
        return Handler


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True)
    args=parser.parse_args()
    os.umask(0o077)
    config=json.loads(Path(args.config).read_text())
    # The lock is per spool. Two agents must never compete for one counter cursor.
    with open(config['spool']+'.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        agent=Agent(config)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',config['auth_port']),agent.handler())
        threading.Thread(target=agent.run,daemon=True).start()
        try:
            server.serve_forever()
        finally:
            agent.stop.set();server.server_close()


if __name__=='__main__':
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    main()
