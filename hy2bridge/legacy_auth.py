"""Local auth/enforcement for existing Hy2 nodes, independent of control delivery.

The observer's cumulative spool remains owned by its collector. This reader adds
the live, not-yet-observed counter tail without modifying the observer cursor.
"""
import argparse
import fcntl
import http.server
import json
import logging
import os
from pathlib import Path
import sqlite3
import threading
import time
from urllib.parse import urlsplit
from contextlib import closing

from .node import Agent, HTTP
from .meter import source_epoch
from .policy import LocalPolicy

LOG = logging.getLogger('hy2bridge.legacy_auth')


class LegacyAgent(Agent):
    def __init__(self, config):
        self.config=config
        url=urlsplit(config['auth_policy_url']);stats=urlsplit(config['stats_url'])
        local_test=bool(config.get('allow_loopback_http') and url.scheme=='http' and url.hostname in ('127.0.0.1','::1','localhost'))
        if (url.scheme!='https' and not local_test) or url.username or url.password or url.query or url.fragment:
            raise ValueError('Policy delivery requires verified HTTPS')
        if not url.path.startswith('/api/fleet/meters/') or not url.path.endswith('/policy'):
            raise ValueError('Invalid policy endpoint')
        if stats.hostname not in ('127.0.0.1','localhost','::1'):raise ValueError('Stats must remain loopback')
        self.http=HTTP(config.get('ca_file'))
        self.policy=LocalPolicy(config['auth_policy_db'])
        self.charged={}
        self.lock=threading.Lock()
        self.stop=threading.Event()
        self.last_success=0
        self.last_error=None
        self.kick_attempts=0
        self.sample_ready=False

    def permits(self, auth):
        with self.lock:
            # Finite budgets require a local counter snapshot, never central I/O.
            rule=(self.policy.value or {}).get('rules',{}).get(auth,{})
            return (self.sample_ready or rule.get('remaining_bytes') is None) and self.policy.permits(auth,self.charged)

    def sync(self):
        failed=False
        while not self.stop.is_set():
            try:
                value=self.http.request(self.config['auth_policy_url'],self.config['meter']['token'])
                with self.lock:
                    self.policy.replace(value)
                    self.last_success=time.monotonic();self.last_error=None
                if failed:LOG.info('Authorization policy synchronization recovered')
                failed=False
            except Exception as exc:
                with self.lock:self.last_error=type(exc).__name__
                if not failed:LOG.warning('Policy delivery unavailable; using local rules (%s)',type(exc).__name__)
                failed=True
            self.stop.wait(max(2,self.config.get('auth_sync_interval',10)))

    def cycle(self):
        cfg=self.config
        try:
            epoch=source_epoch(cfg['meter'])[0]
            stats=self.http.request(cfg['stats_url']+'/traffic',cfg['stats_secret'],bearer=False)
            if source_epoch(cfg['meter'])[0]!=epoch:raise RuntimeError('Core changed during sample')
            # A read transaction gives a consistent totals/raw pair while the
            # observer advances its own counters in an independent transaction.
            with closing(sqlite3.connect('file:'+str(Path(cfg['meter']['spool']).resolve())+'?mode=ro',uri=True,timeout=2)) as db:
                db.execute('BEGIN')
                totals={a:tx+rx for a,tx,rx in db.execute('SELECT * FROM totals')}
                raw={a:tx+rx for a,tx,rx in db.execute('SELECT auth,tx,rx FROM raw WHERE epoch=?',(epoch,))}
            for auth,value in stats.items():
                if any(type(value.get(k)) is not int or value[k]<0 for k in ('tx','rx')):raise ValueError('Invalid counter')
                totals[auth]=totals.get(auth,0)+max(0,value['tx']+value['rx']-raw.get(auth,0))
            with self.lock:self.charged=totals;self.sample_ready=True
            online=self.http.request(cfg['stats_url']+'/online',cfg['stats_secret'],bearer=False)
            # Bootstrap must not terminate existing sessions before a verified
            # policy has ever been received. New unknown access is still denied.
            denied=[auth for auth in online if not self.permits(auth)] if self.policy.value else []
            if denied and cfg.get('enforce',True):
                self.http.request(cfg['stats_url']+'/kick',cfg['stats_secret'],denied,bearer=False)
                self.kick_attempts+=1
        except Exception as exc:
            # Network control loss never changes local authorization. Local core
            # failures are observable, without restarting an otherwise live VPN.
            LOG.debug('Local enforcement sample unavailable (%s)',type(exc).__name__)

    def run(self):
        threading.Thread(target=self.sync,daemon=True).start()
        while not self.stop.is_set():
            self.cycle();self.stop.wait(1)

    def handler(self):
        class Handler(super().handler()):
            def do_POST(self):
                # Existing installations used both the root URL and /auth.
                if self.path=='/':self.path='/auth'
                return super().do_POST()
        return Handler


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);args=p.parse_args()
    os.umask(0o077);cfg=json.loads(Path(args.config).read_text())
    if cfg.get('auth_host','127.0.0.1')!='127.0.0.1':raise ValueError('Auth must bind loopback')
    with open(cfg['auth_policy_db']+'.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        agent=LegacyAgent(cfg)
        # Obtain counters before accepting finite-budget credentials after boot.
        agent.cycle()
        server=http.server.ThreadingHTTPServer(('127.0.0.1',cfg['auth_port']),agent.handler())
        threading.Thread(target=agent.run,daemon=True).start()
        try:server.serve_forever()
        finally:agent.stop.set();server.server_close()


if __name__=='__main__':
    logging.basicConfig(level=logging.INFO);main()
