"""Own a dedicated Hysteria process and recover its local agent independently.

Never attaches to an existing server process. An orchestration service may restart
this entire unit after failure. A node-wide outage disconnects all users on that
node; normal individual quota enforcement remains targeted.
"""
import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from .node import HTTP


def parent_death_signal():
    parent=os.getppid()
    if ctypes.CDLL(None).prctl(1,signal.SIGTERM,0,0,0)!=0:
        raise RuntimeError('Cannot install parent death signal')
    if os.getppid()!=parent:
        os.kill(os.getpid(),signal.SIGTERM)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--node-config',required=True)
    p.add_argument('--hysteria',required=True)
    p.add_argument('--hysteria-config',required=True)
    p.add_argument('--grace',type=float,default=15)
    args=p.parse_args()
    if args.grace<3:raise ValueError('grace must be at least 3 seconds')
    cfg=json.loads(Path(args.node_config).read_text())
    os.umask(0o077)
    children=[]
    stopping=False
    def stopped(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stopped)
    signal.signal(signal.SIGINT,stopped)
    with open(cfg['spool']+'.supervisor.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            child_env=os.environ.copy()
            if cfg.get('durable',False):
                child_env['FLEET_TRAFFIC_WAL']=cfg['traffic_wal']
            hy=subprocess.Popen([args.hysteria,'server','-c',args.hysteria_config],preexec_fn=parent_death_signal,env=child_env)
            children.append(hy)
            target=Path(cfg['pid_file'])
            temporary=target.with_suffix('.new')
            temporary.write_text(str(hy.pid));temporary.replace(target)
            agent=subprocess.Popen([sys.executable,'-m','hy2bridge.node','--config',args.node_config],preexec_fn=parent_death_signal)
            children.append(agent)
            Path(cfg['pid_file']+'.agent').write_text(str(agent.pid))
            while not stopping:
                if hy.poll() is not None:
                    print('Hysteria exited; node service must recover',flush=True)
                    return 1
                if agent.poll() is not None:
                    agent.wait()
                    print('Recovering local authorization agent; Hysteria remains running',flush=True)
                    agent=subprocess.Popen([sys.executable,'-m','hy2bridge.node','--config',args.node_config],preexec_fn=parent_death_signal)
                    children[1]=agent
                    Path(cfg['pid_file']+'.agent').write_text(str(agent.pid))
                    time.sleep(1)
                time.sleep(.2)
            return 0
        finally:
            for c in reversed(children):
                if c.poll() is None:c.terminate()
            for c in children:
                try:c.wait(timeout=3)
                except subprocess.TimeoutExpired:c.kill();c.wait()


if __name__=='__main__':raise SystemExit(main())
