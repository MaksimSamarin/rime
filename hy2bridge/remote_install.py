"""Fixed SSH worker. Input arrives on stdin, never in a shell command line.

Only manages a new, labelled Docker container and its own directory. Failed
installs retain their data for investigation; no host packages/firewall changes.
"""
import json
import hashlib
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
DIAGNOSTIC=None


def run(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=180)
    if p.returncode:
        if DIAGNOSTIC:DIAGNOSTIC.write_text(p.stderr[-16384:])
        raise RuntimeError('Command failed: '+args[0])
    return p.stdout


def main(c):
    global DIAGNOSTIC
    os.umask(0o077)
    assert re.fullmatch('[a-f0-9]{32}',c['id'])
    directory=Path.home()/'.local/share/fleet-nodes'/c['id']
    name='fleet-'+c['id']
    if c['action']=='preflight':
        checks=[]
        checks.append({'passed':sys.platform=='linux','message':'Linux / Python 3'})
        try:run(['docker','info','--format','{{.ServerVersion}}']);ok=True
        except Exception:ok=False
        checks.append({'passed':ok,'message':'Docker доступен текущему SSH-пользователю'})
        for port,proto in c['ports']:
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM)
            try:s.bind(('0.0.0.0',port));ok=True
            except OSError:ok=False
            finally:s.close()
            checks.append({'passed':ok,'message':f'Порт {port}/{proto} свободен'})
        stat=os.statvfs(Path.home())
        checks.append({'passed':stat.f_bavail*stat.f_frsize>2*1024**3,'message':'Свободно более 2 GiB'})
        checks.append({'passed':not directory.exists(),'message':'Новая отдельная директория'})
        memory=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))*1024
        return {'checks':checks,'home':str(Path.home()),'uid':os.getuid(),'gid':os.getgid(),'mem_total_bytes':memory}
    if c['action']=='rollback':
        observer='fleet-observer-'+c['id']
        found=subprocess.run(['docker','inspect',observer],capture_output=True,text=True)
        if found.returncode==0:
            info=json.loads(found.stdout)[0]
            if info['Config']['Labels'].get('fleet.job')!=c['id']:raise RuntimeError('Observer ownership mismatch')
            run(['docker','rm','-f',observer])
        try:info=json.loads(run(['docker','inspect',name]))[0]
        except Exception:return {'removed':False}
        if info['Config']['Labels'].get('fleet.job')!=c['id']:raise RuntimeError('Ownership mismatch')
        log=subprocess.run(['docker','logs','--tail','30',name],capture_output=True,text=True,timeout=5)
        (directory/'rollback-runtime.log').write_text((log.stdout+log.stderr)[-16384:])
        run(['docker','rm','-f',name])
        return {'removed':True,'data_retained':True}
    if c['action']=='observer':
        assert directory.resolve()==directory and not directory.is_symlink()
        main=json.loads(run(['docker','inspect',name]))[0]
        if main['Config']['Labels'].get('fleet.job')!=c['id'] or not main['State']['Running']:raise RuntimeError('VPN container ownership or state mismatch')
        observer='fleet-observer-'+c['id'];home=directory/'observer'
        if home.is_symlink():raise RuntimeError('Observer directory is a symlink')
        home.mkdir(mode=0o700,exist_ok=True);DIAGNOSTIC=directory/'observer-error.log'
        allowed={'observer.py','connections.py','meter.py','spool.py','config.json','panel-ca.pem'}
        if not set(c['files'])<=allowed or 'config.json' not in c['files']:raise ValueError('Invalid observer files')
        digest=hashlib.sha256(json.dumps(c['files'],sort_keys=True).encode()).hexdigest()
        for filename,content in c['files'].items():
            path=home/filename
            if path.is_symlink() or (path.exists() and path.read_text()!=content):raise RuntimeError('Existing observer configuration differs')
        for filename,content in c['files'].items():
            if not (home/filename).exists():(home/filename).write_text(content)
        existing=subprocess.run(['docker','inspect',observer],capture_output=True,text=True)
        if existing.returncode==0:
            info=json.loads(existing.stdout)[0];labels=info['Config'].get('Labels',{})
            if labels.get('fleet.job')!=c['id'] or labels.get('fleet.observer.config')!=digest:raise RuntimeError('Existing observer ownership differs')
            if not info['State']['Running']:run(['docker','start',observer])
            return {'running':True,'already_configured':True}
        image=c['image']
        if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}',image):raise ValueError('Observer image must be pinned')
        args=['docker','run','-d','--name',observer,'--label','fleet.job='+c['id'],'--label','fleet.observer.config='+digest,
            '--restart','unless-stopped','--cpus','0.1','--memory','64m','--pids-limit','32','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=8m',
            '--network','container:'+name,'--pid','container:'+name,'--user',f'{os.getuid()}:{os.getgid()}',
            '--log-driver','json-file','--log-opt','max-size=2m','--log-opt','max-file=2',
            '--mount',f'type=bind,src={home},dst=/observer,readonly']
        for filename in ['meminfo','stat','uptime','loadavg']:
            args+=['--mount',f'type=bind,src=/proc/{filename},dst=/proc/{filename},readonly']
        args+=['--entrypoint','python',image,'/observer/observer.py','--config','/observer/config.json']
        run(args)
        return {'running':json.loads(run(['docker','inspect',observer]))[0]['State']['Running'],'already_configured':False}
    if c['action']=='status':
        info=json.loads(run(['docker','inspect',name]))[0]
        return {'running':info['State']['Running'],'restarts':info['RestartCount']}
    if c['action']!='install':raise ValueError('Unknown action')
    os.umask(0o077)
    directory.mkdir(parents=True,exist_ok=False)
    DIAGNOSTIC=directory/'install-error.log'
    for filename,content in c['files'].items():
        if not re.fullmatch('[A-Za-z0-9_.-]+',filename):raise ValueError('Invalid filename')
        (directory/filename).write_text(content)
    image=c['image']
    if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}',image):raise ValueError('Image must be pinned')
    try:run(['docker','image','inspect',image])
    except Exception:run(['docker','pull',image])
    args=['docker','run','-d','--name',name,'--label','fleet.job='+c['id'],
          '--restart','unless-stopped','--cpus','1','--memory','512m','--pids-limit','128',
          '--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3',
          '--cap-drop','ALL','--security-opt','no-new-privileges','--read-only',
          '--tmpfs','/tmp:rw,noexec,nosuid,size=32m']
    # Network override is server configuration only, never accepted from the UI.
    if c.get('lab_network'):args+=['--network',c['lab_network']]
    else:
        for outside,inside,proto in c['publish']:args+=['-p',f'{outside}:{inside}/{proto}']
    args+=['--mount',f'type=bind,src={directory},dst=/state']
    for source,target in c.get('mounts',[]):
        if source not in c['files'] or not target.startswith('/'):raise ValueError('Invalid mount')
        args+=['--mount',f'type=bind,src={directory/source},dst={target},readonly']
    for key,value in c.get('env',{}).items():args+=['-e',key+'='+value]
    if c['protocol']=='hysteria2':
        bundle=Path(c['bundle'])
        if bundle.parent!=directory.parent or bundle.name!=c['id']+'.tar.gz':raise ValueError('Invalid bundle')
        import tarfile
        with tarfile.open(bundle) as archive:archive.extractall(directory,filter='data')
        (directory/'hysteria-fleet').chmod(0o700)
        args+=['--user',f'{os.getuid()}:{os.getgid()}','-e','PYTHONPATH=/state',image,
               'python','-m','hy2bridge.supervisor','--node-config','/state/agent.json',
               '--hysteria','/state/hysteria-fleet','--hysteria-config','/state/hysteria.json']
    else:args+=['--user',f'{os.getuid()}:{os.getgid()}',image]
    run(args)
    time.sleep(2)
    info=json.loads(run(['docker','inspect',name]))[0]
    if not info['State']['Running']:
        log=subprocess.run(['docker','logs','--tail','50',name],capture_output=True,text=True,timeout=5)
        DIAGNOSTIC.write_text((log.stdout+log.stderr)[-16384:])
    return {'directory':str(directory),'container':name,'running':info['State']['Running'],
            'ip':next((v['IPAddress'] for v in info['NetworkSettings'].get('Networks',{}).values() if v.get('IPAddress')),None)}


if __name__=='__main__':
    try:print(json.dumps(main(json.load(sys.stdin))))
    except Exception as exc:
        # Deliberately avoid remote command output and secrets in API errors.
        print(json.dumps({'error':type(exc).__name__}));sys.exit(1)
