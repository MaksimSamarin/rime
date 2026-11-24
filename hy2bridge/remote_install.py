"""Fixed SSH worker. Input arrives on stdin, never in a shell command line.

Manages labelled node containers, their private directories and their scoped
management-port firewall. Package preparation belongs to the bootstrap step.
"""
import json
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import shutil
import shlex
import sys
import time
DIAGNOSTIC=None
MANAGEMENT_IDENTITY_TIMEOUT = 30

if globals().get('__package__'):
    from .port_check import port_checks
    CONTROL_FIREWALL_WORKER=Path(__file__).with_name('control_firewall.py').read_text()


class RemoteError(RuntimeError):
    def __init__(self,code):
        self.code=code
        super().__init__(code)


def resolve_image(image,candidates=()):
    if not valid_image(image) or len(candidates)>32 or any(not re.fullmatch(r'sha256:[0-9a-f]{64}',value) for value in candidates):
        raise ValueError('Image must be pinned')
    for reference in dict.fromkeys([image,*candidates]):
        result=subprocess.run(['docker','image','inspect',reference],capture_output=True,text=True,timeout=20)
        if result.returncode==0:return reference
        if not re.search(r'No such (?:image|object)',result.stderr,re.IGNORECASE):
            raise RuntimeError('Docker image state cannot be confirmed')
    return None


def authenticated_management(c, image):
    if c['protocol'] != 'vless':
        return False
    info = json.loads(run(['docker', 'image', 'inspect', image]))[0]
    mode = info.get('Config', {}).get('Labels', {}).get('org.rime.management.auth')
    if mode != 'controller-mtls-v1':
        return False
    if c.get('env', {}).get('SSL_CLIENT_CERT_FILE') != '/state/client.pem':
        raise ValueError('Authenticated management requires the controller certificate file')
    certificate = c.get('files', {}).get('client.pem', '')
    if not certificate:
        raise ValueError('Authenticated management requires a controller certificate')
    ssl.PEM_cert_to_DER_cert(certificate)
    return True


def control_firewall(c,directory,remove=False,image=None):
    marker=directory/'control-firewall.json'
    chain='RIME_'+c['id'][:16]
    unit='rime-node-firewall-'+c['id']+'.service'
    script=directory/'control-firewall.sh'
    if remove:
        if not marker.is_file():return
        saved=json.loads(marker.read_text())
        if saved['id']!=c['id']:raise RuntimeError('Firewall ownership mismatch')
        if saved.get('mode') in ('controller-mtls-v1','source-ip-v1') or (Path('/etc/rime-node-firewalls')/c['id']).is_dir():
            home=Path('/etc/rime-node-firewalls')/c['id']
            expected=str(home/'worker.py')
            if saved.get('worker')!=expected:raise RuntimeError('Firewall worker ownership mismatch')
            subprocess.run(['python3',expected,'remove',str(home/'config.json')],check=True,capture_output=True,timeout=20)
            for suffix in ('.path','.service'):
                subprocess.run(['systemctl','disable','--now','rime-node-firewall-'+c['id']+suffix],capture_output=True,timeout=20)
                (Path('/etc/systemd/system')/('rime-node-firewall-'+c['id']+suffix)).unlink(missing_ok=True)
            for name in ('worker.py','config.json'):(home/name).unlink(missing_ok=True)
            home.rmdir();marker.unlink()
            subprocess.run(['systemctl','daemon-reload'],check=True,capture_output=True,timeout=20)
            return
        # Old installations stored an executable hook in the container's rw
        # state. Remove their exact validated chain without executing that file.
        interface=saved.get('interface')
        if not isinstance(interface,str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}',interface):
            raise RuntimeError('Legacy firewall interface ownership mismatch')
        while subprocess.run(['iptables','-C','DOCKER-USER','-i',interface,'-j',chain],capture_output=True,timeout=10).returncode==0:
            subprocess.run(['iptables','-D','DOCKER-USER','-i',interface,'-j',chain],check=True,capture_output=True,timeout=10)
        subprocess.run(['iptables','-F',chain],capture_output=True,timeout=10)
        subprocess.run(['iptables','-X',chain],capture_output=True,timeout=10)
        subprocess.run(['systemctl','disable',unit],capture_output=True,timeout=20)
        (Path('/etc/systemd/system')/unit).unlink(missing_ok=True)
        if Path('/run/systemd/system').is_dir():
            subprocess.run(['systemctl','daemon-reload'],check=True,capture_output=True,timeout=20)
        marker.unlink()
        return
    if image is not None and authenticated_management(c, image):
        return qualified_control_firewall(c,directory,marker)
    if c.get('control_source'):
        qualified_control_firewall(c,directory,marker,mode='source-ip-v1')
    return None


def qualified_control_firewall(c,directory,marker,mode='controller-mtls-v1'):
    source=str(ipaddress.IPv4Address(c.get('control_source')))
    ports=[outside for outside,inside,protocol in c['publish'] if inside in (62050,62051) and protocol=='tcp']
    if len(ports)!=2 or any(type(port)!=int or not 1<=port<=65535 for port in ports):raise ValueError('Invalid management ports')
    if os.getuid()!=0 or not shutil.which('systemctl') or not shutil.which('iptables-restore'):
        raise RuntimeError('Root, systemd and iptables tools are required for management firewall')
    if marker.exists():raise RuntimeError('Firewall already exists for this installation')
    policy=directory/'control-policy'
    if policy.is_symlink():raise RuntimeError('Management policy directory is a symlink')
    policy.mkdir(mode=0o700,exist_ok=True)
    sources=[source]
    digest=hashlib.sha256(json.dumps(sources,separators=(',',':')).encode()).hexdigest()
    (policy/'sources.json').write_text(json.dumps({'node':'pending:'+c['id'],'revision':0,'sources':sources,'digest':digest})+'\n')
    (policy/'refresh').write_text('0\n')
    home=Path('/etc/rime-node-firewalls')/c['id']
    if home.is_symlink() or home.parent.is_symlink():raise RuntimeError('Firewall worker path is not owned')
    home.mkdir(mode=0o700,parents=True,exist_ok=False)
    (home/'worker.py').write_text(CONTROL_FIREWALL_WORKER)
    (home/'worker.py').chmod(0o700)
    (home/'config.json').write_text(json.dumps({'id':c['id'],'ports':ports,'panel_source':source,'policy_file':str(policy/'sources.json')}))
    worker=str(home/'worker.py');configuration=str(home/'config.json')
    unit='rime-node-firewall-'+c['id']
    service=Path('/etc/systemd/system')/(unit+'.service');watch=Path('/etc/systemd/system')/(unit+'.path')
    if service.exists() or watch.exists():raise RuntimeError('Firewall unit already exists')
    service.write_text('[Unit]\nDescription=Rime native management source firewall\nAfter=network-online.target\nBefore=docker.service\nStartLimitIntervalSec=0\n\n'
        '[Service]\nType=oneshot\nRestart=on-failure\nRestartSec=2\nTimeoutStartSec=30\nExecStart='+shlex.quote(sys.executable)+' '+shlex.quote(worker)+' apply '+shlex.quote(configuration)+'\n\n[Install]\nWantedBy=multi-user.target\n')
    watch.write_text('[Unit]\nDescription=Rime native management source policy delivery\n\n[Path]\nPathChanged='+str(policy/'refresh')+'\nUnit='+unit+'.service\n\n[Install]\nWantedBy=multi-user.target\n')
    marker.write_text(json.dumps({'id':c['id'],'mode':mode,'worker':worker,'ports':ports}))
    subprocess.run(['python3',worker,'apply',configuration],check=True,capture_output=True,timeout=20)
    subprocess.run(['systemctl','daemon-reload'],check=True,capture_output=True,timeout=20)
    subprocess.run(['systemctl','enable',unit+'.service'],check=True,capture_output=True,timeout=20)
    subprocess.run(['systemctl','enable','--now',unit+'.path'],check=True,capture_output=True,timeout=20)
    return 'controller-mtls-v1' if mode=='controller-mtls-v1' else None


def run(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=180)
    if p.returncode:
        if DIAGNOSTIC:DIAGNOSTIC.write_text(p.stderr[-16384:])
        raise RuntimeError('Command failed: '+args[0])
    return p.stdout


def valid_image(value):
    return bool(re.fullmatch(r'(?:[a-zA-Z0-9./:_-]+@)?sha256:[0-9a-f]{64}',value))


def inspect_container(name):
    result=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=20)
    if result.returncode==0:
        values=json.loads(result.stdout)
        if len(values)!=1:raise RuntimeError('Unexpected Docker inspection result')
        return values[0]
    missing=r'(?:Error response from daemon:\s*|Error:\s*)No such (?:object|container):\s*'+re.escape(name)+r'\s*$'
    if result.returncode==1 and re.search(missing,result.stderr,re.IGNORECASE):return None
    raise RuntimeError('Container state cannot be confirmed; cleanup was retained')


def remove_transfers(directory,job):
    for suffix in ['.image.tar.gz','.tar.gz']:
        path=directory.parent/(job+suffix)
        if path.is_symlink():raise RuntimeError('Transfer path is a symlink')
        if path.exists():
            if not path.is_file():raise RuntimeError('Transfer path is not a regular file')
            path.unlink()


def management_identity(directory):
    certificate = directory / 'node-cert.pem'
    key = directory / 'node-key.pem'
    try:
        if any(path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size < 131072
               for path in (certificate, key)):
            return None
        # Docker reports Running before the node finishes creating its TLS pair.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key, password='')
        return {'certificate': certificate.read_text(encoding='ascii'),
                'key': key.read_text(encoding='ascii')}
    except (OSError, UnicodeError):
        return None


def main(c):
    global DIAGNOSTIC
    os.umask(0o077)
    assert re.fullmatch('[a-f0-9]{32}',c['id'])
    directory=Path.home()/'.local/share/fleet-nodes'/c['id']
    if directory.resolve()!=directory or directory.is_symlink():raise RuntimeError('Managed-node path is a symlink')
    name='fleet-'+c['id']
    if c['action']=='image-present':
        return {'present':resolve_image(c['image'],c.get('image_candidates',())) is not None}
    if c['action']=='preflight':
        checks=[]
        owned_ports=set()
        ignored_containers=[]
        for identity in c.get('cleanup_proxy_ids',[]):
            if not re.fullmatch('[a-f0-9]{32}',identity):raise ValueError('Invalid proxy cleanup identity')
            previous=inspect_container('fleet-proxy-'+identity)
            if previous is not None:
                labels=previous['Config'].get('Labels',{})
                if labels.get('rime.proxy.job')!=identity or labels.get('rime.transfer')!=c.get('cleanup_job'):
                    raise RuntimeError('Previous proxy belongs to another operation')
                ignored_containers.append('fleet-proxy-'+identity)
                for binding,values in (previous['HostConfig'].get('PortBindings') or {}).items():
                    for value in values or []:owned_ports.add((int(value['HostPort']),binding.split('/')[1]))
        if c.get('cleanup_job'):
            if not re.fullmatch('[a-f0-9]{32}',c['cleanup_job']):raise ValueError('Invalid cleanup job')
            for prefix in ['fleet-','fleet-observer-']:
                found=subprocess.run(['docker','inspect',prefix+c['cleanup_job']],capture_output=True,text=True)
                if found.returncode==0:
                    previous=json.loads(found.stdout)[0]
                    if previous['Config']['Labels'].get('fleet.job')!=c['cleanup_job']:raise RuntimeError('Previous container ownership mismatch')
                    ignored_containers.append(prefix+c['cleanup_job'])
                    for binding,values in (previous['HostConfig'].get('PortBindings') or {}).items():
                        for value in values or []:owned_ports.add((int(value['HostPort']),binding.split('/')[1]))
        checks.append({'passed':sys.platform=='linux','message':'Linux / Python 3'})
        try:run(['docker','info','--format','{{.ServerVersion}}']);ok=True
        except Exception:ok=False
        bootstrap=bool(c.get('allow_bootstrap') and os.getuid()==0 and not shutil.which('docker') and shutil.which('apt-get'))
        checks.append({'passed':ok or bootstrap,'message':'Docker будет установлен' if bootstrap else 'Docker доступен текущему SSH-пользователю'})
        checks.append({'passed':os.uname().machine=='x86_64','message':'Архитектура x86_64'})
        checks.extend(port_checks(c['ports'],ignored_containers,owned_ports))
        stat=os.statvfs(Path.home())
        checks.append({'passed':stat.f_bavail*stat.f_frsize>2*1024**3,'message':'Свободно более 2 GiB'})
        checks.append({'passed':not directory.exists(),'message':'Новая отдельная директория'})
        memory=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))*1024
        return {'checks':checks,'home':str(Path.home()),'uid':os.getuid(),'gid':os.getgid(),'mem_total_bytes':memory}
    if c['action']=='rollback':
        observer='fleet-observer-'+c['id']
        observer_info=inspect_container(observer)
        info=inspect_container(name)
        for container in [observer_info,info]:
            if container is not None and (container['Config'].get('Labels') or {}).get('fleet.job')!=c['id']:
                raise RuntimeError('Container ownership mismatch')
        if observer_info is not None:run(['docker','rm','-f',observer])
        if info is not None:
            log=subprocess.run(['docker','logs','--tail','30',name],capture_output=True,text=True,timeout=5)
            if directory.is_dir():(directory/'rollback-runtime.log').write_text((log.stdout+log.stderr)[-16384:])
            run(['docker','rm','-f',name])
        control_firewall(c,directory,remove=True)
        remove_transfers(directory,c['id'])
        return {'removed':info is not None,'data_retained':True}
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
        image=resolve_image(c['image'],c.get('image_candidates',()))
        if image is None:raise RemoteError('image_unavailable')
        args=['docker','run','-d','--name',observer,'--label','fleet.job='+c['id'],'--label','fleet.observer.config='+digest,
            '--restart','unless-stopped','--cpus','0.1','--memory','64m','--pids-limit','32','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=8m',
            '--network','container:'+name,'--pid','container:'+name,'--user',f'{os.getuid()}:{os.getgid()}',
            '--log-driver','json-file','--log-opt','max-size=2m','--log-opt','max-file=2',
            '--mount',f'type=bind,src={home},dst=/observer,readonly']
        if json.loads(c['files']['config.json']).get('management_policy_dir'):
            policy=directory/'control-policy'
            if policy.is_symlink() or not policy.is_dir():raise RuntimeError('Management policy directory is unavailable')
            args+=['--mount',f'type=bind,src={policy},dst=/control-policy']
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
    image=resolve_image(c['image'],c.get('image_candidates',()))
    if image is None:
        if c.get('image_bundle'):
            bundle=Path(c['image_bundle'])
            if bundle.is_symlink() or bundle.parent!=directory.parent or bundle.name!=c['id']+'.image.tar.gz':
                raise ValueError('Invalid image bundle')
            with bundle.open('rb') as stream:
                digest=hashlib.sha256()
                for data in iter(lambda:stream.read(1024*1024),b''):digest.update(data)
            if digest.hexdigest()!=c['image_bundle_sha256']:raise ValueError('Image bundle checksum mismatch')
            run(['docker','load','-i',str(bundle)])
            image=resolve_image(c['image'],c.get('image_candidates',()))
            if image is None:raise RemoteError('image_unavailable')
            bundle.unlink()
        elif c['image'].startswith('sha256:'):
            raise RemoteError('image_unavailable')
        else:
            run(['docker','pull',c['image']])
            image=resolve_image(c['image'],c.get('image_candidates',()))
            if image is None:raise RemoteError('image_unavailable')
    args=['docker','run','-d','--name',name,'--label','fleet.job='+c['id'],
          '--restart','unless-stopped','--cpus','1','--memory','512m','--pids-limit','128',
          '--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3',
          '--cap-drop','ALL','--security-opt','no-new-privileges','--read-only',
          '--tmpfs','/tmp:rw,noexec,nosuid,size=32m']
    if any(inside<1024 for outside,inside,protocol in c['publish']):
        args+=['--cap-add','NET_BIND_SERVICE']
    # Network override is server configuration only, never accepted from the UI.
    if c.get('lab_network'):args+=['--network',c['lab_network']]
    else:
        for outside,inside,proto in c['publish']:
            bind='0.0.0.0:' if c.get('control_source') and inside in (62050,62051) else ''
            args+=['-p',f'{bind}{outside}:{inside}/{proto}']
    args+=['--mount',f'type=bind,src={directory},dst=/state']
    for source,target in c.get('mounts',[]):
        if source not in c['files'] or not target.startswith('/'):raise ValueError('Invalid mount')
        args+=['--mount',f'type=bind,src={directory/source},dst={target},readonly']
    for key,value in c.get('env',{}).items():args+=['-e',key+'='+value]
    if c['protocol']=='hysteria2':
        bundle=Path(c['bundle'])
        if bundle.is_symlink() or bundle.parent!=directory.parent or bundle.name!=c['id']+'.tar.gz':raise ValueError('Invalid bundle')
        import tarfile
        with tarfile.open(bundle) as archive:archive.extractall(directory,filter='data')
        bundle.unlink()
        (directory/'hysteria-fleet').chmod(0o700)
        args+=['--user',f'{os.getuid()}:{os.getgid()}','-e','PYTHONPATH=/state',image,
               'python','-m','hy2bridge.supervisor','--node-config','/state/agent.json',
               '--hysteria','/state/hysteria-fleet','--hysteria-config','/state/hysteria.json']
    else:args+=['--user',f'{os.getuid()}:{os.getgid()}',image]
    if not c.get('lab_network') and not all(check['passed'] for check in port_checks([(outside,proto) for outside,inside,proto in c['publish']])):
        raise RemoteError('port_conflict')
    management_auth = control_firewall(c,directory,image=image)
    try:run(args)
    except RuntimeError as exc:raise RemoteError('container_start_failed') from exc
    deadline = time.monotonic() + MANAGEMENT_IDENTITY_TIMEOUT
    time.sleep(2)
    export_identity = c.get('export_identity')
    identity = None
    while True:
        info = json.loads(run(['docker', 'inspect', name]))[0]
        if not export_identity or not info['State']['Running']:
            break
        identity = management_identity(directory)
        remaining = deadline - time.monotonic()
        if identity is not None or remaining <= 0:
            break
        time.sleep(min(0.5, remaining))
    if not info['State']['Running'] or (export_identity and identity is None):
        log=subprocess.run(['docker','logs','--tail','50',name],capture_output=True,text=True,timeout=5)
        DIAGNOSTIC.write_text((log.stdout+log.stderr)[-16384:])
    if export_identity and info['State']['Running'] and identity is None:
        raise RemoteError('management_identity_not_ready')
    result={'directory':str(directory),'container':name,'running':info['State']['Running'],
            'ip':next((v['IPAddress'] for v in info['NetworkSettings'].get('Networks',{}).values() if v.get('IPAddress')),None)}
    if management_auth:
        result['management_auth'] = management_auth
    if identity is not None:
        result['management_tls'] = identity
    return result


if __name__=='__main__':
    try:print(json.dumps(main(json.load(sys.stdin))))
    except Exception as exc:
        # Deliberately avoid remote command output and secrets in API errors.
        print(json.dumps({'error':type(exc).__name__,'code':exc.code if isinstance(exc,RemoteError) else None}));sys.exit(1)
