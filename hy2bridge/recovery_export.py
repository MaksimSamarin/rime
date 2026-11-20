"""Read configuration data from the selected host without changing its services."""
import json
from pathlib import Path
import re
import subprocess
import sys


def main(request):
    files={}
    def add(path):
        path=Path(path)
        if path.is_file() and path.stat().st_size<=1024*1024:
            text=path.read_text()
            if len(text.encode())+sum(len(value.encode()) for value in files.values())>8*1024*1024:
                raise ValueError('Recovery configuration exceeds the size limit')
            files[str(path).lstrip('/')]=text
    for root in ['/etc/hysteria','/usr/local/etc/hysteria','/etc/squid','/root/cert']:
        path=Path(root)
        if not path.is_dir():continue
        for source in path.rglob('*'):
            if source.is_file() and (source.suffix in ['.json','.yaml','.yml','.conf','.cnf','.pem','.key','.crt','.cer','.passwd','.htpasswd','.txt','.lst'] or source.name in ['passwd','passwords','squid_passwd','.htpasswd']):
                add(source)
    for identity in request['vpn_ids']:
        if not re.fullmatch('[a-f0-9]{32}',identity):raise ValueError('Invalid node identity')
        root=Path.home()/'.local/share/fleet-nodes'/identity
        for name in ['hysteria.json','cert.pem','key.pem','node-cert.pem','node-key.pem','recovery-config.json']:
            add(root/name)
    for identity in request['proxy_ids']:
        if not re.fullmatch('[a-f0-9]{32}',identity):raise ValueError('Invalid proxy identity')
        root=Path.home()/'.local/share/fleet-proxies'/identity
        names=['squid.conf','passwd','cert.pem','key.pem']+sorted(path.name for path in root.glob('extra-*.txt'))
        for name in names:
            add(root/name)
    # Read the effective running Xray configuration, including file-backed TLS.
    names=['fleet-'+identity for identity in request['vpn_ids']]+['marzban-node']
    program=r'''
from pathlib import Path
import json,os
files={}
recovery=os.environ.get('RIME_NODE_RECOVERY_FILE')
if recovery and Path(recovery).is_file() and Path(recovery).stat().st_size<1024*1024:
    files['effective-xray.json']=Path(recovery).read_text()
for key in ['SSL_CERT_FILE','SSL_KEY_FILE']:
    if os.environ.get(key):
        path=Path(os.environ[key])
        if path.is_file() and path.stat().st_size<131072:
            files[str(path).lstrip('/')]=path.read_text()
            files['recovery-active-management-'+('cert.pem' if key=='SSL_CERT_FILE' else 'key.pem')]=path.read_text()
for directory in Path('/proc').iterdir():
    if not directory.name.isdigit():continue
    try:arguments=(directory/'cmdline').read_bytes().decode().split('\0')
    except (OSError,UnicodeError):continue
    if 'effective-xray.json' in files:break
    if not arguments or Path(arguments[0]).name!='xray':continue
    for flag in ['-c','-config','--config']:
        if flag not in arguments:continue
        path=Path(arguments[arguments.index(flag)+1])
        if not path.is_absolute():path=(directory/'cwd').resolve()/path
        if not path.is_file():continue
        if path.stat().st_size>1024*1024:raise ValueError('Oversized runtime config')
        config=json.loads(path.read_text())
        files['effective-xray.json']=json.dumps(config)
        for inbound in config.get('inbounds',[]):
            for certificate in inbound.get('streamSettings',{}).get('tlsSettings',{}).get('certificates',[]):
                for field in ['certificateFile','keyFile']:
                    if certificate.get(field):
                        source=Path(certificate[field])
                        if source.stat().st_size>131072:raise ValueError('Oversized certificate')
                        files[str(source).lstrip('/')]=source.read_text()
print(json.dumps(files))
'''
    for name in names:
        result=subprocess.run(['docker','exec',name,'python3','-c',program],capture_output=True,text=True,timeout=15)
        if result.returncode==0:
            values=json.loads(result.stdout)
            if values:
                files.update(values)
                if 'effective-xray.json' in values:break
    return {'files':files}


if __name__=='__main__':
    try:print(json.dumps(main(json.load(sys.stdin))))
    except Exception:raise SystemExit(1)
