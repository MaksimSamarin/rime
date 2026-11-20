"""Fixed host worker for one owned native node's management-port source ACL."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def command(*arguments,check=True):
    return subprocess.run(['iptables','-w','5',*arguments],check=check,capture_output=True,timeout=10)


def apply(configuration,remove=False):
    identity=configuration['id']
    if not re.fullmatch('[a-f0-9]{32}',identity):raise ValueError('Invalid firewall ownership')
    chain='RIME_'+identity[:16]
    ports=configuration['ports']
    if len(ports)!=2 or any(type(port) is not int or not 1<=port<=65535 for port in ports):
        raise ValueError('Invalid management ports')
    if remove:
        while command('-C','DOCKER-USER','-j',chain,check=False).returncode==0:
            command('-D','DOCKER-USER','-j',chain)
        command('-F',chain,check=False);command('-X',chain,check=False)
        return
    policy_path=Path(configuration['policy_file'])
    if policy_path.is_symlink() or policy_path.parent.is_symlink():raise ValueError('Management policy path is not owned')
    if policy_path.stat().st_size>16384:raise ValueError('Management policy is too large')
    policy=json.loads(policy_path.read_text())
    values=policy.get('sources')
    if not isinstance(values,list) or not 1<=len(values)<=64:raise ValueError('Invalid management source policy')
    sources=sorted({str(ipaddress.IPv4Address(value)) for value in values})
    if str(ipaddress.IPv4Address(configuration['panel_source'])) not in sources:
        raise ValueError('Management policy must preserve the panel source')
    digest=hashlib.sha256(json.dumps(sources,separators=(',',':')).encode()).hexdigest()
    if sources!=values or policy.get('digest')!=digest:raise ValueError('Management policy digest differs')
    revision=policy.get('revision')
    if type(revision) is not int or revision<0:raise ValueError('Invalid management policy revision')
    command('-N','DOCKER-USER',check=False)
    command('-N',chain,check=False)
    # Replace atomically: an invalid policy never removes the current ACL and
    # a valid policy never creates an interval with a flushed open chain.
    rules=['*filter',':'+chain+' - [0:0]','-F '+chain]
    for port in ports:
        prefix='-A '+chain+' -p tcp -m conntrack --ctdir ORIGINAL --ctorigdstport '+str(port)
        rules += [prefix+' -s '+source+'/32 -j RETURN' for source in sources]
        rules.append(prefix+' -j DROP')
    rules+=['-A '+chain+' -j RETURN','COMMIT','']
    subprocess.run(['iptables-restore','--wait','5','--noflush'],input='\n'.join(rules),text=True,
                   check=True,capture_output=True,timeout=10)
    if command('-C','DOCKER-USER','-j',chain,check=False).returncode:
        command('-I','DOCKER-USER','1','-j',chain)
    target=policy_path.parent/'applied.json'
    if target.is_symlink():raise ValueError('Management acknowledgement path is not owned')
    with tempfile.NamedTemporaryFile(mode='w',dir=target.parent,prefix='.applied-',delete=False) as stream:
        temporary=Path(stream.name)
        stream.write(json.dumps({'revision':revision,'digest':digest})+'\n')
        stream.flush();os.fsync(stream.fileno())
    try:temporary.replace(target)
    finally:temporary.unlink(missing_ok=True)


if __name__=='__main__':
    configuration=json.loads(Path(sys.argv[2]).read_text())
    apply(configuration,remove=sys.argv[1]=='remove')
