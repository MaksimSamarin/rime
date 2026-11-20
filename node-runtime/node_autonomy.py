"""Compare controller inputs without logging configuration or credentials."""
import json
import os
from pathlib import Path


def equivalent(previous, incoming):
    if previous is None:return False
    return json.loads(previous)==json.loads(incoming)


def equivalent_static(previous,incoming):
    if previous is None:return False
    configs=[json.loads(previous),json.loads(incoming)]
    for config in configs:
        for inbound in config.get('inbounds',[]):
            if inbound.get('protocol')=='vless':
                inbound.get('settings',{}).pop('clients',None)
    return configs[0]==configs[1]


def core_epoch(core):
    process = getattr(core, 'process', None)
    if process is None or type(getattr(process, 'pid', None)) is not int or process.poll() is not None:
        return None
    try:
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        stat = Path('/proc') / str(process.pid) / 'stat'
        started = stat.read_text().rsplit(')', 1)[1].split()[19]
        if not boot or not started.isdigit():
            return None
        return boot + ':' + str(process.pid) + ':' + started
    except (OSError, ValueError, IndexError):
        return None


def capabilities(effective, core=None):
    config=json.loads(effective) if effective else {}
    tags=[item['tag'] for item in config.get('inbounds',[])
          if item.get('protocol')=='vless' and isinstance(item.get('tag'),str)]
    return {'user_reconcile':1,'user_tags':tags,'stats_epoch':core_epoch(core)}


def prepare_config(value):
    certificate=os.environ.get('RIME_NODE_CERTIFICATE')
    key=os.environ.get('RIME_NODE_CERTIFICATE_KEY')
    listen=os.environ.get('RIME_NODE_LISTEN')
    profile_path=os.environ.get('RIME_NODE_PROFILE')
    if not certificate and not key and not listen and not profile_path:return value
    if bool(certificate)!=bool(key):raise ValueError('Both node certificate paths are required')
    if listen and listen!='0.0.0.0':raise ValueError('Unsupported managed-node listener')
    config=json.loads(value) if isinstance(value,str) else json.loads(json.dumps(value))
    if profile_path:
        path=Path(profile_path)
        if path.stat().st_size>8*1024*1024:raise ValueError('Node recovery profile is too large')
        profile=json.loads(path.read_text())
        current={inbound['tag']:inbound for inbound in config.get('inbounds',[])}
        restored=[]
        for inbound in profile['inbounds']:
            source=current.get(inbound['tag'])
            if not source or source.get('protocol')!=inbound.get('protocol'):
                raise ValueError('Controller is missing a recovered inbound')
            inbound=json.loads(json.dumps(inbound))
            if 'clients' in source.get('settings',{}):
                inbound.setdefault('settings',{})['clients']=source['settings']['clients']
            restored.append(inbound)
        for name,setting in profile.items():
            if name not in ['inbounds','api']:config[name]=setting
        config['inbounds']=restored+[inbound for inbound in config.get('inbounds',[]) if inbound.get('tag')=='API_INBOUND']
    for inbound in config.get('inbounds',[]):
        stream=inbound.get('streamSettings',{})
        if inbound.get('protocol')=='vless' and listen:inbound['listen']=listen
        if inbound.get('protocol')=='vless' and stream.get('security')=='tls':
            if certificate:
                stream.setdefault('tlsSettings',{})['certificates']=[
                    {'certificate':Path(certificate).read_text().splitlines(),'key':Path(key).read_text().splitlines()}]
    recovery_file=os.environ.get('RIME_NODE_RECOVERY_FILE')
    if recovery_file:
        snapshot=json.loads(json.dumps(config))
        selected={tag.strip() for tag in os.environ.get('INBOUNDS','').split(',') if tag.strip()}
        snapshot['inbounds']=[item for item in snapshot.get('inbounds',[]) if item.get('tag')!='API_INBOUND' and (not selected or item.get('tag') in selected)]
        snapshot.pop('api',None)
        for inbound in snapshot['inbounds']:inbound.get('settings',{}).pop('clients',None)
        destination=Path(recovery_file)
        temporary=destination.with_suffix('.pending')
        with temporary.open('w') as stream:json.dump(snapshot,stream)
        temporary.chmod(0o600);temporary.replace(destination)
    return json.dumps(config)
