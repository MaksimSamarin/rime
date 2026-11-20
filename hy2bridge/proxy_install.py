"""Own only one labelled Squid container and its private deployment directory."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import shutil
import shlex
import subprocess
import sys
from contextlib import contextmanager
from urllib.parse import quote


LEGACY_POINTER = Path('/var/lib/rime-proxy-legacy/squid.json')
LEGACY_ADAPTER = LEGACY_POINTER.with_name('renewal-adapter.json')

if globals().get('__package__'):
    from .port_check import port_checks


class RemoteError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def resolve_image(image, candidates=()):
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image) or len(candidates) > 32 or any(
            not isinstance(value, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', value) for value in candidates):
        raise ValueError('Proxy image must be immutable')
    for reference in dict.fromkeys([image, *candidates]):
        result = subprocess.run(['docker', 'image', 'inspect', reference], capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            return reference
        if not re.search(r'No such (?:image|object)', result.stderr, re.IGNORECASE):
            raise RuntimeError('Docker image state cannot be confirmed')
    return None


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError('Proxy container operation failed')
    return result.stdout


def paths(job):
    if not re.fullmatch(r'[a-f0-9]{32}', job):
        raise ValueError('Invalid proxy job')
    return Path.home() / '.local/share/fleet-proxies' / job, 'fleet-proxy-' + job


def inspect_container(name):
    result = subprocess.run(['docker', 'inspect', name], capture_output=True, text=True, timeout=15)
    if result.returncode == 0:
        return json.loads(result.stdout)[0]
    if result.returncode == 1 and re.search(r'No such (?:object|container):\s*' + re.escape(name) + r'\s*$', result.stderr, re.IGNORECASE):
        return None
    raise RuntimeError('Proxy container state cannot be confirmed')


def verify_owner(container, job):
    if container['Config'].get('Labels', {}).get('rime.proxy.job') != job:
        raise RuntimeError('Proxy container ownership mismatch')


def legacy_profile(text):
    rows = [shlex.split(line, comments=True) for line in text.splitlines()]
    rows = [row for row in rows if row]
    allowed = {'visible_hostname', 'http_port', 'https_port', 'cache', 'auth_param', 'acl', 'http_access', 'access_log', 'cache_log'}
    if any(row[0] not in allowed for row in rows):
        raise RuntimeError('Unsupported legacy Squid configuration')
    http = [row for row in rows if row[0] == 'http_port']
    https = [row for row in rows if row[0] == 'https_port']
    auth = [row for row in rows if row[:3] == ['auth_param', 'basic', 'program']]
    if len(http) != 1 or http[0][1:] not in [['3128'], ['0.0.0.0:3128']] or len(https)>1 or len(auth) != 1:
        raise RuntimeError('Legacy Squid requires HTTP 3128 and optional HTTPS 443')
    if len(auth[0]) != 5 or (https and (https[0][1] not in ['443', '0.0.0.0:443'] or len(https[0]) != 4)):
        raise RuntimeError('Unsupported legacy Squid listener or authentication')
    tls = dict(value.split('=', 1) for value in https[0][2:]) if https else {}
    if https and (set(tls) != {'tls-cert', 'tls-key'} or any(Path(value).parent != Path('/etc/squid/tls') for value in tls.values())):
        raise RuntimeError('Unsupported legacy Squid certificate location')
    if auth[0][3] != '/usr/lib/squid/basic_ncsa_auth' or Path(auth[0][4]).parent != Path('/etc/squid'):
        raise RuntimeError('Unsupported legacy Squid password helper')
    access = [row[1:] for row in rows if row[0] == 'http_access']
    if access != [['deny', '!Safe_ports'], ['deny', 'CONNECT', '!SSL_ports'], ['deny', 'to_localhost'],
                  ['deny', 'private_dst'], ['allow', 'authenticated'], ['deny', 'all']]:
        raise RuntimeError('Unsupported legacy Squid access rules')
    if ['acl', 'authenticated', 'proxy_auth', 'REQUIRED'] not in rows:
        raise RuntimeError('Legacy Squid authentication is required')
    ports = {}
    for name in ['Safe_ports', 'SSL_ports']:
        values = [row[3:] for row in rows if row[:3] == ['acl', name, 'port']]
        if len(values) != 1 or not values[0] or any(not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', value) for value in values[0]):
            raise RuntimeError('Unsupported legacy Squid destination ports')
        for value in values[0]:
            bounds = [int(part) for part in value.split('-')]
            if min(bounds) < 1 or max(bounds) > 65535 or bounds[0] > bounds[-1]:
                raise RuntimeError('Invalid legacy Squid destination ports')
        ports[name] = ' '.join(values[0])
    return {'passwd_path': auth[0][4], 'certificate_path': tls.get('tls-cert'), 'key_path': tls.get('tls-key'),
            'http_port':3128,'https_port':443 if https else None,**ports}


def legacy_unit():
    raw = command(['systemctl', 'show', 'squid.service', '--property=MainPID,ActiveState,UnitFileState,FragmentPath,ExecStart,DropInPaths'])
    unit = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    if unit.get('FragmentPath') not in ['/lib/systemd/system/squid.service', '/usr/lib/systemd/system/squid.service'] or unit.get('DropInPaths'):
        raise RuntimeError('Unsupported legacy Squid service unit')
    executable = re.search(r'path=([^;]+);\s*argv\[\]=([^;]+);', unit.get('ExecStart', ''))
    if not executable or executable[1].strip() != '/usr/sbin/squid' or shlex.split(executable[2]) != ['/usr/sbin/squid', '--foreground', '-sYC']:
        raise RuntimeError('Legacy service does not execute the supported Squid binary')
    unit['ExecStart'] = '/usr/sbin/squid --foreground -sYC'
    return unit


def legacy_sockets(main_pid,expected_ports=(3128,443)):
    proc = Path('/proc')
    parents = {}
    for entry in proc.iterdir():
        if entry.name.isdigit():
            try:
                stat = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
                parents[int(entry.name)] = int(stat[1])
            except (OSError, ValueError, IndexError):
                continue
    descendants = {main_pid}
    for _ in range(16):
        children = {pid for pid, parent in parents.items() if parent in descendants}
        if children <= descendants:
            break
        descendants |= children
    owners = {}
    for pid in descendants:
        try:
            if os.readlink(proc / str(pid) / 'exe') != '/usr/sbin/squid':
                continue
            for descriptor in (proc / str(pid) / 'fd').iterdir():
                target = os.readlink(descriptor)
                if re.fullmatch(r'socket:\[[0-9]+\]', target):
                    owners[target[8:-1]] = pid
        except (OSError, ValueError):
            continue
    listeners = []
    for name in ['tcp', 'tcp6']:
        for line in (proc / 'net' / name).read_text().splitlines()[1:]:
            fields = line.split()
            port = int(fields[1].rsplit(':', 1)[1], 16)
            if fields[3] == '0A' and port in expected_ports:
                if fields[9] not in owners:
                    raise RuntimeError('Legacy proxy port is owned by another process')
                listeners.append([port, fields[9], owners[fields[9]]])
    if {entry[0] for entry in listeners} != set(expected_ports):
        raise RuntimeError('Legacy Squid listeners are incomplete')
    return sorted(listeners)


def legacy_snapshot(password=None):
    if os.getuid() != 0:
        raise RuntimeError('Legacy Squid replacement requires root')
    unit = legacy_unit()
    pid = int(unit.get('MainPID', '0'))
    if unit.get('ActiveState') != 'active' or pid <= 1 or unit.get('UnitFileState') not in ['enabled', 'disabled']:
        raise RuntimeError('Legacy Squid is not running in the supported state')
    config = Path('/etc/squid/squid.conf').read_text()
    profile = legacy_profile(config)
    tls_files=[]
    if profile['https_port'] is not None:
        try:adapter = json.loads(LEGACY_ADAPTER.read_text())
        except (OSError, ValueError):raise RemoteError('legacy_adapter_unavailable') from None
        hook = Path(adapter['hook'])
        if adapter.get('version') != 1 or adapter.get('pointer') != str(LEGACY_POINTER) or hook.parent != Path('/usr/local/sbin'):
            raise RuntimeError('Legacy proxy certificate renewal adapter is not prepared')
        if LEGACY_ADAPTER.is_symlink() or hook.is_symlink() or LEGACY_ADAPTER.stat().st_uid != 0 or hook.stat().st_uid != 0 or (LEGACY_ADAPTER.stat().st_mode | hook.stat().st_mode) & 0o022:
            raise RuntimeError('Legacy proxy certificate adapter ownership is invalid')
        if hashlib.sha256(hook.read_bytes()).hexdigest() != adapter.get('hook_sha256'):
            raise RuntimeError('Legacy proxy certificate adapter changed')
        tls_files=[profile['certificate_path'],profile['key_path'],str(LEGACY_ADAPTER),str(hook)]
    files = {}
    for value in ['/etc/squid/squid.conf', unit['FragmentPath'], profile['passwd_path'], *tls_files]:
        raw = Path(value).read_bytes()
        if len(raw) > 131072:
            raise RuntimeError('Legacy Squid file exceeds the supported size')
        files[value] = hashlib.sha256(raw).hexdigest()
    passwd = Path(profile['passwd_path']).read_text()
    entries = passwd.splitlines()
    if len(entries) != 1 or ':' not in entries[0]:
        raise RuntimeError('Legacy replacement supports exactly one NCSA user')
    username, hashed = entries[0].split(':', 1)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', username) or not hashed:
        raise RuntimeError('Unsupported legacy Squid account')
    if password is not None:
        result = subprocess.run(['/usr/lib/squid/basic_ncsa_auth', profile['passwd_path']],
            input=quote(username, safe='') + ' ' + quote(password, safe='') + '\n', capture_output=True, text=True, timeout=5)
        if result.returncode or not result.stdout.startswith('OK'):
            raise RemoteError('legacy_password_rejected')
    guard = {'pid': pid, 'listeners': legacy_sockets(pid,[p for p in [3128,profile['https_port']] if p is not None]), 'files': files, 'unit': unit}
    fingerprint = hashlib.sha256(json.dumps(guard, sort_keys=True).encode()).hexdigest()
    return {'fingerprint': fingerprint, 'guard': guard, 'username': username, 'passwd': passwd,
            'passwd_path': profile['passwd_path'],
            'password_hash': hashed, 'certificate': Path(profile['certificate_path']).read_text() if profile['certificate_path'] else '',
            'certificate_key': Path(profile['key_path']).read_text() if profile['key_path'] else '',
            'http_port':3128,'https_port':profile['https_port'],
            'Safe_ports': profile['Safe_ports'], 'SSL_ports': profile['SSL_ports']}


def legacy_backup(job):
    if not re.fullmatch(r'[a-f0-9]{32}', job):
        raise ValueError('Invalid legacy proxy job')
    return Path.home() / '.local/share/fleet-proxy-legacy' / job


@contextmanager
def legacy_lock(directory):
    import fcntl
    with (directory / 'lock').open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def legacy_timer(job, stop=False):
    unit = 'rime-proxy-recover-' + job
    if stop:
        subprocess.run(['systemctl', 'stop', unit + '.timer'], capture_output=True, timeout=20)
        return
    command(['systemd-run', '--quiet', '--collect', '--unit=' + unit, '--on-active=180s',
             sys.executable, str(legacy_backup(job) / 'recover.py')])


def legacy_stop(config):
    current = legacy_snapshot()
    if current['fingerprint'] != config['legacy_fingerprint']:
        raise RemoteError('legacy_changed')
    directory = legacy_backup(config['id'])
    if directory.resolve() != directory:
        raise RuntimeError('Legacy backup path is a symlink')
    directory.mkdir(parents=True, exist_ok=False)
    files = directory / 'files'
    files.mkdir()
    for index, source in enumerate(current['guard']['files']):
        shutil.copyfile(source, files / str(index))
    (directory / 'snapshot.json').write_text(json.dumps(current['guard']))
    recovery = "import base64\nnamespace={'__name__':'proxy_recovery'}\nexec(base64.b64decode(" + repr(config['recovery_code']) + "),namespace)\nnamespace['legacy_restore'](" + repr(config['id']) + ",False)\n"
    (directory / 'recover.py').write_text(recovery)
    legacy_timer(config['id'])
    if legacy_snapshot()['fingerprint'] != config['legacy_fingerprint']:
        legacy_timer(config['id'], stop=True)
        raise RemoteError('legacy_changed')
    command(['systemctl', 'stop', 'squid.service'])
    if legacy_unit().get('ActiveState') != 'inactive':
        raise RuntimeError('Legacy Squid did not stop')
    return {'stopped': True, 'backup': str(directory)}


def verify_legacy_files(snapshot):
    for source, expected in snapshot['files'].items():
        if hashlib.sha256(Path(source).read_bytes()).hexdigest() != expected:
            raise RemoteError('legacy_changed')


def legacy_restore(job, force=False):
    directory = legacy_backup(job)
    if not directory.exists() and legacy_unit().get('ActiveState') == 'active':
        return {'restored': True, 'untouched': True}
    if not directory.is_dir() or directory.resolve() != directory:
        raise RuntimeError('Legacy proxy backup is unavailable')
    with legacy_lock(directory):
        if (directory / 'committed').exists() and not force:
            return {'restored': False, 'committed': True}
        if LEGACY_POINTER.exists():
            if LEGACY_POINTER.is_symlink() or not LEGACY_POINTER.is_file():
                raise RuntimeError('Managed legacy proxy reference is invalid')
            if json.loads(LEGACY_POINTER.read_text()).get('id') != job:
                raise RuntimeError('Another proxy owns the legacy service replacement')
        snapshot = json.loads((directory / 'snapshot.json').read_text())
        unit = legacy_unit()
        if unit['FragmentPath'] != snapshot['unit']['FragmentPath'] or unit['ExecStart'] != snapshot['unit']['ExecStart']:
            raise RuntimeError('Legacy Squid service changed; automatic restore was stopped')
        verify_legacy_files(snapshot)
        _, name = paths(job)
        found = inspect_container(name)
        if found is not None:
            verify_owner(found, job)
            command(['docker', 'rm', '-f', name])
        if LEGACY_POINTER.is_file():
            pointer = json.loads(LEGACY_POINTER.read_text())
            if pointer.get('id') == job:
                LEGACY_POINTER.unlink()
        command(['systemctl', 'enable' if snapshot['unit']['UnitFileState'] == 'enabled' else 'disable', 'squid.service'])
        command(['systemctl', 'start', 'squid.service'])
        restored = legacy_snapshot()
        if restored['guard']['files'] != snapshot['files']:
            raise RuntimeError('Legacy proxy files changed during replacement')
        (directory / 'restored').write_text('restored\n')
        legacy_timer(job, stop=True)
    return {'restored': True}


def legacy_commit(job):
    directory = legacy_backup(job)
    with legacy_lock(directory):
        snapshot = json.loads((directory / 'snapshot.json').read_text())
        unit = legacy_unit()
        if unit['FragmentPath'] != snapshot['unit']['FragmentPath'] or unit['ExecStart'] != snapshot['unit']['ExecStart']:
            raise RemoteError('legacy_changed')
        verify_legacy_files(snapshot)
        target, name = paths(job)
        found = inspect_container(name)
        if found is None:
            raise RuntimeError('Managed proxy is not running')
        verify_owner(found, job)
        if not found['State']['Running'] or unit.get('ActiveState') != 'inactive' or (directory / 'restored').exists():
            raise RuntimeError('Legacy replacement state changed before commit')
        if LEGACY_POINTER.exists():
            raise RuntimeError('Another managed legacy proxy is already registered')
        LEGACY_POINTER.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        pointer = {'id': job, 'directory': str(target), 'container': name,
                   'legacy_config_digest': snapshot['files']['/etc/squid/squid.conf'],
                   'http_port': 3128, 'https_port': 443 if any(row[0]==443 for row in snapshot['listeners']) else None}
        temporary = LEGACY_POINTER.with_name(job + '.new')
        temporary.write_text(json.dumps(pointer))
        temporary.replace(LEGACY_POINTER)
        command(['systemctl', 'disable', 'squid.service'])
        (directory / 'committed').write_text('committed\n')
        legacy_timer(job, stop=True)
    return {'committed': True}


def qualify_legacy_hash(config, image):
    current = legacy_snapshot()
    if current['fingerprint'] != config['legacy_fingerprint']:
        raise RemoteError('legacy_changed')
    qualify_hash(config['id'], current['username'], current['passwd_path'], config['legacy_password'], image)


def qualify_hash(job, username, passwd_path, password, image):
    name = 'fleet-proxy-qualify-' + job
    owner = Path(passwd_path).stat()
    arguments = ['docker', 'run', '--rm', '-i', '--name', name, '--label', 'rime.proxy.job=' + job,
                 '--network', 'none', '--read-only', '--cpus', '0.1', '--memory', '32m', '--pids-limit', '16',
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', f'{owner.st_uid}:{owner.st_gid}',
                 '--mount', 'type=bind,src=' + passwd_path + ',dst=/state/passwd,readonly',
                 '--entrypoint', '/usr/lib/squid/basic_ncsa_auth', image, '/state/passwd']
    try:
        result = subprocess.run(arguments, input=quote(username, safe='') + ' ' + quote(password, safe='') + '\n',
                                capture_output=True, text=True, timeout=30)
        if result.returncode or not result.stdout.startswith('OK'):
            raise RemoteError('legacy_hash_incompatible')
    finally:
        found = inspect_container(name)
        if found is not None:
            verify_owner(found, job)
            command(['docker', 'rm', '-f', name])


def managed_snapshot(service, legacy=False, require_running=True):
    directory, name = paths(service)
    if directory.resolve() != directory or directory.is_symlink():
        raise RuntimeError('Managed proxy directory is a symlink')
    info = inspect_container(name)
    if info is None:
        raise RuntimeError('Managed proxy container is missing')
    verify_owner(info, service)
    if require_running and not info['State']['Running']:
        raise RuntimeError('Managed proxy is stopped; reconcile it before replacing')
    mounts = [item for item in info['Mounts'] if item['Destination'] == '/state']
    if len(mounts) != 1 or mounts[0]['Source'] != str(directory) or mounts[0]['RW']:
        raise RuntimeError('Managed proxy state mount differs from its owner')
    files = {}
    names=['squid.conf','passwd','cert.pem','key.pem']+sorted(path.name for path in directory.glob('extra-*.txt'))
    contents={}
    for filename in names:
        path = directory / filename
        if filename in ['cert.pem', 'key.pem'] and not path.exists():
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 131072:
            raise RuntimeError('Managed proxy file is invalid')
        files[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        contents[filename]=path.read_text()
    passwd = (directory / 'passwd').read_text().splitlines()
    if not passwd or any(':' not in line for line in passwd):
        raise RuntimeError('Managed proxy account does not match the supported profile')
    username, hashed = passwd[0].split(':', 1)
    configuration = (directory / 'squid.conf').read_text()
    policy = {}
    for acl_name in ['Safe_ports', 'SSL_ports']:
        values = re.findall(r'^acl ' + acl_name + r' port (.+)$', configuration, flags=re.MULTILINE)
        if len(values) != 1:
            raise RuntimeError('Managed proxy destination-port policy is incomplete')
        policy[acl_name] = values[0]
    if (directory / 'cert.pem').exists() != (directory / 'key.pem').exists():
        raise RuntimeError('Managed proxy certificate pair is incomplete')
    pointer = None
    if legacy:
        pointer = json.loads(LEGACY_POINTER.read_text())
        if pointer.get('id') != service or pointer.get('directory') != str(directory) or pointer.get('container') != name:
            raise RuntimeError('Managed proxy certificate pointer differs from its owner')
    guard = {'id': info['Id'], 'image': info['Image'], 'labels': info['Config'].get('Labels', {}),
             'ports': info['HostConfig'].get('PortBindings') or {}, 'mount': mounts[0], 'files': files}
    fingerprint = hashlib.sha256(json.dumps({'guard': guard, 'pointer': pointer}, sort_keys=True).encode()).hexdigest()
    return {'fingerprint': fingerprint, 'guard': guard, 'pointer': pointer, 'username': username, 'running': info['State']['Running'], **policy,
            'container':info,
            'files':contents,
            'password_hash': hashed, 'certificate': (directory / 'cert.pem').read_text() if (directory / 'cert.pem').exists() else '',
            'certificate_key': (directory / 'key.pem').read_text() if (directory / 'key.pem').exists() else ''}


def managed_stop(config):
    old = managed_snapshot(config['replace_service'], bool(config.get('legacy_managed')))
    if old['fingerprint'] != config['managed_fingerprint']:
        raise RemoteError('managed_changed')
    directory = legacy_backup(config['id'])
    if directory.resolve() != directory:
        raise RuntimeError('Managed proxy backup path is a symlink')
    directory.mkdir(parents=True, exist_ok=False)
    snapshot = {'kind': 'managed', 'old_service': config['replace_service'], 'old': old}
    (directory / 'snapshot.json').write_text(json.dumps(snapshot))
    recovery = "import base64\nnamespace={'__name__':'proxy_recovery'}\nexec(base64.b64decode(" + repr(config['recovery_code']) + "),namespace)\nnamespace['managed_restore'](" + repr(config['id']) + ",False)\n"
    (directory / 'recover.py').write_text(recovery)
    legacy_timer(config['id'])
    if managed_snapshot(config['replace_service'], bool(config.get('legacy_managed')))['fingerprint'] != config['managed_fingerprint']:
        legacy_timer(config['id'], stop=True)
        raise RemoteError('managed_changed')
    _, name = paths(config['replace_service'])
    command(['docker', 'stop', '--time', '10', name])
    if inspect_container(name)['State']['Running']:
        raise RuntimeError('Original managed proxy did not stop')
    return {'stopped': True}


def managed_restore(job, force=False, original=None, legacy=False):
    directory = legacy_backup(job)
    if not directory.exists() and original:
        managed_snapshot(original, legacy)
        return {'restored': True, 'untouched': True}
    with legacy_lock(directory):
        if (directory / 'committed').exists() and not force:
            return {'restored': False, 'committed': True}
        snapshot = json.loads((directory / 'snapshot.json').read_text())
        old = snapshot['old']
        pointer = None
        if old['pointer'] is not None and LEGACY_POINTER.exists():
            pointer = json.loads(LEGACY_POINTER.read_text())
            if pointer.get('id') not in [snapshot['old_service'], job]:
                raise RuntimeError('Another proxy owns the certificate reference')
        current = managed_snapshot(snapshot['old_service'], require_running=False)
        if current['guard'] != old['guard']:
            raise RemoteError('managed_changed')
        _, new_name = paths(job)
        found = inspect_container(new_name)
        if found is not None:
            verify_owner(found, job)
            command(['docker', 'rm', '-f', new_name])
        if old['pointer'] is not None:
            temporary = LEGACY_POINTER.with_name(job + '.rollback')
            temporary.write_text(json.dumps(old['pointer']))
            temporary.replace(LEGACY_POINTER)
        _, old_name = paths(snapshot['old_service'])
        command(['docker', 'start', old_name])
        if not inspect_container(old_name)['State']['Running']:
            raise RuntimeError('Original managed proxy did not restart')
        (directory / 'restored').write_text('restored\n')
        legacy_timer(job, stop=True)
    return {'restored': True}


def managed_commit(config):
    directory = legacy_backup(config['id'])
    with legacy_lock(directory):
        snapshot = json.loads((directory / 'snapshot.json').read_text())
        current = managed_snapshot(snapshot['old_service'], require_running=False)
        if current['guard'] != snapshot['old']['guard'] or current['running'] or (directory / 'restored').exists():
            raise RemoteError('managed_changed')
        target, name = paths(config['id'])
        found = inspect_container(name)
        if found is None:
            raise RuntimeError('Replacement managed proxy is missing')
        verify_owner(found, config['id'])
        if not found['State']['Running']:
            raise RuntimeError('Replacement managed proxy is not running')
        ports = found['HostConfig'].get('PortBindings') or {}
        for inside, field in [('3128/tcp', 'http_port'), ('8443/tcp', 'https_port')]:
            expected = config.get(field)
            actual = [int(value['HostPort']) for value in ports.get(inside) or []]
            if actual != ([expected] if expected is not None else []):
                raise RuntimeError('Replacement proxy port mapping differs from the plan')
        if snapshot['old']['pointer'] is not None:
            if json.loads(LEGACY_POINTER.read_text()) != snapshot['old']['pointer']:
                raise RuntimeError('Certificate reference changed during replacement')
            pointer = {**snapshot['old']['pointer'], 'id': config['id'], 'directory': str(target), 'container': name,
                       'http_port': config.get('http_port'), 'https_port': config.get('https_port')}
            temporary = LEGACY_POINTER.with_name(config['id'] + '.new')
            temporary.write_text(json.dumps(pointer))
            temporary.replace(LEGACY_POINTER)
        (directory / 'committed').write_text('committed\n')
        legacy_timer(config['id'], stop=True)
    return {'committed': True}


def managed_retire(config):
    _, name = paths(config['replace_service'])
    found = inspect_container(name)
    if found is not None:
        verify_owner(found, config['replace_service'])
        if found['State']['Running']:
            raise RuntimeError('Original proxy resumed; cleanup requires reconciliation')
        command(['docker', 'rm', name])
    return {'removed': found is not None}


def delete_checkpoint(config):
    checkpoint=legacy_backup(config['id'])
    if checkpoint.is_symlink() or checkpoint.resolve()!=checkpoint:
        raise RuntimeError('Managed proxy deletion checkpoint changed')
    path=checkpoint/'snapshot.json'
    if path.is_symlink():raise RemoteError('managed_changed')
    snapshot=json.loads(path.read_text())
    if snapshot.get('kind')!='managed' or snapshot.get('old_service')!=config['replace_service']:
        raise RemoteError('managed_changed')
    return checkpoint,snapshot


def verify_delete_directory(directory,snapshot):
    if directory.is_symlink() or directory.resolve()!=directory:
        raise RemoteError('managed_changed')
    expected=snapshot['old']['guard']['files']
    for name,digest in expected.items():
        path=Path(name)
        if (path.parent!=directory or path.is_symlink() or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest()!=digest):
            raise RemoteError('managed_changed')
    allowed={Path(name).name for name in expected}|{'transfer.json','startup-error.log'}
    if any(path.name not in allowed or path.is_symlink() or not path.is_file() for path in directory.iterdir()):
        raise RemoteError('managed_changed')


def managed_delete_commit(config,allow_running=False):
    checkpoint=legacy_backup(config['id'])
    with legacy_lock(checkpoint):
        checkpoint,snapshot=delete_checkpoint(config)
        directory,name=paths(config['replace_service'])
        marker=checkpoint/'committed'
        if marker.is_symlink():raise RemoteError('managed_changed')
        committed=marker.is_file() and marker.read_text().strip()=='deleted'
        found=inspect_container(name)
        if found is None:
            if committed:return {'committed':True,'removed':True}
            raise RemoteError('managed_changed')
        current=managed_snapshot(config['replace_service'],require_running=False)
        if current['guard']!=snapshot['old']['guard']:
            raise RemoteError('managed_changed')
        verify_delete_directory(directory,snapshot)
        pointer=snapshot['old']['pointer']
        if pointer is not None:
            if LEGACY_POINTER.exists():
                if LEGACY_POINTER.is_symlink() or json.loads(LEGACY_POINTER.read_text())!=pointer:
                    raise RemoteError('managed_changed')
            elif not committed:raise RemoteError('managed_changed')
        if current['running']:
            if not allow_running:raise RemoteError('managed_changed')
            command(['docker','stop','--time','10',current['guard']['id']])
            current=managed_snapshot(config['replace_service'],require_running=False)
            if current['guard']!=snapshot['old']['guard'] or current['running']:
                raise RemoteError('managed_changed')
        marker.write_text('deleted\n')
        if pointer is not None and LEGACY_POINTER.exists():LEGACY_POINTER.unlink()
        legacy_timer(config['id'],stop=True)
    return {'committed':True}


def managed_delete_resume(config):
    return managed_delete_commit(config,allow_running=True)


def managed_delete_finalize(config):
    checkpoint=legacy_backup(config['id'])
    with legacy_lock(checkpoint):
        checkpoint,snapshot=delete_checkpoint(config)
        marker=checkpoint/'committed'
        if marker.is_symlink() or not marker.is_file() or marker.read_text().strip()!='deleted':
            raise RemoteError('managed_changed')
        directory,name=paths(config['replace_service'])
        found=inspect_container(name)
        if found is not None:
            current=managed_snapshot(config['replace_service'],require_running=False)
            if current['guard']!=snapshot['old']['guard'] or current['running']:
                raise RemoteError('managed_changed')
            verify_delete_directory(directory,snapshot)
            command(['docker','rm',current['guard']['id']])
        if inspect_container(name) is not None:raise RemoteError('managed_changed')
        if directory.is_symlink() or directory.resolve()!=directory:
            raise RemoteError('managed_changed')
        if directory.exists():
            verify_delete_directory(directory,snapshot)
            shutil.rmtree(directory)
        legacy_timer(config['id'],stop=True)
    return {'removed':True}


def reconcile_state(config):
    directory = legacy_backup(config['id'])
    _, name = paths(config['id'])
    found = inspect_container(name)
    candidate = managed_snapshot(config['id'], require_running=False) if found is not None else None
    committed = (directory / 'committed').is_file()
    if committed and config.get('legacy_managed'):
        pointer = json.loads(LEGACY_POINTER.read_text())
        if pointer.get('id') != config['id']:
            raise RuntimeError('Committed certificate reference no longer belongs to this proxy')
    return {'candidate': candidate, 'committed': committed, 'restored': (directory / 'restored').is_file()}


def main(config):
    os.umask(0o077)
    directory, name = paths(config['id'])
    action = config['action']
    if config.get('transfer_id') and not re.fullmatch(r'[a-f0-9]{32}',config['transfer_id']):
        raise ValueError('Invalid transfer identity')
    if action=='transfer-finalize':
        found=inspect_container(name)
        if found is None:raise RuntimeError('Transferred proxy is missing')
        verify_owner(found,config['id'])
        if found['Config'].get('Labels',{}).get('rime.transfer')!=config['transfer_id']:
            raise RuntimeError('Proxy belongs to another transfer')
        marker=directory/'transfer.json'
        if marker.is_symlink():raise RuntimeError('Proxy transfer marker is a symlink')
        expected=json.loads(marker.read_text())
        digest=hashlib.sha256(config['passwd'].encode()).hexdigest()
        if expected!={'id':config['transfer_id'],'passwd_sha256':digest}:
            raise RuntimeError('Proxy original account digest changed')
        temporary=directory/'passwd.restore'
        with temporary.open('x') as stream:stream.write(config['passwd'])
        os.chown(temporary,0,65534);temporary.chmod(0o640)
        temporary.replace(directory/'passwd')
        command(['docker','restart',name])
        return {'running':inspect_container(name)['State']['Running'],'passwd_sha256':digest}
    if action == 'managed-snapshot':
        return managed_snapshot(config['replace_service'], bool(config.get('legacy_managed')))
    if action == 'managed-stop':
        return managed_stop(config)
    if action == 'managed-restore':
        return managed_restore(config['id'], bool(config.get('force')), config.get('replace_service'), bool(config.get('legacy_managed')))
    if action == 'managed-commit':
        return managed_commit(config)
    if action == 'managed-retire':
        return managed_retire(config)
    if action == 'managed-delete-commit':
        return managed_delete_commit(config)
    if action == 'managed-delete-resume':
        return managed_delete_resume(config)
    if action == 'managed-delete-finalize':
        return managed_delete_finalize(config)
    if action == 'reconcile-state':
        return reconcile_state(config)
    if action == 'managed-start':
        managed_snapshot(config['id'], require_running=False)
        command(['docker', 'start', name])
        return {'running': inspect_container(name)['State']['Running']}
    if action == 'legacy-stop':
        return legacy_stop(config)
    if action == 'legacy-restore':
        return legacy_restore(config['id'], bool(config.get('force')))
    if action == 'legacy-commit':
        return legacy_commit(config['id'])
    if action == 'rollback':
        found = inspect_container(name)
        if found is not None:
            verify_owner(found, config['id'])
            if config.get('transfer_id') and found['Config'].get('Labels',{}).get('rime.transfer')!=config['transfer_id']:
                raise RuntimeError('Proxy belongs to another transfer; cleanup stopped')
            command(['docker', 'rm', '-f', name])
        bundle = directory.parent / (config['id'] + '.image.tar.gz')
        if bundle.is_file() and not bundle.is_symlink():
            bundle.unlink()
        return {'removed': found is not None, 'data_retained': True}
    if action == 'preflight':
        owned_ports = set()
        ignored_containers = []
        legacy = legacy_snapshot(config.get('legacy_password')) if config.get('replace_legacy_squid') else None
        managed = managed_snapshot(config['replace_service'], bool(config.get('legacy_managed'))) if config.get('replace_service') else None
        if legacy:
            owned_ports.update(row[0] for row in legacy['guard']['listeners'])
            config['ports']=sorted(owned_ports)
        if managed:
            ignored_containers.append(paths(config['replace_service'])[1])
            for entries in managed['guard']['ports'].values():
                owned_ports.update(int(entry['HostPort']) for entry in entries or [])
        if config.get('cleanup_job'):
            _, previous_name = paths(config['cleanup_job'])
            previous = inspect_container(previous_name)
            if previous is not None:
                verify_owner(previous, config['cleanup_job'])
                ignored_containers.append(previous_name)
                for entries in (previous['HostConfig'].get('PortBindings') or {}).values():
                    owned_ports.update(int(entry['HostPort']) for entry in entries or [])
        checks = [{'passed': sys.platform == 'linux', 'message': 'Linux / Python 3'},
                  {'passed': os.getuid() == 0, 'message': 'SSH-доступ root'},
                  {'passed': os.uname().machine == 'x86_64', 'message': 'Архитектура x86_64'}]
        if managed:
            checks.append({'passed': bool(shutil.which('systemctl') and shutil.which('systemd-run') and Path('/run/systemd/system').is_dir()),
                           'message': 'Работающий systemd для автоматического отката замены прокси'})
        try:
            command(['docker', 'info', '--format', '{{.ServerVersion}}'])
            docker = True
        except Exception:
            docker = False
        bootstrap = bool(config.get('allow_bootstrap') and os.getuid() == 0 and not shutil.which('docker') and shutil.which('apt-get'))
        checks.append({'passed': docker or bootstrap, 'message': 'Docker будет установлен' if bootstrap else 'Docker доступен'})
        checks.extend(port_checks([(port, 'tcp') for port in config['ports']], ignored_containers,
                                  [(port, 'tcp') for port in owned_ports]))
        fs = os.statvfs(Path.home())
        checks.append({'passed': fs.f_bavail * fs.f_frsize > 512 * 1024 ** 2, 'message': 'Свободно более 512 MiB'})
        checks.append({'passed': not directory.exists(), 'message': 'Новая отдельная директория прокси'})
        result = {'home': str(Path.home()), 'checks': checks}
        if legacy:
            result['legacy'] = legacy
        if managed:
            result['managed'] = managed
        return result
    image = config['image']
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise ValueError('Proxy image must be immutable')
    if action == 'image-present':
        return {'present': resolve_image(image, config.get('image_candidates', ())) is not None}
    if action not in ['install', 'image-prepare'] or os.getuid() != 0:
        raise ValueError('Unsupported proxy operation')
    if action == 'install':
        directory.mkdir(parents=True, exist_ok=False)
        if inspect_container(name) is not None:
            raise RuntimeError('Proxy container already exists')
    local_image = resolve_image(image, config.get('image_candidates', ()))
    if local_image is None:
        if not config.get('image_bundle'):
            raise RemoteError('image_unavailable')
        bundle = Path(config['image_bundle'])
        if bundle.is_symlink() or bundle.parent != directory.parent or bundle.name != config['id'] + '.image.tar.gz':
            raise ValueError('Invalid proxy image bundle')
        with bundle.open('rb') as stream:
            digest = hashlib.sha256()
            for data in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(data)
        if digest.hexdigest() != config['image_bundle_sha256']:
            raise ValueError('Proxy image checksum mismatch')
        command(['docker', 'load', '-i', str(bundle)])
        local_image = resolve_image(image, config.get('image_candidates', ()))
        if local_image is None:
            raise RemoteError('image_identity_unresolved')
        bundle.unlink()
    if action == 'image-prepare':
        if config.get('legacy_fingerprint'):
            qualify_legacy_hash(config, local_image)
        if config.get('qualify_service'):
            managed = managed_snapshot(config['qualify_service'], bool(config.get('legacy_managed')))
            if managed['fingerprint'] != config['managed_fingerprint']:
                raise RemoteError('managed_changed')
            source, _ = paths(config['qualify_service'])
            qualify_hash(config['id'], managed['username'], str(source / 'passwd'), config['qualify_password'], local_image)
        return {'present': True}
    allowed = {'squid.conf', 'passwd', 'cert.pem', 'key.pem'}
    if any(name not in allowed and not re.fullmatch(r'extra-[a-f0-9]{16}\.txt',name) for name in config['files']) or not {'squid.conf', 'passwd'} <= set(config['files']):
        raise ValueError('Invalid proxy files')
    os.chown(directory, 0, 65534)
    directory.chmod(0o750)
    for filename, value in config['files'].items():
        path = directory / filename
        path.write_text(value)
        os.chown(path, 0, 65534)
        path.chmod(0o640)
    if config.get('transfer_id'):
        (directory/'transfer.json').write_text(json.dumps({'id':config['transfer_id'],'passwd_sha256':config['restore_passwd_sha256']}))
    publishes = []
    for outside, inside in config['publish']:
        if type(outside) != int or not 1 <= outside <= 65535 or inside not in [3128, 8443]:
            raise ValueError('Invalid proxy port')
        publishes += ['-p', f'0.0.0.0:{outside}:{inside}/tcp']
    arguments = ['docker', 'run', '-d', '--name', name, '--label', 'rime.proxy.job=' + config['id'],
                 '--label', 'rime.proxy.node=' + config['node'], '--restart', 'unless-stopped',
                 '--cpus', '0.5', '--memory', '128m', '--pids-limit', '64', '--user', '65534:65534',
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
                 '--tmpfs', '/run/squid:rw,noexec,nosuid,size=8m,uid=65534,gid=65534,mode=0755',
                 '--tmpfs', '/tmp:rw,noexec,nosuid,size=8m',
                 '--log-driver', 'json-file', '--log-opt', 'max-size=2m', '--log-opt', 'max-file=2',
                 '--mount', f'type=bind,src={directory},dst=/state,readonly', *publishes, local_image]
    if config.get('transfer_id'):arguments[-1:-1]=['--label','rime.transfer='+config['transfer_id']]
    if not all(check['passed'] for check in port_checks([(outside, 'tcp') for outside, inside in config['publish']])):
        raise RemoteError('port_conflict')
    try:
        command(arguments)
        found = inspect_container(name)
        if found is None or not found['State']['Running']:
            raise RuntimeError('Proxy container did not start')
    except Exception:
        log = subprocess.run(['docker', 'logs', '--tail', '40', name], capture_output=True, text=True, timeout=10)
        # Squid access logging is disabled and configuration/credentials are not printed.
        (directory / 'startup-error.log').write_text((log.stdout + log.stderr)[-16384:])
        raise
    return {'running': True, 'container': name, 'directory': str(directory)}


if __name__ == '__main__':
    try:
        print(json.dumps(main(json.load(sys.stdin))))
    except Exception as error:
        failure = {'error': type(error).__name__}
        if isinstance(error, RemoteError):
            failure['code'] = error.code
        print(json.dumps(failure))
        raise SystemExit(1)
