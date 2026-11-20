"""Own the entry service, its resource journal and its private files."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys


def command(arguments):
    process = subprocess.run(arguments, capture_output=True, text=True, timeout=30)
    if process.returncode:
        raise RuntimeError('Entry service operation failed')
    return process.stdout


def main(config):
    identity = config['id']
    if os.getuid() != 0 or not re.fullmatch(r'[a-f0-9]{32}', identity):
        raise ValueError('Invalid entry installation owner')
    directory = Path('/var/lib/rime-relay') / identity
    service = 'rime-relay-' + identity
    meter = 'rime-relay-meter-' + identity
    if config['action'] == 'preflight':
        return {'checks':port_checks(config['ports'])}
    if config['action'] == 'status':
        return {'running': command(['systemctl', 'is-active', service]).strip() == 'active',
                'meter_running': command(['systemctl', 'is-active', meter]).strip() == 'active'}
    if config['action'] == 'remove':
        if not directory.exists() and not any((Path('/etc/systemd/system')/(name+'.service')).exists() for name in [meter,service]):
            return {'removed':True}
        if not directory.is_dir() or directory.is_symlink() or directory.resolve() != directory:
            raise ValueError('Entry ownership directory changed')
        owner = json.loads((directory / 'owner.json').read_text())
        if owner != {'id': identity, 'schema': 1}:
            raise ValueError('Entry service owner changed')
        for name in [meter, service]:
            unit_path = Path('/etc/systemd/system') / (name + '.service')
            if unit_path.is_file():
                command(['systemctl', 'disable', '--now', name])
                unit_path.unlink()
        shutil.rmtree(directory)
        command(['systemctl', 'daemon-reload'])
        return {'removed': True}
    if config['action'] != 'install' or directory.exists():
        raise ValueError('Entry installation already exists')
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('The entry server requires systemd')
    if any((Path('/etc/systemd/system') / (name + '.service')).exists() for name in [service, meter]):
        raise ValueError('Entry unit name is already used')
    binaries = Path('/usr/local/lib/rime-relay')
    binaries.mkdir(mode=0o755, parents=True, exist_ok=True)
    marker = binaries / 'account.json'
    try:
        account = pwd.getpwnam('rime-relay')
        if not marker.is_file():
            raise ValueError('The entry service account is already used')
    except KeyError:
        command(['useradd', '--system', '--home-dir', '/var/lib/rime-relay', '--shell', '/usr/sbin/nologin', '--no-create-home', 'rime-relay'])
        account = pwd.getpwnam('rime-relay')
        marker.write_text(json.dumps({'uid': account.pw_uid}))
        marker.chmod(0o600)
    if json.loads(marker.read_text()).get('uid') != account.pw_uid:
        raise ValueError('Entry service account changed')
    binary = Path(config['binary'])
    if binary.is_symlink() or not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != config['binary_sha256']:
        raise ValueError('Entry runtime checksum differs')
    qualified = binaries / ('gost-' + config['binary_sha256'])
    if not qualified.exists():
        shutil.copyfile(binary, qualified)
        qualified.chmod(0o755)
    binary.unlink()
    for name in ['launch.py', 'observer.py']:
        (binaries / name).write_text(config['scripts'][name])
        (binaries / name).chmod(0o644)
    directory.mkdir(mode=0o700, parents=True)
    os.chown(directory, account.pw_uid, account.pw_gid)
    owner = directory / 'owner.json'
    owner.write_text(json.dumps({'id': identity, 'schema': 1}))
    owner.chmod(0o600)
    os.chown(owner, account.pw_uid, account.pw_gid)
    for name, value in config['files'].items():
        if name not in {'gost.json', 'control-cert.pem', 'control-key.pem', 'observer.json', 'panel-ca.pem'}:
            raise ValueError('Invalid entry file')
        path = directory / name
        path.write_text(value)
        path.chmod(0o600)
        os.chown(path, account.pw_uid, account.pw_gid)
    for name, executable in [(service, f'{sys.executable} {binaries}/launch.py --state {directory} --binary {qualified}'),
                             (meter, f'{sys.executable} {binaries}/observer.py --config {directory}/observer.json')]:
        unit = f'''[Unit]
Description=Rime entry service {identity}
After=network-online.target
Wants=network-online.target

[Service]
User=rime-relay
Group=rime-relay
WorkingDirectory={directory}
ExecStart={executable}
Restart=always
RestartSec=3
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={directory}
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
'''
        path = Path('/etc/systemd/system') / (name + '.service')
        if path.exists():
            raise ValueError('Entry unit name is already used')
        path.write_text(unit)
        path.chmod(0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', service, meter])
    return {'running': True, 'directory': str(directory)}


if __name__ == '__main__':
    try:
        print(json.dumps(main(json.load(sys.stdin))))
    except Exception:
        print(json.dumps({'error': 'EntryOperationFailed'}))
        raise SystemExit(1)
