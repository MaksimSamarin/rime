"""Install the local update worker for an existing Rime Docker container."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def command(args):
    return subprocess.check_output(args, text=True).strip()


def container_name(container):
    name=container.get('Name','').removeprefix('/')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}',name) or re.fullmatch(r'[a-fA-F0-9]{64}',name):
        raise SystemExit('Specify an existing named panel container, not a 64-hex container ID.')
    return name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--container')
    parser.add_argument('--install-directory', default='/opt/rime-updater')
    parser.add_argument('--state-directory', default='/var/lib/rime-updater')
    args = parser.parse_args()
    if args.container is None:
        args.container = command(['docker', 'compose', 'ps', '-q', 'rime'])
    if os.geteuid() != 0 or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}', args.container):
        raise SystemExit('Run as root and specify the existing panel container name.')
    os.umask(0o077)
    container = json.loads(command(['docker', 'inspect', args.container]))[0]
    args.container=container_name(container)
    environment = dict(item.split('=', 1) for item in container['Config']['Env'])
    # Mirror the panel's own default (config.py) so an unset variable fails the mount check below.
    url = environment.get('SQLALCHEMY_DATABASE_URL', 'sqlite:///db.sqlite3')
    if not url.startswith('sqlite:///'):
        raise SystemExit('The update worker requires a SQLite panel installation.')
    database = Path(url.removeprefix('sqlite:///'))
    if not database.is_absolute():
        database = Path(container['Config'].get('WorkingDir') or '/code') / database
    mounts = [mount for mount in container['Mounts'] if Path(mount['Destination']) in database.parents]
    if not mounts:
        raise SystemExit('The panel database must reside on a persistent Docker mount.')
    mount = max(mounts, key=lambda item: len(item['Destination']))
    host_database = Path(mount['Source']) / database.relative_to(mount['Destination'])
    data = host_database.parent.resolve()
    uid, gid = map(int, command(['docker', 'exec', args.container, 'sh', '-c', 'printf "%s %s" "$(id -u)" "$(id -g)"']).split())
    script = "import ast;from pathlib import Path;print(next(ast.literal_eval(n.value) for n in ast.parse(Path('/code/app/__init__.py').read_text()).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='__version__' for t in n.targets)))"
    version = command(['docker', 'exec', args.container, 'python', '-c', script])
    install = Path(args.install_directory).resolve()
    state = Path(args.state_directory).resolve()
    if install in (Path('/'), data) or state in (Path('/'), data) or data in state.parents:
        raise SystemExit('Choose separate updater installation and state directories.')
    install.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    package = Path(__file__).resolve().parents[1] / 'update_runtime'
    shutil.copytree(package, install / 'update_runtime', dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
    queue = data / '.updates'
    if queue.is_symlink():
        raise SystemExit('The update queue must be a regular directory.')
    queue.mkdir(mode=0o700, exist_ok=True)
    os.chown(queue, uid, gid)
    configuration = {
        'container': args.container, 'data_directory': str(data), 'database': str(host_database),
        'state_directory': str(state), 'panel_uid': uid, 'panel_gid': gid, 'current_version': version,
    }
    config_path = install / 'config.json'
    if config_path.exists():
        shutil.copy2(config_path, install / 'config.before.json')
    config_path.write_text(json.dumps(configuration, indent=2))
    config_path.chmod(0o600)
    service = f'''[Unit]
Description=Rime release updater
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory={install}
ExecStart={sys.executable} -m update_runtime.worker --config {config_path}
UMask=0077
Nice=10
Restart=on-failure
RestartSec=5
'''
    watcher = f'''[Unit]
Description=Watch Rime update requests

[Path]
PathExists={queue}/request.json
Unit=rime-update.service

[Install]
WantedBy=multi-user.target
'''
    for name, content in [('rime-update.service', service), ('rime-update.path', watcher)]:
        target = Path('/etc/systemd/system') / name
        if target.exists():
            shutil.copy2(target, install / (name + '.before'))
        target.write_text(content)
        target.chmod(0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'rime-update.path'], check=True)
    marker = queue / 'agent.json'
    marker.write_text(json.dumps({'protocol': 1}))
    os.chown(marker, uid, gid)
    marker.chmod(0o600)
    print('The Rime update worker is ready. Open the version button in the panel.')


if __name__ == '__main__':
    main()
