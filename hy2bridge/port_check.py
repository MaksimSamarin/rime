"""Read-only socket and Docker publication checks for standalone SSH workers."""
import json
import shutil
import socket
import subprocess
import sys


def port_checks(ports, ignored_containers=(), owned_ports=()):
    published = {}
    if shutil.which('docker'):
        result = subprocess.run(['docker', 'ps', '-q', '--no-trunc'], capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError('Docker port ownership cannot be confirmed')
        identities = result.stdout.split()
        if identities:
            result = subprocess.run(['docker', 'inspect', *identities], capture_output=True, text=True, timeout=20)
            if result.returncode:
                raise RuntimeError('Docker port ownership changed; repeat the check')
            for container in json.loads(result.stdout):
                name = container['Name'].lstrip('/')
                for binding, entries in (container['HostConfig'].get('PortBindings') or {}).items():
                    protocol = binding.rsplit('/', 1)[1]
                    for entry in entries or []:
                        published.setdefault((int(entry['HostPort']), protocol), set()).add(name)
    ignored = set(ignored_containers)
    owned = set(owned_ports)
    checks = []
    for port, protocol in ports:
        owners = published.get((port, protocol), set())
        foreign = owners - ignored
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM) as listener:
            try:
                # Linux servers can rebind after closed TCP sessions (TIME_WAIT).
                # Never use SO_REUSEPORT, or reuse a live UDP socket.
                if protocol=='tcp' and sys.platform.startswith('linux'):
                    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                listener.bind(('0.0.0.0', port))
                if protocol=='tcp':listener.listen(1)
                free = True
            except OSError:
                free = False
        pending = bool(owners & ignored) or (port, protocol) in owned
        passed = not foreign and (free or pending)
        if foreign:
            status = 'занят контейнером ' + ', '.join(sorted(foreign))
        elif pending:
            status = 'будет освобождён при переключении выбранной установки'
        else:
            status = 'свободен' if free else 'занят службой сервера'
        checks.append({'passed': passed, 'message': f'Порт {port}/{protocol.upper()} {status}'})
    return checks
