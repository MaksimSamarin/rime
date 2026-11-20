"""Read-only SSH prerequisites and explicit bootstrap of a fresh Debian/Ubuntu VPS."""
import shlex


PROBE = r'''
printf '%s\n' "$(id -u)" "$(id -g)" "$HOME" "$(uname -s)" "$(uname -m)"
printf '%s\n' "$(command -v python3 || true)" "$(command -v docker || true)" "$(command -v apt-get || true)"
if docker info >/dev/null 2>&1; then printf '%s\n' ready; else printf '%s\n' unavailable; fi
awk '/MemTotal:/{print $2}' /proc/meminfo
df -Pk "$HOME" | awk 'NR==2 {print $4}'
printf '%s\n' TCP_SOCKETS
cat /proc/net/tcp /proc/net/tcp6 2>/dev/null || true
printf '%s\n' UDP_SOCKETS
cat /proc/net/udp /proc/net/udp6 2>/dev/null || true
'''

INSTALL = r'''
set -eu
[ "$(id -u)" = 0 ]
. /etc/os-release
case "$ID" in ubuntu|debian) ;; *) exit 40 ;; esac
[ "$(uname -m)" = x86_64 ]
umask 077
mkdir -p "$HOME/.local/share/fleet-nodes"
log="$HOME/.local/share/fleet-nodes/$1.bootstrap.log"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
{
 packages=''
 command -v python3 >/dev/null 2>&1 || packages="$packages python3"
 command -v docker >/dev/null 2>&1 || packages="$packages docker.io iptables"
 if [ -n "$packages" ]; then
  if apt-get -o DPkg::Lock::Timeout=120 -o APT::Update::Error-Mode=any -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update; then
   apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends $packages
  else
   apt-get -o DPkg::Lock::Timeout=120 --no-download install -y --no-install-recommends $packages
  fi
 fi
 if ! docker info >/dev/null 2>&1; then
  systemctl start docker || service docker start
 fi
 docker info >/dev/null
} >"$log" 2>&1
'''


def inspect(client, ports):
    _, output, errors = client.exec_command('sh -c ' + shlex.quote(PROBE), timeout=20)
    raw = output.read(1024 * 1024).decode()
    if output.channel.recv_exit_status() != 0:
        raise ValueError('Не удалось прочитать параметры Linux-сервера')
    header, sockets = raw.split('TCP_SOCKETS\n', 1)
    tcp_sockets,udp_sockets=sockets.split('UDP_SOCKETS\n',1)
    values = header.splitlines()
    if len(values) != 11:
        raise ValueError('Неполные параметры SSH-сервера')
    uid, gid, home, system, architecture, python, docker, apt, docker_state, memory, disk = values
    can_bootstrap = uid == '0' and bool(apt) and architecture == 'x86_64' and system == 'Linux'
    checks = [
        {'passed': system == 'Linux', 'message': 'Linux'},
        {'passed': architecture == 'x86_64', 'message': 'Архитектура x86_64'},
        {'passed': bool(python) or can_bootstrap, 'message': 'Python 3 доступен или будет установлен'},
        {'passed': docker_state=='ready' or (not docker and can_bootstrap), 'message': 'Docker доступен или будет установлен'},
        {'passed': int(disk) * 1024 > 2 * 1024 ** 3, 'message': 'Свободно более 2 GiB'},
    ]
    occupied = set()
    for protocol,table in [('tcp',tcp_sockets),('udp',udp_sockets)]:
        for line in table.splitlines():
            fields = line.split()
            if len(fields) > 3 and ':' in fields[1] and fields[3] in ['0A', '07']:
                occupied.add((int(fields[1].rsplit(':', 1)[1], 16),protocol))
    for port, protocol in ports:
        free=(port,protocol) not in occupied
        checks.append({'passed':free,'message':f'Порт {port}/{protocol} '+('свободен' if free else 'занят')})
    return {'checks': checks, 'home': home, 'uid': int(uid), 'gid': int(gid),
            'mem_total_bytes': int(memory) * 1024, 'python_available': bool(python),
            'docker_installed': bool(docker), 'bootstrap_required': not python or not docker}


def install(client, job):
    command = 'sh -c ' + shlex.quote(INSTALL) + ' rime-bootstrap ' + shlex.quote(job)
    _, output, errors = client.exec_command(command, timeout=600)
    output.read()
    errors.read()
    if output.channel.recv_exit_status() != 0:
        raise ValueError('Подготовка Python/Docker не завершена; журнал сохранён в каталоге установки на сервере')
