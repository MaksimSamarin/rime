"""Keep the hub API on a UID-private socket and protect loaded routing rules."""
import atexit
import errno
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading


PRIVATE_IPS = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
    '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8',
]
from xray_api.routing import PRIVATE_BLOCK_TAG as BLOCK_TAG, protect_balancers as _protect_balancers


class PrivateAPISocket:
    def __init__(self):
        self.directory = Path(tempfile.mkdtemp(prefix='rime-hub-api-'))
        self.directory.chmod(0o700)
        self.path = self.directory/'api.sock'
        self.closed = False
        atexit.register(self.close)

    def prepare(self):
        parent=self.directory.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid()
                or stat.S_IMODE(parent.st_mode)!=0o700):
            raise ValueError('The hub API socket directory is not private')
        try:
            previous=self.path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(previous.st_mode) or previous.st_uid!=os.getuid():
            raise ValueError('The hub API socket path has changed ownership')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
            stream.settimeout(.2)
            try:
                stream.connect(str(self.path))
            except OSError as error:
                if error.errno not in (errno.ECONNREFUSED,errno.ENOENT):
                    raise
                if self.path.exists() and self.path.lstat().st_ino==previous.st_ino:
                    self.path.unlink()
                return
        raise RuntimeError('The hub API socket is already in use')

    def close(self):
        if self.closed:
            return
        self.closed=True
        try:
            previous=self.path.lstat()
            if stat.S_ISSOCK(previous.st_mode) and previous.st_uid==os.getuid():
                self.path.unlink()
        except FileNotFoundError:
            pass
        try:
            self.directory.rmdir()
        except OSError:
            pass


_endpoint=None
_endpoint_lock=threading.Lock()


def hub_api_endpoint():
    global _endpoint
    with _endpoint_lock:
        if _endpoint is None:
            _endpoint=PrivateAPISocket()
        return _endpoint



def protect_hub_api(config):
    """Apply mandatory guards after reading any operator-supplied XRAY_JSON."""
    endpoint=hub_api_endpoint()
    previous_api=config.get('api') or {}
    old_api_tag=previous_api.get('tag') if not previous_api.get('listen') else None
    # A direct listener registers no API outbound handler. An API_INBOUND ->
    # API route would let a public catch-all balancer select that handler.
    config['api']={'tag':'API','listen':str(endpoint.path)+',0600',
                   'services':['HandlerService','StatsService','LoggerService']}
    if not isinstance(config.get('stats'),dict):
        config['stats']={}
    config['inbounds']=[row for row in config.get('inbounds',[]) if row.get('tag')!='API_INBOUND']
    routing=config.setdefault('routing',{})
    reserved_tags={BLOCK_TAG}
    if old_api_tag:
        reserved_tags.add(old_api_tag)
    old_rules=[row for row in routing.get('rules',[])
               if row.get('outboundTag') not in reserved_tags
               and 'API_INBOUND' not in row.get('inboundTag',[])]
    # Resolve at the first IP guard, even when a loaded domain/catch-all rule
    # would otherwise match. AsIs and IPIfNonMatch can defer that resolution.
    routing['domainStrategy']='IPOnDemand'
    routing['rules']=[
        {'type':'field','domain':['domain:localhost','domain:localhost.',
             'full:ip6-localhost','domain:localhost.localdomain'],'outboundTag':BLOCK_TAG},
        {'type':'field','ip':list(PRIVATE_IPS),'outboundTag':BLOCK_TAG},
        *old_rules,
    ]
    config['outbounds']=[row for row in config.get('outbounds',[])
                         if row.get('tag')!=BLOCK_TAG]
    config['outbounds'].append({'tag':BLOCK_TAG,'protocol':'blackhole'})
    config.api_host=str(endpoint.path)
    config.api_port=0
    return endpoint
