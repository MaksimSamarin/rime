import grpc
import threading
import weakref


_CONTROL_LOCKS=weakref.WeakValueDictionary()
_CONTROL_LOCKS_GUARD=threading.Lock()


def control_lock(address,port):
    key=(str(address).lower().rstrip('.'),int(port))
    with _CONTROL_LOCKS_GUARD:
        lock=_CONTROL_LOCKS.get(key)
        if lock is None:
            lock=threading.RLock()
            _CONTROL_LOCKS[key]=lock
        return lock


class XRayBase(object):
    def __init__(self, address: str, port: int, ssl_cert: str = None, ssl_target_name: str = None,
                 ssl_key: str = None, client_cert: str = None, control_identity=None,
                 unix_socket: str = None):
        self.control_lock=control_lock(*(control_identity or (address,port)))
        if bool(ssl_key) != bool(client_cert):
            raise ValueError('Both the API client certificate and key are required')
        if ssl_key and ssl_cert is None:
            raise ValueError('Authenticated API access requires a trusted server certificate')
        if unix_socket is not None:
            if not str(unix_socket).startswith('/') or any((ssl_cert,ssl_key,client_cert)):
                raise ValueError('The local API requires an absolute Unix socket path')
            self.address = str(unix_socket)
            self.port = 0
            self._channel = grpc.insecure_channel('unix:'+str(unix_socket),
                                                  options=(('grpc.enable_http_proxy',0),))
        elif ssl_cert is None:
            self.address = address
            self.port = port
            self._channel = grpc.insecure_channel(f"{address}:{port}", options=(('grpc.enable_http_proxy', 0),))

        else:
            self.address = address
            self.port = port
            root = ssl_cert.encode() if isinstance(ssl_cert,str) else ssl_cert
            key = ssl_key.encode() if isinstance(ssl_key,str) else ssl_key
            chain = client_cert.encode() if isinstance(client_cert,str) else client_cert
            credentials = {'root_certificates':root}
            if key:
                credentials.update(private_key=key, certificate_chain=chain)
            creds = grpc.ssl_channel_credentials(**credentials)
            opts = [('grpc.enable_http_proxy', 0)]
            if ssl_target_name is not None:
                opts.append(('grpc.ssl_target_name_override', ssl_target_name))
            self._channel = grpc.secure_channel(f"{address}:{port}",
                                                credentials=creds,
                                                options=opts)
