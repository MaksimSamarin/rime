"""Authenticate controller API connections before forwarding to a private Unix API."""
import atexit
import errno
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import stat
import tempfile
import threading


class BridgeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            with self.server.context.wrap_socket(self.request, server_side=True) as incoming:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as outgoing:
                    outgoing.settimeout(5)
                    outgoing.connect(self.server.internal)
                    incoming.settimeout(None)
                    outgoing.settimeout(None)

                    def copy(source, destination):
                        try:
                            while data := source.recv(65536):
                                destination.sendall(data)
                        except (OSError, ssl.SSLError):
                            pass
                        finally:
                            for stream in (source,destination):
                                try:
                                    stream.shutdown(socket.SHUT_RDWR)
                                except OSError:
                                    pass

                    upstream = threading.Thread(target=copy, args=(incoming,outgoing), daemon=True)
                    upstream.start()
                    copy(outgoing,incoming)
                    upstream.join(timeout=2)
        except (OSError, ssl.SSLError):
            pass


class BridgeServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, context, internal, connections=32,per_source=4,policy_file=None):
        self.context = context
        self.internal = internal
        self.slots = threading.BoundedSemaphore(connections)
        self.per_source=per_source
        self.source_lock=threading.Lock()
        self.source_counts={}
        self.policy_file=Path(policy_file) if policy_file else None
        super().__init__(address, BridgeHandler)

    def allowed(self,address):
        if self.policy_file is None:return True
        try:
            if self.policy_file.is_symlink() or self.policy_file.stat().st_size>16384:return False
            policy=json.loads(self.policy_file.read_text())
            sources=policy['sources']
            if not isinstance(sources,list) or not 1<=len(sources)<=64:return False
            return ipaddress.ip_address(address) in {ipaddress.ip_address(value) for value in sources}
        except (OSError,ValueError,KeyError,TypeError):
            return False

    def release(self,source):
        with self.source_lock:
            count=self.source_counts[source]-1
            if count:self.source_counts[source]=count
            else:del self.source_counts[source]
        self.slots.release()

    def process_request(self, request, client_address):
        source=client_address[0]
        if not self.allowed(source):
            self.shutdown_request(request)
            return
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.source_lock:
            if self.source_counts.get(source,0)>=self.per_source:
                self.slots.release()
                self.shutdown_request(request)
                return
            self.source_counts[source]=self.source_counts.get(source,0)+1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.release(source)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.release(client_address[0])


class APIBridge:
    def __init__(self, host, port, certificate, key, client_certificate, internal=None,policy_file=None):
        if not client_certificate:
            raise ValueError('SSL_CLIENT_CERT_FILE is required for the node API')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['h2'])
        context.load_cert_chain(certificate, key)
        context.load_verify_locations(cafile=client_certificate)
        context.verify_mode = ssl.CERT_REQUIRED
        self.directory = None
        if internal is None:
            self.directory = Path(tempfile.mkdtemp(prefix='rime-node-api-'))
            self.directory.chmod(0o700)
            internal = self.directory/'api.sock'
        self.internal = Path(internal)
        parent = self.internal.parent.stat()
        if (not self.internal.is_absolute() or self.internal.parent.is_symlink()
                or parent.st_mode & 0o077 or parent.st_uid != os.getuid()):
            raise ValueError('The internal API requires an owned private Unix socket directory')
        try:
            self.server = BridgeServer((host,port), context, str(self.internal),policy_file=policy_file)
        except BaseException:
            if self.directory is not None:
                self.directory.rmdir()
            raise
        self.closed = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.directory is not None:
            try:
                if self.internal.is_socket():
                    self.internal.unlink()
                self.directory.rmdir()
            except OSError:
                pass

    def prepare_endpoint(self):
        if self.internal.exists():
            previous = self.internal.lstat()
            if not stat.S_ISSOCK(previous.st_mode) or previous.st_uid != os.getuid():
                raise ValueError('The internal API socket path has changed ownership')
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.settimeout(.2)
                try:
                    connection.connect(str(self.internal))
                except OSError as error:
                    if error.errno not in (errno.ECONNREFUSED,errno.ENOENT):
                        raise
                    if self.internal.exists() and self.internal.lstat().st_ino == previous.st_ino:
                        self.internal.unlink()
        return str(self.internal)+',0600',0


_bridge = None
_bridge_lock = threading.Lock()


def internal_endpoint():
    """Keep one API listener and endpoint for the complete node process lifetime."""
    global _bridge
    with _bridge_lock:
        if _bridge is None:
            from config import (XRAY_API_HOST, XRAY_API_PORT, SSL_CERT_FILE,
                                SSL_KEY_FILE, SSL_CLIENT_CERT_FILE)
            _bridge = APIBridge(XRAY_API_HOST, XRAY_API_PORT, SSL_CERT_FILE,
                                SSL_KEY_FILE, SSL_CLIENT_CERT_FILE,
                                policy_file=os.environ.get('RIME_MANAGEMENT_SOURCES_FILE','/state/control-policy/sources.json'))
            atexit.register(_bridge.close)
        return _bridge.prepare_endpoint()
