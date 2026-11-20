"""Direct HTTP/HTTPS forward-proxy acceptance without credentials in subprocess arguments."""
import base64
import json
import secrets
import socket
import ssl
import time

from urllib3.util.ssltransport import SSLTransport


def bounded_timeout(deadline, limit=8):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Proxy probe deadline exceeded')
    return min(limit, remaining)


def read_headers(sock, deadline):
    data = bytearray()
    while not data.endswith(b'\r\n\r\n'):
        sock.settimeout(bounded_timeout(deadline))
        part = sock.recv(1)
        if not part or len(data) >= 16384:
            raise OSError('Incomplete proxy response')
        data.extend(part)
    first = bytes(data).split(b'\r\n', 1)[0].split()
    if len(first) < 2 or not first[1].isdigit():
        raise OSError('Invalid proxy response')
    return int(first[1])


def connect(address, port, domain, tls, context, destination, destination_port, credentials, deadline):
    sock = socket.create_connection((address, port), timeout=bounded_timeout(deadline, 6))
    try:
        sock.settimeout(bounded_timeout(deadline))
        if tls:
            sock = context.wrap_socket(sock, server_hostname=domain)
        authority = destination + ':' + str(destination_port)
        headers = ['CONNECT ' + authority + ' HTTP/1.1', 'Host: ' + authority]
        if credentials is not None:
            encoded = base64.b64encode(credentials.encode('utf-8')).decode('ascii')
            headers.append('Proxy-Authorization: Basic ' + encoded)
        sock.settimeout(bounded_timeout(deadline))
        sock.sendall(('\r\n'.join(headers) + '\r\n\r\n').encode('ascii'))
        return sock, read_headers(sock, deadline)
    except BaseException:
        sock.close()
        raise


def probe(address, domain, port, tls, username, password, settings):
    started = time.monotonic()
    deadline = started + 15
    result = {'mode': 'https' if tls else 'http', 'port': port, 'passed': False, 'stage': 'proxy_connect'}
    context = ssl.create_default_context(cafile=settings.get('panel_ca_file'))
    destination = settings.get('probe_host', 'api.ipify.org')
    destination_port = settings.get('probe_port', 443)
    path = settings.get('probe_path', '/?format=json')
    if '\r' in destination or '\n' in destination or not path.startswith('/') or '\r' in path or '\n' in path:
        raise ValueError('Invalid proxy probe endpoint')
    try:
        for credentials, field in [(None, 'anonymous_status'),
                                    (username + ':' + secrets.token_urlsafe(24), 'wrong_password_status')]:
            sock, status = connect(address, port, domain, tls, context, destination, destination_port, credentials, deadline)
            try:
                result[field] = status
                if status != 407:
                    raise OSError('Proxy authentication is not enforced')
            finally:
                sock.close()
        result['stage'] = 'authorization'
        sock, status = connect(address, port, domain, tls, context, destination, destination_port, username + ':' + password, deadline)
        try:
            result['authorized_status'] = status
            if status != 200:
                raise OSError('Proxy authentication failed')
            result['stage'] = 'payload'
            # SSLTransport preserves the outer TLS session for an HTTPS proxy.
            sock.settimeout(bounded_timeout(deadline))
            with SSLTransport(sock, context, server_hostname=destination) as stream:
                stream.settimeout(bounded_timeout(deadline))
                stream.sendall(('GET ' + path + ' HTTP/1.0\r\nHost: ' + destination + '\r\nConnection: close\r\n\r\n').encode('ascii'))
                response = bytearray()
                while True:
                    stream.settimeout(bounded_timeout(deadline))
                    part = stream.recv(4096)
                    if not part:
                        break
                    response.extend(part)
                    if len(response) > 65536:
                        raise OSError('Proxy probe response is too large')
            headers, body = bytes(response).split(b'\r\n\r\n', 1)
            if b' 200 ' not in headers.split(b'\r\n', 1)[0] or json.loads(body).get('ip') != settings.get('expected_egress_ip', address):
                raise OSError('Unexpected proxy egress')
            result['passed'] = True
        finally:
            sock.close()
    except Exception as error:
        result['error'] = type(error).__name__
    result['latency_ms'] = round((time.monotonic() - started) * 1000, 2)
    result['checked_at'] = time.time()
    return result
