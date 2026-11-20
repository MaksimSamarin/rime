"""Check the installed console through its actual TCP or Unix listener."""
import ast
import http.client
import os
from pathlib import Path
import socket
import ssl
import json


def check(expected, environment=None, version_file='/code/app/__init__.py'):
    environment = os.environ if environment is None else environment
    version = next(ast.literal_eval(node.value) for node in ast.parse(Path(version_file).read_text()).body
        if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='__version__' for target in node.targets))
    if version != expected:
        raise ValueError('Installed source version differs')
    port = int(environment.get('UVICORN_PORT','8000'))
    certificate = environment.get('UVICORN_SSL_CERTFILE')
    bind = environment.get('UVICORN_HOST','0.0.0.0') if certificate else '127.0.0.1'
    address = {'0.0.0.0':'127.0.0.1','::':'::1'}.get(bind,bind)
    host = address
    if certificate:
        decoded = ssl._ssl._test_decode_cert(certificate)
        names = decoded.get('subjectAltName',[])
        host = next((value for kind,value in names if kind in ('DNS','IP Address') and '*' not in value),None)
        if not host:host = 'rime.' + next(value[2:] for kind,value in names if kind=='DNS' and value.startswith('*.'))
        context = ssl.create_default_context()
        context.load_verify_locations(cafile=certificate)
        connection = http.client.HTTPSConnection(host,port,context=context,timeout=4)
    else:
        connection = http.client.HTTPConnection(host,port,timeout=4)
    def connect(authority,timeout=None,source_address=None):
        if environment.get('UVICORN_UDS'):
            sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                sock.settimeout(timeout)
                sock.connect(environment['UVICORN_UDS'])
                return sock
            except BaseException:
                sock.close()
                raise
        return socket.create_connection((address,port),timeout)
    if environment.get('UVICORN_UDS'):
        def connect_unix():
            sock = connect(None,timeout=4)
            try:
                connection.sock = context.wrap_socket(sock,server_hostname=host) if certificate else sock
            except BaseException:
                sock.close()
                raise
        connection.connect = connect_unix
    else:
        connection._create_connection = connect
    try:
        connection.request('GET','/fleet')
        response = connection.getresponse()
        if response.status != 200 or b'Rime' not in response.read(1024*1024):
            raise ValueError('Installed console readiness check failed')
        from .paths import update_directory
        directory=update_directory(environment.get('SQLALCHEMY_DATABASE_URL','sqlite:////var/lib/marzban/db.sqlite3'),environment)
        token_path=directory/'.health-token'
        if token_path.is_symlink() or token_path.stat().st_size>256:
            raise ValueError('Invalid readiness token file')
        token=token_path.read_text().strip()
        if len(token)<32:raise ValueError('Readiness token unavailable')
        connection.request('GET','/api/system/updates/ready',headers={'Authorization':'Bearer '+token})
        response=connection.getresponse()
        raw=response.read(65537)
        if response.status!=200 or len(raw)>65536:
            raise ValueError('Authenticated API readiness failed')
        value=json.loads(raw)
        if value.get('version')!=expected or any(value.get(name) is not True for name in ('ready','scheduler','migrations','hub_api')):
            raise ValueError('Application components are not ready')
    finally:
        connection.close()
