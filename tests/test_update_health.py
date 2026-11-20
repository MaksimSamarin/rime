import http.server
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import unittest
import json

from update_runtime.health import check


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_GET(self):
        raw=(json.dumps({'version':'0.9.0','ready':True,'scheduler':True,'migrations':True,'hub_api':True}).encode()
             if self.path=='/api/system/updates/ready' and self.headers.get('Authorization')=='Bearer '+'a'*48
             else b'<!doctype html><title>Rime</title>')
        self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)


class HealthTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.version=self.root/'version.py'
        self.version.write_text('__version__ = "0.9.0"\n')
        (self.root/'.health-token').write_text('a'*48)

    def serve(self,server):
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

    def test_unix_listener_is_checked_through_its_socket(self):
        if not hasattr(socket,'AF_UNIX'):self.skipTest('Unix sockets are unavailable')
        path=str(self.root/'panel.sock')
        server=socketserver.ThreadingUnixStreamServer(path,Handler)
        self.serve(server)
        check('0.9.0',{'UVICORN_UDS':path,'RIME_UPDATE_DIRECTORY':str(self.root)},self.version)

    def test_plain_http_uses_the_loopback_binding_of_the_panel(self):
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.serve(server)
        check('0.9.0',{'UVICORN_HOST':'::','UVICORN_PORT':str(server.server_port),'RIME_UPDATE_DIRECTORY':str(self.root)},self.version)

    def test_different_source_version_is_rejected(self):
        with self.assertRaises(ValueError):check('0.9.1',{},self.version)

    def test_html_only_panel_is_not_ready(self):
        class Broken(Handler):
            def do_GET(self):
                raw=b'<title>Rime</title>';self.send_response(200);self.end_headers();self.wfile.write(raw)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Broken);self.serve(server)
        with self.assertRaises(ValueError):
            check('0.9.0',{'UVICORN_PORT':str(server.server_port),'RIME_UPDATE_DIRECTORY':str(self.root)},self.version)

    def test_migrations_or_scheduler_not_ready_rejects_candidate(self):
        class Broken(Handler):
            def do_GET(self):
                raw=(b'<title>Rime</title>' if self.path=='/fleet' else
                     b'{"version":"0.9.0","ready":true,"scheduler":false,"migrations":true}')
                self.send_response(200);self.end_headers();self.wfile.write(raw)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Broken);self.serve(server)
        with self.assertRaises(ValueError):
            check('0.9.0',{'UVICORN_PORT':str(server.server_port),'RIME_UPDATE_DIRECTORY':str(self.root)},self.version)
