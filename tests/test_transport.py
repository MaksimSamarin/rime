"""Linux-only agent HTTPS trust and redirect credential boundary."""
import datetime
import http.server
import ssl
import tempfile
from pathlib import Path
import threading
import unittest
import urllib.error

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

try:
    from hy2bridge.node import HTTP
except ImportError:HTTP=None

@unittest.skipIf(HTTP is None,'Linux node agent uses fcntl')
class TransportTests(unittest.TestCase):
    def test_verified_tls_rejects_untrusted_ca_and_redirect(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.datetime.now(datetime.timezone.utc)
            cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False).sign(key,hashes.SHA256())
            (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            reached=[]
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    reached.append(self.path)
                    if self.path=='/redirect':
                        self.send_response(302);self.send_header('Location','/leak');self.end_headers()
                    else:
                        self.send_response(200);self.end_headers();self.wfile.write(b'{"ok":true}')
                def log_message(self,*args):pass
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'cert.pem',root/'key.pem')
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                url=f'https://localhost:{server.server_port}'
                with self.assertRaises(urllib.error.URLError):HTTP().request(url,'synthetic-token')
                trusted=HTTP(str(root/'cert.pem'))
                self.assertTrue(trusted.request(url,'synthetic-token')['ok'])
                with self.assertRaises(urllib.error.HTTPError):trusted.request(url+'/redirect','synthetic-token')
                self.assertNotIn('/leak',reached)
                with self.assertRaises(urllib.error.URLError):trusted.request(url.replace('localhost','127.0.0.1'),'synthetic-token')
            finally:server.shutdown();server.server_close();thread.join()
