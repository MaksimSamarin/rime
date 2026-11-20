"""Qualify real forwarding counters across hot replacement in a closed network."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
from pathlib import Path
import socket
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0,str(Path(__file__).parents[1]))
from hy2bridge.relay_accounting import RelayAccounting
from hy2bridge.relay_control import forwarding_service
from hy2bridge.store import Store


def main(binary):
    spec = importlib.util.spec_from_file_location('relay_observer',Path(__file__).parents[1]/'relay-runtime'/'observer.py')
    observer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observer)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        journal = observer.Journal(root/'transport.sqlite3')
        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                journal.observe(value['events'],'boot')
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def log_message(self,*_):
                pass

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                while value := self.request.recv(65536):
                    self.request.sendall(value)

        receiver = HTTPServer(('127.0.0.1',16441),Receiver)
        echo = socketserver.ThreadingTCPServer(('127.0.0.1',16442),Echo)
        echo.daemon_threads = True
        for server in [receiver,echo]:
            threading.Thread(target=server.serve_forever,daemon=True).start()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        identity = 'a'*32
        first = forwarding_service(identity+'-00000001',16443,'127.0.0.1',16442,'tcp')
        config = {'services':[first],'api':{'addr':'127.0.0.1:16440','pathPrefix':'/api'},
                  'observers':[{'name':'rime-meter','plugin':{'type':'http','addr':'http://127.0.0.1:16441','timeout':'2s'}}]}
        path = root/'gost.json'
        path.write_text(json.dumps(config))
        process = subprocess.Popen([binary,'-C',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def request(method,path,value=None):
            data = json.dumps(value).encode() if value is not None else None
            return opener.open(urllib.request.Request('http://127.0.0.1:16440/api/config'+path,
                data=data,method=method,headers={'Content-Type':'application/json'}),timeout=3).read()

        def wait_counter(generation,expected):
            for _ in range(50):
                with journal.connect() as database:
                    row = database.execute('SELECT rx,tx FROM observations WHERE epoch=?',('boot-'+generation,)).fetchone()
                if row == (expected,expected):
                    return
                time.sleep(.1)
            raise AssertionError('Forwarding observation does not match the transmitted bytes')

        def transfer(connection,size):
            payload = b'fixture-'*(size//8)
            connection.sendall(payload)
            received = bytearray()
            while len(received)<len(payload):
                received.extend(connection.recv(len(payload)-len(received)))
            if bytes(received)!=payload:
                raise AssertionError('Forwarded payload differs')

        try:
            time.sleep(.5)
            with socket.create_connection(('127.0.0.1',16443),timeout=3) as held:
                transfer(held,4096)
                wait_counter('00000001',4096)
                request('DELETE','/services/'+first['name'])
                second = forwarding_service(identity+'-00000002',16443,'127.0.0.1',16442,'tcp')
                request('POST','/services',second)
                # Retired connections still report under their original generation.
                transfer(held,2048)
                with socket.create_connection(('127.0.0.1',16443),timeout=3) as fresh:
                    transfer(fresh,8192)
                    wait_counter('00000001',6144)
                    wait_counter('00000002',8192)
            journal.collect('boot',{'cpu_percent':1})
            db_path = root/'panel.sqlite3'
            with sqlite3.connect(db_path) as database:
                database.execute('CREATE TABLE fleet_tunnel_services(id TEXT PRIMARY KEY,entry TEXT)')
                database.execute('INSERT INTO fleet_tunnel_services VALUES(?,?)',(identity,'entry'))
            accounting = RelayAccounting(Store(db_path))
            while row := journal.first():
                packet = json.loads(row[1])
                accounting.ingest('entry',packet)
                accounting.ingest('entry',packet)
                journal.acknowledge(row[0])
            with sqlite3.connect(db_path) as database:
                actual = database.execute('SELECT rx,tx FROM fleet_relay_totals').fetchone()
            if actual != (14336,14336):
                raise AssertionError('Hot replacement or retry changed the accounting total')
            actual_config = json.loads(request('GET',''))
            if actual_config.get('metrics'):
                raise AssertionError('Unbounded Prometheus label retention is enabled')
            print('PASS retired and current generations report independently, exact bytes and retries are preserved; Prometheus is disabled')
        finally:
            process.terminate()
            process.wait(timeout=5)
            for server in [receiver,echo]:
                server.shutdown()
                server.server_close()


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary',default='/opt/rime-relay/gost')
    main(parser.parse_args().binary)
