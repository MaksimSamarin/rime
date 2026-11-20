"""REST node reconnect with a real Xray VLESS stream, synthetic keys only."""
import json
import socket
import socketserver
import sys
import threading
import time
import types
import uuid

sys.path.insert(0,'/code')
import rest_service


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data:=self.request.recv(65536):self.request.sendall(data)


def main():
    server=socketserver.ThreadingTCPServer(('127.0.0.1',18080),Echo);server.daemon_threads=True
    threading.Thread(target=server.serve_forever,daemon=True).start()
    service=rest_service.service
    auth=uuid.UUID('11111111-1111-4111-8111-111111111111')
    config=json.dumps({'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':16443,'tag':'test','protocol':'vless',
        'settings':{'clients':[{'id':str(auth)}],'decryption':'none'}}],'outbounds':[{'tag':'DIRECT','protocol':'freedom'}]})
    def opened():
        s=socket.create_connection(('127.0.0.1',16443),timeout=2);s.settimeout(2)
        s.sendall(bytes([0])+auth.bytes+bytes([0,1])+int(18080).to_bytes(2,'big')+bytes([1,127,0,0,1])+b'hello')
        assert s.recv(2)==b'\x00\x00'
        assert s.recv(5)==b'hello'
        return s
    def echo(s):
        s.sendall(b'continues');assert s.recv(9)==b'continues'
    req=types.SimpleNamespace(client=types.SimpleNamespace(host='127.0.0.1'))
    try:
        service.connect(req);service.start(service.session_id,config)
        pid=service.core.process.pid
        a=opened();echo(a)
        service.disconnect();echo(a)
        b=opened();echo(b)
        changed=json.loads(config)
        changed['inbounds'].append({'tag':'API_INBOUND','protocol':'dokodemo-door','listen':'127.0.0.1','port':19901,'settings':{'address':'127.0.0.1'}})
        changed['api']={'tag':'CONTROLLER_API','services':['StatsService']}
        changed['routing']={'rules':[{'type':'field','inboundTag':['API_INBOUND'],'outboundTag':'CONTROLLER_API'}]}
        service.connect(req);service.start(service.session_id,json.dumps(changed));echo(a);echo(b)
        assert service.core.process.pid==pid
        print('PASS native_controller_disconnect_existing_and_new_payload')
        print('PASS native_reconnect_changed_controller_api_port_preserves_pid_and_streams')
        service.stop(service.session_id)
        assert not service.core.started
        print('PASS native_explicit_stop_still_stops_engine')
    finally:
        if service.core.started:service.core.stop()
        server.shutdown();server.server_close()


if __name__=='__main__':main()
