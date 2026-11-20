"""Real runtime user mutations followed by controller reconnect, synthetic UUIDs."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import sys
import threading
import time
import types
import uuid

sys.path.insert(0, '/code')
import rest_service
from xray_api import XRay
from xray_api.types import VLESSAccount

ALICE = '11111111-1111-4111-8111-111111111111'
BOB = '22222222-2222-4222-8222-222222222222'
BOB_NEW = '33333333-3333-4333-8333-333333333333'


class PanelConfig(dict):
    def to_json(self):
        return json.dumps(self)


def wrapper_class():
    # Load the complete controller class without booting the panel and its jobs.
    annotation = types.ModuleType('app.xray.config')
    annotation.XRayConfig = PanelConfig
    sys.modules['app.xray.config'] = annotation
    spec = importlib.util.spec_from_file_location('qualified_controller_node', '/code/app/xray/node.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ReSTXRayNode


def rest_controller(service):
    from fastapi import FastAPI
    import uvicorn
    app = FastAPI()
    app.include_router(service.router)
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=62050, log_level='error',
        ssl_certfile='/lab/config/cert.pem', ssl_keyfile='/lab/config/key.pem'))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(.05)
    assert server.started, 'Native REST server did not start'
    node = wrapper_class()('127.0.0.1', 62050, 62051, Path('/lab/config/key.pem').read_text(),
                           Path('/lab/config/cert.pem').read_text())
    return server, thread, node


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


def opened(auth):
    stream = socket.create_connection(('127.0.0.1', 16443), timeout=2)
    stream.settimeout(2)
    try:
        stream.sendall(bytes([0]) + uuid.UUID(auth).bytes + bytes([0, 1]) + (18080).to_bytes(2, 'big') +
                       bytes([1, 127, 0, 0, 1]) + b'hello')
        assert stream.recv(2) == b'\x00\x00'
        assert stream.recv(5) == b'hello'
        return stream
    except BaseException:
        stream.close()
        raise


def fresh(auth):
    try:
        opened(auth).close()
        return True
    except (OSError, AssertionError):
        return False


def continuing(stream):
    try:
        stream.sendall(b'continues')
        return stream.recv(9) == b'continues'
    except OSError:
        return False


def config(with_bob=False):
    clients = [{'id': ALICE, 'email': 'alice', 'level': 0}]
    if with_bob:
        clients.append({'id': BOB, 'email': 'bob', 'level': 0})
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': 16443,
        'tag': 'test', 'protocol': 'vless', 'settings': {'clients': clients, 'decryption': 'none'}}],
        'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom'}]}


def main():
    server = socketserver.ThreadingTCPServer(('127.0.0.1', 18080), Echo)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    results = []
    verify = os.environ.get('REQUIRE_NO_RESTART') == '1'
    wrapper = os.environ.get('USE_CONTROLLER_WRAPPER') == '1'
    mutations = ['add', 'update_uuid', 'remove']
    if verify:
        mutations.extend(['missed_add', 'missed_update_uuid', 'missed_remove', 'reorder'])
    if wrapper:
        mutations.extend(['dead_core_restart', 'unsupported_query', 'transport_query_recovery'])
    try:
        for mutation in mutations:
            service = rest_service.Service()
            held = None
            controller = None
            try:
                request = types.SimpleNamespace(client=types.SimpleNamespace(host='127.0.0.1'))
                original = config(with_bob=mutation not in ('add', 'missed_add'))
                desired = copy.deepcopy(original)
                if wrapper:
                    controller = rest_controller(service)
                    node = controller[2]
                    node.start(PanelConfig(original))
                else:
                    service.connect(request)
                    service.start(service.session_id, json.dumps(original))
                held = opened(ALICE)
                pid = service.core.process.pid
                api = node.api if wrapper else XRay('127.0.0.1', 62051, ssl_cert=Path('/lab/config/cert.pem').read_bytes(), ssl_target_name='lab.invalid')
                if mutation == 'dead_core_restart':
                    service.core.stop()
                    node.start(PanelConfig(original))
                    recovered = service.core.started and service.core.process.pid != pid and fresh(ALICE) and fresh(BOB)
                    result = {'mutation': mutation, 'controller_wrapper': True, 'core_version': service.core_version,
                              'cold_core_recovered': recovered}
                    results.append(result)
                    print(json.dumps(result), flush=True)
                    assert recovered, 'Connected controller did not recover a dead core'
                    continue
                if mutation in ('unsupported_query', 'transport_query_recovery'):
                    api.remove_inbound_user('test', 'bob', timeout=3)
                    assert not fresh(BOB) and continuing(held)
                    original_query = api.get_inbound_users
                    def unavailable(*args, **kwargs):
                        if mutation == 'unsupported_query':
                            raise NotImplementedError('Synthetic unsupported API')
                        raise ConnectionError('Synthetic interrupted transport')
                    api.get_inbound_users = unavailable
                    node.disconnect()
                    if mutation == 'unsupported_query':
                        node.start(PanelConfig(original))
                        correct = service.core.process.pid != pid and fresh(ALICE) and fresh(BOB)
                        result = {'mutation': mutation, 'controller_wrapper': True, 'core_version': service.core_version,
                                  'unsupported_query_restarts_and_restores_users': correct}
                    else:
                        try:
                            node.start(PanelConfig(original))
                        except ConnectionError:
                            pass
                        else:
                            raise AssertionError('Uncertain transport was acknowledged')
                        assert service.core.process.pid == pid and continuing(held) and not fresh(BOB)
                        api.get_inbound_users = original_query
                        node.start(PanelConfig(original))
                        correct = service.core.process.pid == pid and continuing(held) and fresh(BOB)
                        result = {'mutation': mutation, 'controller_wrapper': True, 'core_version': service.core_version,
                                  'transport_uncertainty_preserves_core_then_recovers': correct}
                    results.append(result)
                    print(json.dumps(result), flush=True)
                    assert correct
                    continue
                if mutation in ('add', 'missed_add'):
                    desired['inbounds'][0]['settings']['clients'].append({'id': BOB, 'email': 'bob', 'level': 0})
                    if mutation == 'add':
                        api.add_inbound_user('test', VLESSAccount(email='bob', id=BOB), timeout=3)
                        assert fresh(BOB)
                    else:
                        assert not fresh(BOB)
                    allowed, blocked = [BOB], []
                elif mutation in ('update_uuid', 'missed_update_uuid'):
                    desired['inbounds'][0]['settings']['clients'][1]['id'] = BOB_NEW
                    if mutation == 'update_uuid':
                        api.remove_inbound_user('test', 'bob', timeout=3)
                        api.add_inbound_user('test', VLESSAccount(email='bob', id=BOB_NEW), timeout=3)
                        assert fresh(BOB_NEW) and not fresh(BOB)
                    else:
                        assert fresh(BOB) and not fresh(BOB_NEW)
                    allowed, blocked = [BOB_NEW], [BOB]
                elif mutation in ('remove', 'missed_remove'):
                    desired['inbounds'][0]['settings']['clients'].pop()
                    if mutation == 'remove':
                        api.remove_inbound_user('test', 'bob', timeout=3)
                        assert not fresh(BOB)
                    else:
                        assert fresh(BOB)
                    allowed, blocked = [], [BOB]
                else:
                    desired['inbounds'][0]['settings']['clients'].reverse()
                    allowed, blocked = [BOB], []
                assert continuing(held), 'Dynamic user mutation interrupted another user'
                if wrapper:
                    node.disconnect()
                    node.start(PanelConfig(desired))
                elif verify:
                    service.disconnect()
                    response = service.connect(request)
                    from hy2bridge.native_users import reconcile
                    assert response['user_reconcile'] == 1
                    verified = reconcile(api, desired, response['user_tags'], VLESSAccount)
                    assert verified is True and continuing(held)
                    service.start(service.session_id, json.dumps(desired), users_verified=verified)
                else:
                    service.disconnect()
                    service.connect(request)
                    service.start(service.session_id, json.dumps(desired))
                result = {'mutation': mutation, 'core_version': service.core_version,
                          'controller_wrapper': wrapper,
                          'pid_before': pid, 'pid_after': service.core.process.pid,
                          'pid_preserved': service.core.process.pid == pid, 'alice_flow_preserved': continuing(held),
                          'desired_user_policy': all(fresh(auth) for auth in allowed) and not any(fresh(auth) for auth in blocked)}
                results.append(result)
                print(json.dumps(result), flush=True)
                if verify:
                    assert result['pid_preserved'] and result['alice_flow_preserved'] and result['desired_user_policy']
                else:
                    assert not result['pid_preserved'] and not result['alice_flow_preserved'] and result['desired_user_policy']
            finally:
                if held:
                    held.close()
                if service.core.started:
                    service.core.stop()
                if controller:
                    controller[2].session.close()
                    controller[0].should_exit = True
                    controller[1].join(timeout=5)
    finally:
        server.shutdown()
        server.server_close()
        print(json.dumps({'checks': len(results), 'mode': 'regression' if os.environ.get('REQUIRE_NO_RESTART') == '1' else 'defect-reproduction'}), flush=True)


if __name__ == '__main__':
    main()
