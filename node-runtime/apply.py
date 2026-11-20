"""Patch the v0.5 node lifecycle without changing client keys or VPN settings.

Run against a staged node source directory, never an unreviewed live checkout.
The upstream source and its license remain in the resulting node image.
"""
import ast
from pathlib import Path
import sys


def patch_rpyc(root):
    path = Path(root) / 'rpyc_service.py'
    if not path.exists():
        return
    source = path.read_text()
    if '_rime_lock' in source:
        raise ValueError('RPyC node is already patched')
    tree = ast.parse(source)
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'XrayService')
    methods = {node.name: node for node in owner.body if isinstance(node, ast.FunctionDef)}
    replacements = {
        '__init__': '''    def __init__(self):
        self.core = None
        self.connection = None
        self._rime_effective = None
        self._rime_lock = RLock()
        self._rime_sessions = local()
        self._rime_owner = None
''',
        'on_connect': '''    def on_connect(self, conn):
        with self._rime_lock:
            peer, _ = socket.getpeername(conn._channel.stream.sock)
            conn.peer = peer
            self._rime_sessions.connection = conn
''',
        'on_disconnect': '''    def on_disconnect(self, conn):
        with self._rime_lock:
            if conn is self.connection:
                self.connection = None
                self._rime_owner = None
                logger.warning('Controller session closed')
            if getattr(self._rime_sessions, 'connection', None) is conn:
                self._rime_sessions.connection = None
''',
        'start': '''    @rpyc.exposed
    def start(self, config: str, users_verified=False):
        with self._rime_lock:
            self._rime_require_owner()
            config = XRayConfig(prepare_config(config), self.connection.peer)
            incoming = config.to_json()
            if self.core and self.core.started and users_verified is True and equivalent_static(self._rime_effective, incoming):
                self._rime_effective = incoming
                return self.capabilities()
            if self.core:
                self.core.stop()
            self.core = XRayCore(executable_path=XRAY_EXECUTABLE_PATH, assets_path=XRAY_ASSETS_PATH)
            @self.core.on_start
            def on_start():
                connection = self.connection
                if connection and hasattr(connection.root, 'on_start'):
                    try:
                        connection.root.on_start()
                    except Exception as error:
                        logger.debug('Controller start notification failed: %s', type(error).__name__)
            @self.core.on_stop
            def on_stop():
                connection = self.connection
                if connection and hasattr(connection.root, 'on_stop'):
                    try:
                        connection.root.on_stop()
                    except Exception as error:
                        logger.debug('Controller stop notification failed: %s', type(error).__name__)
            self.core.start(config)
            self._rime_effective = incoming
            return self.capabilities()
''',
        'stop': '''    @rpyc.exposed
    def stop(self):
        with self._rime_lock:
            self._rime_require_owner()
            if self.core:
                self.core.stop()
            self.core = None
            self._rime_effective = None
''',
        'restart': '''    @rpyc.exposed
    def restart(self, config: str):
        with self._rime_lock:
            self.stop()
            return self.start(config)
''',
    }
    lines = source.splitlines(keepends=True)
    for name in sorted(replacements, key=lambda value: methods[value].lineno, reverse=True):
        method = methods[name]
        first = min([method.lineno, *[decorator.lineno for decorator in method.decorator_list]])
        lines[first - 1:method.end_lineno] = [replacements[name]]
    source = ''.join(lines)
    source += '''
    def _rime_require_owner(self):
        caller = getattr(self._rime_sessions, 'connection', None)
        if caller is None or getattr(caller, 'closed', False) is True:
            raise ConnectionError('Controller session is unavailable')
        if self.connection is None:
            self.claim(None)
        if self.connection is not caller:
            raise ConnectionError('Controller ownership changed')

    @rpyc.exposed
    def claim(self, expected_owner):
        with self._rime_lock:
            caller = getattr(self._rime_sessions, 'connection', None)
            if caller is None or getattr(caller, 'closed', False) is True:
                raise ConnectionError('Controller session is unavailable')
            if caller is self.connection:
                return self.capabilities()
            if expected_owner != self._rime_owner:
                raise ConnectionError('Controller ownership changed')
            previous = self.connection
            self.connection = caller
            self._rime_owner = uuid4().hex
            if previous:
                try:
                    previous._channel.close()
                except Exception:
                    pass
            return self.capabilities()

    @rpyc.exposed
    def capabilities(self):
        with self._rime_lock:
            import xray
            return json.dumps({**capabilities(self._rime_effective, self.core),
                               'started': bool(self.core and self.core.started),
                               'owner': self._rime_owner,
                               'api_mtls': int(getattr(xray, 'RIME_API_MTLS', False) is True)})
'''
    source = 'import json\nfrom threading import RLock, local\nfrom uuid import uuid4\nfrom node_autonomy import capabilities, equivalent_static, prepare_config\n' + source
    compile(source, str(path), 'exec')
    path.write_text(source)


def patch(root):
    path=Path(root)/'rest_service.py';source=path.read_text()
    if 'from node_autonomy import' in source:raise ValueError('Node is already patched')
    tree=ast.parse(source)
    service=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Service')
    methods={n.name:n for n in service.body if isinstance(n,ast.FunctionDef)}
    replacements={
        'response':'''    def response(self, **kwargs):
        return {"connected": self.connected, "started": self.core.started,
                "core_version": self.core_version,
                **capabilities(getattr(self, '_rime_effective', None), self.core), **kwargs}
''',
        'connect':'''    def connect(self, request: Request):
        self.session_id = uuid4()
        self.client_ip = request.client.host
        self.connected = True
        return self.response(session_id=self.session_id, autonomous=True)
''',
        'disconnect':'''    def disconnect(self):
        self.session_id = None
        self.client_ip = None
        self.connected = False
        return self.response()
''',
    }
    for name in ('start','restart'):
        method=methods[name]
        method.body.insert(1,ast.parse('config = prepare_config(config)').body[0])
        decode=next(i for i,n in enumerate(method.body) if isinstance(n,ast.Try) and any(
            isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='XRayConfig' for call in ast.walk(n)))
        # Compare the node's *effective* config: the controller uses a random
        # local API port after each boot, which the node replaces with its own.
        code="self._rime_effective = config.to_json()"
        if name=='start':
            method.args.args.append(ast.arg(arg='users_verified',annotation=ast.Name(id='bool',ctx=ast.Load())))
            method.args.defaults.append(ast.parse('Body(False, embed=True)',mode='eval').body)
            code="""if self.core.started and equivalent(getattr(self, '_rime_effective', None), config.to_json()):
    return self.response(autonomous=True)
if self.core.started and users_verified is True and equivalent_static(getattr(self, '_rime_effective', None), config.to_json()):
    self._rime_effective = config.to_json()
    return self.response(autonomous=True, users_reconciled=True)
if self.core.started:
    return self.restart(session_id, config.to_json())
self._rime_effective = config.to_json()"""
        method.body[decode+1:decode+1]=ast.parse(code).body
        rendered=ast.unparse(ast.fix_missing_locations(method))
        replacements[name]='\n'.join('    '+line if line else line for line in rendered.splitlines())+'\n'
    lines=source.splitlines(keepends=True)
    for name in sorted(replacements,key=lambda name:methods[name].lineno,reverse=True):
        method=methods[name];lines[method.lineno-1:method.end_lineno]=[replacements[name]]
    source='from node_autonomy import equivalent, equivalent_static, capabilities, prepare_config\n'+''.join(lines)
    compile(source,str(path),'exec');path.write_text(source)
    helper=Path(__file__).with_name('node_autonomy.py')
    (Path(root)/helper.name).write_bytes(helper.read_bytes())
    patch_rpyc(root)
    from patch_api import patch_api
    patch_api(root)


if __name__=='__main__':patch(sys.argv[1])
