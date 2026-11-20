"""Stage a stable private Unix API behind controller-certificate authentication."""
import ast
from pathlib import Path


def patch_api(root):
    root = Path(root)
    path = root / 'xray.py'
    if not path.is_file():
        return False
    source = path.read_text()
    if 'from api_bridge import internal_endpoint' in source:
        raise ValueError('The native API bridge is already patched')
    tree = ast.parse(source)
    owner = next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='XRayConfig')
    method = next(node for node in owner.body if isinstance(node,ast.FunctionDef) and node.name=='_apply_api')
    replacement = """def _apply_api(self):
    self.api_host,self.api_port = internal_endpoint()
    previous_tag = (self.get('api') or {}).get('tag')
    previous_direct = bool((self.get('api') or {}).get('listen'))
    allowed = globals().get('INBOUNDS')
    self['inbounds'] = [inbound for inbound in self.get('inbounds', [])
        if inbound.get('tag') != 'API_INBOUND' and (not allowed or inbound.get('tag') in allowed)]
    routing = self.setdefault('routing', {})
    routing['rules'] = [rule for rule in routing.get('rules', [])
        if rule.get('inboundTag') != ['API_INBOUND'] and (previous_direct or (
            rule.get('outboundTag') != 'API' and (not previous_tag or rule.get('outboundTag') != previous_tag)))]
    self['api'] = {'tag':'API', 'listen': self.api_host, 'services': ['HandlerService','StatsService','LoggerService']}
    self['stats'] = {}
"""
    method.body = ast.parse(replacement).body[0].body
    rendered = ast.unparse(ast.fix_missing_locations(method))
    lines = source.splitlines(keepends=True)
    lines[method.lineno-1:method.end_lineno] = ['\n'.join('    '+line if line else line for line in rendered.splitlines())+'\n']
    patched = 'from api_bridge import internal_endpoint\nRIME_API_MTLS = True\nRIME_MANAGEMENT_SOURCES = 1\nRIME_API_DIRECT = True\n'+''.join(lines)
    compile(patched,str(path),'exec')
    path.write_text(patched)
    helper = root / 'node_autonomy.py'
    tree = ast.parse(helper.read_text())
    capability = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='capabilities')
    capability.body.insert(0,ast.Import(names=[ast.alias(name='xray')]))
    returned = next(node for node in ast.walk(capability) if isinstance(node,ast.Return))
    if not isinstance(returned.value,ast.Dict):
        raise ValueError('Unexpected native capability representation')
    returned.value.keys.append(ast.Constant(value='api_mtls'))
    returned.value.values.append(ast.parse("int(getattr(xray, 'RIME_API_MTLS', False) is True)",mode='eval').body)
    returned.value.keys.append(ast.Constant(value='management_sources'))
    returned.value.values.append(ast.parse("int(getattr(xray, 'RIME_MANAGEMENT_SOURCES', 0) == 1)",mode='eval').body)
    returned.value.keys.append(ast.Constant(value='api_direct'))
    returned.value.values.append(ast.parse("int(getattr(xray, 'RIME_API_DIRECT', False) is True)",mode='eval').body)
    helper.write_text(ast.unparse(ast.fix_missing_locations(tree))+'\n')
    (root/'api_bridge.py').write_bytes(Path(__file__).with_name('api_bridge.py').read_bytes())
    return True
