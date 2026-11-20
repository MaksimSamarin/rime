import ast
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


class SubscriptionRenderTests(unittest.TestCase):
    def test_first_reality_render_keeps_short_id_without_mutating_the_source(self):
        path=Path(__file__).parents[1]/'app/subscription/share.py'
        tree=ast.parse(path.read_text(encoding='utf-8'))
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='process_inbounds_and_tags')
        future=ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)
        module=ast.fix_missing_locations(ast.Module(body=[future,function],type_ignores=[]))
        protocol=Enum('Protocol',{'vless':'vless'}).vless
        inbound={'network':'tcp','port':443,'tls':'reality','sni':['node.invalid'],'host':[], 'sids':['1234abcd']}
        host={'id':1,'address':['node.invalid'],'port':443,'sni':None,'host':None,'path':None,'tls':None,
              'alpn':None,'fingerprint':None,'allowinsecure':False,'mux_enable':False,'fragment_setting':None,
              'noise_setting':None,'random_user_agent':False,'remark':'Synthetic'}
        config=SimpleNamespace(inbounds_by_tag={'reality':inbound})
        namespace={'xray':SimpleNamespace(config=config,hosts={'reality':[host]}),
                   'random':SimpleNamespace(choice=lambda values:values[0]),'secrets':SimpleNamespace(token_hex=lambda _: 'salt')}
        exec(compile(module,str(path),'exec'),namespace)
        result=MagicMock()
        with patch('hy2bridge.access.host_allowed',return_value=True):
            namespace['process_inbounds_and_tags']({protocol:['reality']},{protocol:SimpleNamespace(model_dump=lambda:{'id':'synthetic'})},
                                                  {'USERNAME':'synthetic'},result)
        self.assertEqual(result.add.call_args.kwargs['inbound']['sid'],'1234abcd')
        self.assertNotIn('sid',inbound)


if __name__=='__main__':unittest.main()
