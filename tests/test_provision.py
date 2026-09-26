import unittest
from unittest.mock import MagicMock
import test_accounting
from hy2bridge.provision import Provisioner,ProvisionError
from hy2bridge.registry import Registry

class ProvisionTests(unittest.TestCase):
    setUp=test_accounting.AccountingTests.setUp
    tearDown=test_accounting.AccountingTests.tearDown

    def test_target_allowlist_rejects_unlisted_and_shell_input(self):
        p=Provisioner(self.store,{'allowed_hosts':['test.invalid']},None,None,None)
        self.assertEqual(p.target('test.invalid',22),('test.invalid',22))
        for host in ('production.invalid','test.invalid; id','-oProxyCommand=anything','127.0.0.1'):
            with self.assertRaises(ProvisionError):p.target(host,22)
        with self.assertRaises(ProvisionError):p.target('test.invalid',True)

    def test_partial_registration_is_compensated(self):
        register=MagicMock(side_effect=RuntimeError('synthetic'))
        unregister=MagicMock()
        p=Provisioner(self.store,{},register,unregister,lambda *_:False)
        p.validate=lambda _:None
        p.configuration=lambda *args:{'action':'install','id':args[0]}
        client=MagicMock();p.connect=lambda _:client
        p.remote=MagicMock(return_value={'running':True})
        job='a'*32
        record={'data':{'protocol':'vless'},'plan':{'id':job}}
        p.update(job,'running','test');p.worker(record)
        unregister.assert_called_once()
        self.assertEqual(p.remote.call_args.args[1],{'action':'rollback','id':job})
        self.assertEqual(p.job(job)['state'],'rolled_back')
        self.assertEqual(record['data'],{})

    def test_registry_stores_hash_and_publishes_only_ready_node(self):
        import hashlib
        registry=Registry(self.store);token='synthetic-token-12345678901234567890'
        with self.store.connection(write=True) as db:
            db.execute('INSERT INTO fleet_managed(id,protocol,token_hash,name,domain,port) VALUES(?,?,?,?,?,?)',
                ('node','hysteria2',hashlib.sha256(token.encode()).hexdigest(),'A & B','node.invalid',443))
        self.assertTrue(registry.authorize('node','Bearer '+token))
        self.assertFalse(registry.authorize('other','Bearer '+token))
        self.assertFalse(registry.authorize('node',token))
        self.assertEqual(registry.links('user-id'),[])
        with self.store.connection(write=True) as db:db.execute('UPDATE fleet_managed SET active=1')
        self.assertIn('#A%20%26%20B',registry.links('user-id')[0])
