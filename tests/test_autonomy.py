import copy
from pathlib import Path
import tempfile
import unittest

from hy2bridge.policy import LocalPolicy


class LocalPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=str(Path(self.tmp.name)/'node.db')
        self.policy=LocalPolicy(self.path)
        self.value={'version':1,'allowed':['known'],'rules':{'known':{'expire':2000,'remaining_bytes':500,'accounted_bytes':100}}}
        self.policy.replace(self.value)

    def test_offline_auth_survives_restart_and_expiry_is_local(self):
        restored=LocalPolicy(self.path)
        self.assertTrue(restored.permits('known',{'known':150},now=1999))
        self.assertFalse(restored.permits('known',{},now=2000))
        self.assertFalse(restored.permits('unknown',{},now=1999))

    def test_only_unacknowledged_local_usage_consumes_remaining_budget(self):
        self.assertTrue(self.policy.permits('known',{'known':599},now=1000))
        self.assertFalse(self.policy.permits('known',{'known':600},now=1000))
        next_value=copy.deepcopy(self.value);next_value['version']=2
        next_value['rules']['known'].update(remaining_bytes=1,accounted_bytes=599)
        self.policy.replace(next_value)
        self.assertTrue(self.policy.permits('known',{'known':599},now=1000))
        self.assertFalse(self.policy.permits('known',{'known':600},now=1000))

    def test_revocation_persists_without_network(self):
        self.policy.replace({'version':2,'allowed':[],'rules':{}})
        self.assertFalse(LocalPolicy(self.path).permits('known',{},now=1000))

    def test_invalid_and_stale_updates_keep_last_good_policy(self):
        for value in [{'version':0},dict(self.value,version=0),dict(self.value,rules={}),dict(self.value,allowed=[])]:
            with self.assertRaises(ValueError):self.policy.replace(value)
            self.assertTrue(LocalPolicy(self.path).permits('known',{},now=1000))

    def test_unprovisioned_node_denies_everything(self):
        self.assertFalse(LocalPolicy(str(Path(self.tmp.name)/'empty.db')).permits('known',{}))


if __name__=='__main__':unittest.main()
