from pathlib import Path
import tempfile
import unittest
from hy2bridge.connections import tcp_summary,hy2_summary


class ConnectionSummaryTests(unittest.TestCase):
    def test_same_source_multiple_transports_is_not_multiple_users(self):
        a=['0:','0100007F:0805','0100000A:A001','01','0','0','0','0','0','100']
        b=['1:','0100007F:0805','0100000A:A002','01','0','0','0','0','0','101']
        c=['2:','0100007F:0805','0200000A:A003','01','0','0','0','0','0','102']
        result=tcp_summary([(4,a),(4,b),(4,c),(4,a)],[],b'test-key',2053)
        self.assertEqual(result['total'],3);self.assertEqual(result['unique_source_ips'],2)
        self.assertEqual(sorted(g['count'] for g in result['groups']),[1,2])
        self.assertIsNone(result['authenticated_users'])
        self.assertNotIn('10.0.0.1',str(result))

    def test_client_instances_and_accounts_have_distinct_counts_without_uuid_leak(self):
        secret_id='credential-that-must-not-appear'
        result=hy2_summary({secret_id:2,'second-account':1,'offline-account':0},b'test-key')
        self.assertEqual(result['total'],3);self.assertEqual(result['authenticated_users'],2)
        self.assertIsNone(result['unique_source_ips']);self.assertNotIn(secret_id,str(result))

    def test_group_truncation_preserves_total(self):
        result=hy2_summary({'account-'+str(i):1 for i in range(60)},b'test-key')
        self.assertEqual(len(result['groups']),50)
        self.assertEqual(result['other_connections'],10)
        self.assertEqual(sum(g['count'] for g in result['groups'])+result['other_connections'],result['total'])
