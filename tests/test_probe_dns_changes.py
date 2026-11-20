import copy
import unittest
from unittest.mock import patch

from hy2bridge.client_probe import probe
from hy2bridge.provision import ProvisionError
from hy2bridge.provision_probe import ProvisionProbe


class ProbeDnsChangesTests(unittest.TestCase):
    def setUp(self):
        self.monitor = ProvisionProbe(None, {}, None, None)
        self.original = {
            'node': 'n1',
            'expected_ip': '8.8.8.8',
            'config': {'_kind': 'hy2', '_hostname': 'node.example', 'server': '8.8.8.8:443'},
        }
        self.monitor.target = lambda *_: copy.deepcopy(self.original)

    def answers(self, *addresses):
        return [(2, 1, 6, '', (address, 0)) for address in addresses]

    def test_active_check_follows_dns_with_an_old_registered_address(self):
        with patch('socket.getaddrinfo', return_value=self.answers('1.1.1.1')):
            target = self.monitor.active_target('job', {})
        self.assertEqual(target['expected_ip'], '1.1.1.1')
        self.assertEqual(target['resolved_ip'], '1.1.1.1')
        self.assertEqual(target['config']['_hostname'], 'node.example')
        self.assertEqual(self.original['expected_ip'], '8.8.8.8')

    def test_multiple_dns_answers_are_pinned_to_one_verified_address(self):
        with patch('socket.getaddrinfo', return_value=self.answers('1.1.1.1', '1.0.0.1')):
            target = self.monitor.active_target('job', {})
        self.assertEqual(target['expected_ip'], target['resolved_ip'])
        self.assertIn(target['resolved_ip'], ['1.1.1.1', '1.0.0.1'])

    def test_private_dns_answers_are_rejected(self):
        with patch('socket.getaddrinfo', return_value=self.answers('127.0.0.1')):
            with self.assertRaises(ProvisionError):
                self.monitor.active_target('job', {})

    def test_all_preserved_hostnames_must_share_the_selected_node_address(self):
        self.original['variants'] = [{'_hostname': 'other.example'}]
        answers = [self.answers('1.1.1.1'), self.answers('8.8.8.8')]
        with patch('socket.getaddrinfo', side_effect=answers):
            with self.assertRaises(ProvisionError):
                self.monitor.active_target('job', {})

    def test_probe_keeps_the_selected_dns_answer_for_the_whole_connection(self):
        target = {**self.original, 'expected_ip': '1.1.1.1', 'resolved_ip': '1.1.1.1'}
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS changed mid-check')):
            with patch('os.access', return_value=False):
                result = probe(target, {'direct_targets': ['1.1.1.1'], 'hysteria_binary': '/missing'}, 1234)
        self.assertEqual(result['stage'], 'configuration')
        self.assertEqual(result['target_ip'], '1.1.1.1')

    def test_pinned_address_still_requires_direct_route_authorization(self):
        target = {**self.original, 'resolved_ip': '1.0.0.1'}
        with patch('socket.getaddrinfo', side_effect=AssertionError('Unnecessary DNS')):
            result = probe(target, {'direct_targets': ['1.1.1.1']}, 1234)
        self.assertEqual(result['stage'], 'route')
        self.assertFalse(result['passed'])


if __name__ == '__main__':
    unittest.main()
