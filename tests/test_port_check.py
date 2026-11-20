import json
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

from hy2bridge.port_check import port_checks


def free_tcp_port():
    # Unprivileged port: CI runners cannot bind ports below 1024.
    with socket.socket() as probe:
        probe.bind(('0.0.0.0', 0))
        return probe.getsockname()[1]


class PortChecksTests(unittest.TestCase):
    def docker(self, bindings):
        containers = [{'Name': '/' + name, 'HostConfig': {'PortBindings': ports}} for name, ports in bindings.items()]
        return [subprocess.CompletedProcess([], 0, 'container-id\n', ''),
                subprocess.CompletedProcess([], 0, json.dumps(containers), '')]

    def check(self, bindings, ports, **kwargs):
        with patch('hy2bridge.port_check.shutil.which', return_value='/usr/bin/docker'), \
                patch('hy2bridge.port_check.subprocess.run', side_effect=self.docker(bindings)):
            return port_checks(ports, **kwargs)

    def test_docker_publication_blocks_even_when_socket_can_bind(self):
        checks = self.check({'vless': {'24443/tcp': [{'HostPort': '443'}]}}, [(443, 'tcp')])
        self.assertFalse(checks[0]['passed'])
        self.assertIn('vless', checks[0]['message'])

    def test_hysteria_udp_does_not_block_https_tcp(self):
        port = free_tcp_port()
        checks = self.check({'hy2': {'24443/udp': [{'HostPort': str(port)}]}}, [(port, 'tcp')])
        self.assertTrue(checks[0]['passed'])

    def test_cleanup_cannot_hide_foreign_owner_on_same_port(self):
        bindings = {name: {'8443/tcp': [{'HostPort': '443'}]} for name in ['old-proxy', 'vless']}
        checks = self.check(bindings, [(443, 'tcp')], ignored_containers=['old-proxy'], owned_ports=[(443, 'tcp')])
        self.assertFalse(checks[0]['passed'])

    def test_only_selected_proxy_is_exempted_for_replacement(self):
        port = free_tcp_port()
        checks = self.check({'old-proxy': {'8443/tcp': [{'HostPort': str(port)}]}}, [(port, 'tcp')],
                            ignored_containers=['old-proxy'])
        self.assertTrue(checks[0]['passed'])

    def test_native_tcp_listener_blocks_without_docker(self):
        with socket.socket() as listener:
            listener.bind(('0.0.0.0', 0))
            listener.listen()
            with patch('hy2bridge.port_check.shutil.which', return_value=None):
                checks = port_checks([(listener.getsockname()[1], 'tcp')])
            self.assertFalse(checks[0]['passed'])

    def test_daemon_failure_cannot_claim_port_is_free(self):
        with patch('hy2bridge.port_check.shutil.which', return_value='/usr/bin/docker'), \
                patch('hy2bridge.port_check.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'daemon unavailable')):
            with self.assertRaises(RuntimeError):
                port_checks([(443, 'tcp')])

    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux TCP rebinding semantics')
    def test_closed_tcp_sessions_do_not_claim_an_active_listener(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1];listener.listen(1)
            with socket.create_connection(('127.0.0.1',port)) as client:
                peer,_=listener.accept();peer.shutdown(socket.SHUT_WR)
                self.assertEqual(client.recv(1),b'');client.close();peer.close()
        with socket.socket() as strict:
            with self.assertRaises(OSError):strict.bind(('0.0.0.0',port))
        with patch('hy2bridge.port_check.shutil.which',return_value=None):
            self.assertTrue(port_checks([(port,'tcp')])[0]['passed'])

    def test_reusable_active_tcp_and_udp_listeners_still_block(self):
        for protocol,kind in [('tcp',socket.SOCK_STREAM),('udp',socket.SOCK_DGRAM)]:
            with socket.socket(socket.AF_INET,kind) as listener:
                if sys.platform.startswith('linux'):listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                listener.bind(('0.0.0.0',0));port=listener.getsockname()[1]
                if protocol=='tcp':listener.listen(1)
                with patch('hy2bridge.port_check.shutil.which',return_value=None):
                    self.assertFalse(port_checks([(port,protocol)])[0]['passed'])


if __name__ == '__main__':
    unittest.main()
