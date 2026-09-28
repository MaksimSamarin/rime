import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from hy2bridge.telemetry import HostResources, PanelRuntime,complete_resources


class TelemetryTests(unittest.TestCase):
    def test_provisioning_requires_complete_fresh_resources_including_real_zero(self):
        metrics={'cpu_percent':0,'mem_total_bytes':100,'mem_available_bytes':50,'disk_total_bytes':1000,'disk_free_bytes':0,
                 'net_rx_bytes':0,'net_tx_bytes':0,'online_connections':0,'service_healthy':True}
        node={'seen_at':1000,'metrics':metrics}
        self.assertTrue(complete_resources(node,now=1001))
        self.assertFalse(complete_resources(node,now=1031))
        for key in metrics:
            missing={**metrics,key:None}
            self.assertFalse(complete_resources({'seen_at':1000,'metrics':missing},now=1001),key)
        self.assertFalse(complete_resources({'seen_at':1000,'metrics':{**metrics,'cpu_percent':float('nan')}},now=1001))
    def test_panel_process_and_host_uptime_are_distinct(self):
        ps=Mock();ps.Process.return_value.create_time.return_value=950
        ps.boot_time.return_value=100;ps.Process.return_value.memory_info.return_value=SimpleNamespace(rss=1234)
        runtime=PanelRuntime(ps,'test-version')
        with patch('hy2bridge.telemetry.time.time',return_value=1000):data=runtime.snapshot()
        self.assertEqual(data['uptime_seconds'],50)
        self.assertEqual(data['host_uptime_seconds'],900)
        self.assertEqual(data['process_memory_bytes'],1234)
        self.assertEqual(data['version'],'test-version')

    def test_cpu_delta_is_shared_across_requests_and_guest_not_counted_twice(self):
        ps = Mock()
        ps.cpu_times.side_effect = [Mock(_asdict=lambda:dict(user=100,idle=900,guest=40)),
                                   Mock(_asdict=lambda:dict(user=150,idle=950,guest=65)),
                                   Mock(_asdict=lambda:dict(user=150,idle=950,guest=65))]
        ps.virtual_memory.return_value=SimpleNamespace(total=1000,available=400)
        ps.disk_usage.return_value=SimpleNamespace(total=2000,free=500)
        sampler=HostResources(ps,'/state')
        with patch('hy2bridge.telemetry.time.monotonic',side_effect=[10,12,12.1]):
            self.assertIsNone(sampler.snapshot()['cpu_percent'])
            value=sampler.snapshot()
            self.assertEqual(value['cpu_percent'],50)
            self.assertEqual(sampler.snapshot()['cpu_percent'],50)
        self.assertEqual(value['mem_total_bytes'],1000)
        self.assertEqual(value['disk_free_bytes'],500)
        ps.disk_usage.assert_called_with('/state')
