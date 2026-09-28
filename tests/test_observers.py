import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock,patch
import test_accounting
from test_accounting import connect
from hy2bridge.observer import Resources,Sender
from hy2bridge.observers import Observers
from hy2bridge.operations import Operations
from hy2bridge.registry import Registry


class ObserverRegistryTests(unittest.TestCase):
    setUp=test_accounting.AccountingTests.setUp
    tearDown=test_accounting.AccountingTests.tearDown

    def setup_nodes(self):
        with connect(self.path) as db:
            db.execute('CREATE TABLE nodes(id INTEGER,name TEXT,address TEXT,status TEXT,message TEXT,xray_version TEXT,last_status_change TEXT)')
            db.execute("INSERT INTO nodes VALUES(3,'native','native.invalid','connected',NULL,'core-test',NULL)")
        ops=Operations(self.store);registry=Registry(self.store)
        entries=[{'node':'xray:3','kind':'native','token':'a'*40,'name':'native','domain':'native.invalid','address':'native.invalid','port':443},
                 {'node':'old-hy2','kind':'legacy_hy2','token':'b'*40,'name':'old Hy2','domain':'old.invalid','address':'old.invalid','port':443}]
        return ops,registry,entries

    def test_scoped_credentials_are_hashed_and_never_authorize_accounting(self):
        ops,registry,entries=self.setup_nodes();observer=Observers(self.store,entries)
        self.assertTrue(observer.authorize('xray:3','Bearer '+'a'*40))
        self.assertFalse(observer.authorize('old-hy2','Bearer '+'a'*40))
        self.assertFalse(observer.authorize('xray:3','a'*40))
        self.assertFalse(registry.authorize('old-hy2','Bearer '+'b'*40))
        with connect(self.path) as db:
            self.assertNotEqual(db.execute('SELECT token_hash FROM fleet_observers LIMIT 1').fetchone()[0],'a'*40)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM fleet_managed').fetchone()[0],0)
        Observers(self.store,entries[:1])
        self.assertFalse(observer.authorize('old-hy2','Bearer '+'b'*40))

    def test_legacy_discovery_preserves_users_and_merges_native_resource_metrics(self):
        ops,registry,entries=self.setup_nodes();Observers(self.store,entries);ops.native_probe=lambda _:True
        health={'cpu_percent':17,'mem_total_bytes':1000,'mem_available_bytes':600,'disk_total_bytes':9000,'disk_free_bytes':3000,'resource_observer':True,'service_healthy':True}
        ops.heartbeat('xray:3',dict(health));ops.heartbeat('old-hy2',dict(health))
        nodes={n['id']:n for n in ops.nodes()}
        self.assertEqual(len(nodes),2)
        self.assertEqual(nodes['xray:3']['metrics']['cpu_percent'],17)
        self.assertEqual(nodes['xray:3']['metrics']['core_version'],'core-test')
        self.assertIsNotNone(nodes['xray:3']['seen_at'])
        self.assertTrue(nodes['old-hy2']['monitoring_only'])
        self.assertEqual(nodes['old-hy2']['state'],'healthy')
        ops.heartbeat('old-hy2',{**health,'service_healthy':False})
        self.assertIsNone(next(e for e in ops.events() if e['code']=='service_unavailable')['resolved_at'])
        ops.heartbeat('old-hy2',dict(health))
        self.assertIsNotNone(next(e for e in ops.events() if e['code']=='service_unavailable')['resolved_at'])
        self.assertEqual(registry.links('test-uuid'),[])
        with connect(self.path) as db:
            self.assertEqual(db.execute('SELECT used_traffic FROM users').fetchone()[0],0)
            self.assertEqual(json.loads(db.execute('SELECT settings FROM proxies').fetchone()[0])['id'],'test-uuid')

    def test_nonexistent_native_node_is_rejected(self):
        _,_,entries=self.setup_nodes();entries[0]['node']='xray:99'
        with self.assertRaises(ValueError):Observers(self.store,entries)


class ResourceObserverTests(unittest.TestCase):
    def test_hy2_connections_distinguish_zero_unavailable_and_unconfigured(self):
        self.assertEqual(Resources({}).connections()['connection_metric_state'],'not_configured')
        sampler=Resources({'stats_url':'http://127.0.0.1:19999','stats_secret':'test-secret-1234567890'})
        response=MagicMock();sampler.stats=MagicMock();sampler.stats.open.return_value.__enter__.return_value=response
        response.read.return_value=b'{}'
        empty=sampler.connections();self.assertEqual(empty['online_users'],0);self.assertEqual(empty['online_connections'],0);self.assertEqual(empty['connection_metric_state'],'available')
        response.read.return_value=b'{"one-user":2,"another":1}'
        self.assertEqual(sampler.connections()['online_connections'],3)
        self.assertEqual(sampler.connections()['online_users'],2)
        sampler.stats.open.side_effect=OSError('synthetic')
        result=sampler.connections();self.assertIsNone(result['online_connections']);self.assertEqual(result['connection_metric_state'],'unavailable')

    def test_statistics_secret_cannot_be_sent_to_a_remote_endpoint(self):
        with self.assertRaises(ValueError):Resources({'stats_url':'http://remote.invalid:19999','stats_secret':'test-secret-1234567890'})

    def test_cpu_delta_socket_count_and_service_state_are_real_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'net').mkdir();(p/'123').mkdir()
            (p/'stat').write_text('cpu 100 0 0 900 0 0 0 0 20 0\n')
            (p/'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 400 kB\n')
            (p/'uptime').write_text('100.5 0\n')
            (p/'123/comm').write_text('xray\n');(p/'123/stat').write_text('123 (xray) S 0 0\n')
            (p/'net/tcp').write_text('header\n0: 00000000:01BB 00000000:0000 0A\n1: 00000000:01BB 00000000:FFFF 01\n2: 00000000:0016 00000000:FFFF 01\n3: 00000000:F262 00000000:FFFF 01\n4: 00000000:A011 00000000:01BB 01\n')
            sampler=Resources({'protocol':'xray','vpn_port':443,'process_names':['xray']},tmp)
            with patch('hy2bridge.observer.os.statvfs',return_value=SimpleNamespace(f_blocks=100,f_bavail=30,f_frsize=1024),create=True),patch('hy2bridge.observer.os.getloadavg',return_value=(.5,.2,.1),create=True):
                first=sampler.sample();self.assertIsNone(first['cpu_percent'])
                (p/'stat').write_text('cpu 150 0 0 950 0 0 0 0 30 0\n')
                second=sampler.sample();self.assertEqual(second['cpu_percent'],50)
                self.assertEqual(second['online_connections'],1);self.assertTrue(second['service_healthy'])
                self.assertEqual(second['mem_available_bytes'],400*1024)
                self.assertEqual(second['disk_free_bytes'],30*1024)
                (p/'123/stat').write_text('123 (xray) Z 0 0\n')
                self.assertFalse(sampler.sample()['service_healthy'])

    def test_sender_refuses_unverified_or_credential_bearing_endpoints(self):
        for url in ['http://remote.invalid/api/fleet/telemetry/a','https://user:pass@remote.invalid/api/fleet/telemetry/a','https://remote.invalid/api/users']:
            with self.assertRaises(ValueError):Sender({'url':url,'token':'a'*40})
