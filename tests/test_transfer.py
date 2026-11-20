import copy
import hashlib
import json
import time
import unittest
from unittest.mock import MagicMock, patch

import test_accounting
from hy2bridge.access import Access
from hy2bridge.lifecycle import Lifecycle
from hy2bridge.observers import Observers
from hy2bridge.operations import Operations
from hy2bridge.provision import Provisioner, ProvisionError
from hy2bridge.reachability import Reachability
from hy2bridge.registry import Registry
from hy2bridge.transfer import NodeTransfer


class TransferTests(unittest.TestCase):
    tearDown = test_accounting.AccountingTests.tearDown

    def setUp(self):
        test_accounting.AccountingTests.setUp(self)
        with self.store.connection(write=True) as db:
            db.executescript('''
                CREATE TABLE nodes(id INTEGER PRIMARY KEY,name TEXT,address TEXT,port INTEGER,api_port INTEGER,created_at TEXT);
                INSERT INTO nodes VALUES(1,'Original','1.1.1.1',62050,62051,'2026-01-01'),(2,'Other','9.9.9.9',62050,62051,'2026-01-02');
                CREATE TABLE hosts(id INTEGER PRIMARY KEY,remark TEXT,address TEXT,port INTEGER,inbound_tag TEXT);
                INSERT INTO hosts VALUES(1,'Original','old.example',443,'VLESS_TEST'),(2,'Other','other.example',443,'VLESS_TEST');
                CREATE TABLE fleet_proxy_services(id TEXT PRIMARY KEY,node TEXT,active INTEGER);
            ''')
        self.operations = Operations(self.store)
        self.operations.observers = Observers(self.store)
        self.operations.native_probe = lambda *_: True
        self.registry = Registry(self.store)
        self.access = Access(self.store)
        self.access.save(1, ['group'], ['xray:1'])
        Reachability(self.store)
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_host_nodes VALUES(1,'xray:1'),(2,'xray:2')")
        self.base = Provisioner(self.store, {'panel_url': 'https://panel.example', 'vless_template': {
            'inbound_tag': 'VLESS_TEST', 'service_port': 62050, 'api_port': 62051}}, None, None, None)
        self.life = Lifecycle(self.store)
        self.probe = MagicMock()
        self.probe.settings = {'probe_username': 'alice'}
        self.transfer = self.engine()
        self.transfer.reconnect = MagicMock()

    def engine(self):
        return NodeTransfer(self.base, self.operations, self.probe, self.life)

    def protected(self):
        with self.store.connection() as db:
            return {table: [tuple(row) for row in db.execute('SELECT * FROM ' + table)]
                    for table in ['users', 'proxies', 'hosts', 'fleet_host_nodes', 'fleet_user_meta']}

    def data(self, node='xray:1'):
        with self.store.connection() as db:
            source = self.transfer.snapshot(node, db)
        return {**{key: source[key] for key in ['name', 'protocol', 'domain', 'vpn_port']},
                'move_node': node, '_source': source, 'address': '8.8.4.4', 'host': 'new.example',
                '_expected_memory': 1024, 'ssh_port': 22}

    def register(self, node='xray:1', job='a' * 32):
        data = self.data(node)
        self.transfer.update(job, 'running', 'Synthetic transfer', {'move_node': node})
        self.transfer.register_node(job, data, 'new-token' * 8)
        return data

    def test_legacy_vless_retains_id_subscriptions_and_user_metadata(self):
        before = self.protected()
        data = self.register()
        self.assertEqual(self.protected(), before)
        with self.store.connection() as db:
            self.assertEqual(tuple(db.execute('SELECT id,address,created_at FROM nodes WHERE id=1').fetchone()),
                             (1, '8.8.4.4', '2026-01-01'))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM nodes').fetchone()[0], 2)
        self.transfer.verify_node('a' * 32, data)
        self.probe.run.assert_called_once_with('a' * 32, data)
        self.transfer.accept_node('a' * 32, data)
        self.assertTrue(data['_transfer_accepted'])

    def test_failed_move_restores_registration_without_touching_users_or_other_nodes(self):
        before = self.protected()
        self.register()
        self.transfer.restore_node('a' * 32, {})
        self.assertEqual(self.protected(), before)
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT address FROM nodes WHERE id=1').fetchone()[0], '1.1.1.1')
            self.assertEqual(db.execute('SELECT address FROM nodes WHERE id=2').fetchone()[0], '9.9.9.9')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM fleet_managed').fetchone()[0], 0)
        self.transfer.restore_node('a' * 32, {})

    def test_source_change_before_switch_stops_transfer(self):
        data = self.data()
        with self.store.connection(write=True) as db:
            db.execute("UPDATE hosts SET port=8443 WHERE id=1")
        with self.assertRaises(ProvisionError):
            self.transfer.register_node('a' * 32, data, 'new-token' * 8)
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT address FROM nodes WHERE id=1').fetchone()[0], '1.1.1.1')

    def test_concurrent_edit_after_switch_is_not_overwritten_by_rollback(self):
        self.register()
        with self.store.connection(write=True) as db:
            db.execute("UPDATE nodes SET address='4.4.4.4' WHERE id=1")
        with self.assertRaises(ProvisionError):
            self.transfer.restore_node('a' * 32, {})
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT address FROM nodes WHERE id=1').fetchone()[0], '4.4.4.4')

    def test_interrupted_transfer_restores_persisted_snapshot_on_restart(self):
        self.register()
        restarted = self.engine()
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT address FROM nodes WHERE id=1').fetchone()[0], '1.1.1.1')
            self.assertEqual(db.execute('SELECT state FROM fleet_node_transfers').fetchone()[0], 'rolled_back')
        self.assertEqual(restarted.job('a' * 32)['state'], 'failed')

    def test_accepted_transfer_survives_restart_before_final_job_update(self):
        data = self.register()
        self.transfer.accept_node('a' * 32, data)
        restarted = self.engine()
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT address FROM nodes WHERE id=1').fetchone()[0], '8.8.4.4')
        self.assertEqual(restarted.job('a' * 32)['state'], 'succeeded')

    def test_managed_hy2_rotates_agent_token_but_preserves_links_and_identity(self):
        self.operations.ensure_node('hy2-original', 'Original Hy2', address='1.0.0.1')
        old_token = 'old-token' * 8
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_managed(id,protocol,token_hash,name,domain,port,active) VALUES('hy2-original','hysteria2',?,'Original Hy2','hy2.example',443,1)",
                       (hashlib.sha256(old_token.encode()).hexdigest(),))
        before = self.registry.links('test-uuid')
        data = self.register('hy2-original')
        self.assertEqual(self.registry.links('test-uuid'), before)
        self.assertFalse(self.registry.authorize('hy2-original', 'Bearer ' + old_token))
        self.assertTrue(self.registry.authorize('hy2-original', 'Bearer ' + 'new-token' * 8))
        self.transfer.verify_node('a' * 32, data)
        self.probe.run.assert_called_once_with('hy2-original', data)
        self.transfer.restore_node('a' * 32, {})
        self.assertTrue(self.registry.authorize('hy2-original', 'Bearer ' + old_token))

    def test_hy2_new_journal_and_rollback_preserve_charged_usage_and_history(self):
        from hy2bridge.quotas import NodeQuotas
        quotas = NodeQuotas(self.store)
        self.operations.ensure_node('hy2-original', 'Original Hy2', address='1.0.0.1')
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_managed(id,protocol,name,domain,port,active) VALUES('hy2-original','hysteria2','Hy2','hy2.example',443,1)")
        self.store.ingest('hy2-original', {'spool': 'original-spool-0001', 'seq': 1, 'totals': {'test-uuid': {'tx': 100, 'rx': 200}}})
        self.register('hy2-original')
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT used_traffic FROM users WHERE id=1').fetchone()[0], 300)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hy2_nodes').fetchone()[0], 0)
        self.store.ingest('hy2-original', {'spool': 'new-server-spool-0001', 'seq': 1, 'totals': {'test-uuid': {'tx': 10, 'rx': 20}}})
        self.transfer.restore_node('a' * 32, {})
        self.store.ingest('hy2-original', {'spool': 'original-spool-0001', 'seq': 2, 'totals': {'test-uuid': {'tx': 105, 'rx': 210}}})
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT used_traffic FROM users WHERE id=1').fetchone()[0], 345)
            self.assertEqual(db.execute('SELECT SUM(tx+rx) FROM hy2_hourly').fetchone()[0], 345)
            self.assertEqual(sum(quotas.totals(db, 'hy2-original')), 345)

    def test_hub_legacy_hy2_proxy_and_unmapped_profiles_are_rejected(self):
        for node in ['xray:local', 'unknown']:
            with self.assertRaises(ProvisionError):
                self.transfer.options_for(node)
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_proxy_services VALUES('proxy','xray:1',1)")
        with self.assertRaisesRegex(ProvisionError, 'HTTP/HTTPS'):
            self.transfer.options_for('xray:1')
        with self.store.connection(write=True) as db:
            db.execute('DELETE FROM fleet_proxy_services')
            db.execute("UPDATE hosts SET inbound_tag='OTHER' WHERE id=1")
        with self.assertRaisesRegex(ProvisionError, 'VLESS-шаблона'):
            self.transfer.options_for('xray:1')

    def test_readiness_requires_fresh_complete_metrics_from_new_instance(self):
        data = self.register()
        metrics = {'cpu_percent': 5, 'mem_total_bytes': 1024, 'mem_available_bytes': 512,
                   'disk_total_bytes': 10000, 'disk_free_bytes': 5000, 'net_rx_bytes': 0,
                   'net_tx_bytes': 0, 'online_connections': 0, 'service_healthy': True}
        with self.store.connection(write=True) as db:
            db.execute('INSERT INTO fleet_health VALUES(?,?,?)', ('xray:1', data['_cutover_at'] - 1, json.dumps(metrics)))
        self.assertFalse(self.transfer.node_ready('a' * 32, data))
        with self.store.connection(write=True) as db:
            db.execute('UPDATE fleet_health SET seen_at=?', (time.time(),))
        self.assertTrue(self.transfer.node_ready('a' * 32, data))
        data['_expected_memory'] = 2048
        self.assertFalse(self.transfer.node_ready('a' * 32, data))

    def test_preflight_keeps_shared_plan_map_for_the_deploy_endpoint(self):
        data = self.data()
        self.transfer.validate = MagicMock()
        self.transfer.connect = MagicMock()
        self.transfer.remote = MagicMock(return_value={'checks': [{'passed': True}], 'home': '/root'})
        with patch('hy2bridge.bootstrap.inspect', return_value={'python_available': True, 'bootstrap_required': False, 'docker_installed': True}), patch('threading.Timer'):
            plan = self.transfer.preflight(data)
        self.assertIs(self.transfer.plans, self.base.plans)
        self.assertIn(plan['id'], self.base.plans)

    def test_static_observer_config_cannot_replace_transferred_credential_on_restart(self):
        self.register()
        Observers(self.store, [{'node': 'xray:1', 'token': 'old-token' * 8, 'kind': 'native',
                              'domain': 'old.example', 'port': 443}])
        self.assertTrue(self.operations.observers.authorize('xray:1', 'Bearer ' + 'new-token' * 8))

    def test_retention_keeps_latest_deployment_and_trims_old_transfer_snapshots(self):
        self.operations.nodes = MagicMock(return_value=[])
        old = time.time() - 100 * 86400
        with self.store.connection(write=True) as db:
            for job, age in [('a' * 32, old), ('b' * 32, old + 1)]:
                db.execute("INSERT INTO fleet_jobs VALUES(?,'succeeded','Synthetic','[]',?,'{}')", (job, age))
                db.execute("INSERT INTO fleet_node_transfers VALUES(?,'xray:1','{}','{}','succeeded',?)", (job, age))
        self.operations.prune()
        with self.store.connection() as db:
            self.assertEqual([row['id'] for row in db.execute('SELECT id FROM fleet_node_transfers')], ['b' * 32])
            self.assertEqual([row['id'] for row in db.execute('SELECT id FROM fleet_jobs')], ['b' * 32])

    def worker(self, fail, concurrent_edit=False):
        data = self.data()
        self.transfer.validate = MagicMock()
        self.transfer.configuration = MagicMock(return_value={'action': 'install', 'id': 'a' * 32, 'publish': [], 'image': 'synthetic'})
        self.transfer.observer_configuration = MagicMock(return_value={'action': 'observer'})
        self.transfer.connect = MagicMock()
        self.transfer.remote = MagicMock(return_value={'running': True})
        def readiness(*_):
            if concurrent_edit:
                with self.store.connection(write=True) as db:
                    db.execute("UPDATE nodes SET address='4.4.4.4' WHERE id=1")
            if fail:
                raise ProvisionError('Synthetic payload failure')
            return True
        self.transfer.ready = readiness
        self.transfer.worker({'data': data, 'plan': {'id': 'a' * 32}, 'remote': {'mem_total_bytes': 1024}})
        return [call.args[1]['action'] for call in self.transfer.remote.call_args_list]

    def test_worker_failure_rolls_back_only_the_candidate_and_registration(self):
        before = self.protected()
        actions = self.worker(True)
        self.assertEqual(actions, ['install', 'observer', 'rollback'])
        self.assertEqual(self.protected(), before)
        self.assertEqual(self.transfer.job('a' * 32)['state'], 'rolled_back')

    def test_uncertain_registration_rollback_retains_candidate_for_reconciliation(self):
        actions = self.worker(True, concurrent_edit=True)
        self.assertEqual(actions, ['install', 'observer'])
        self.assertEqual(self.transfer.job('a' * 32)['state'], 'failed')
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT state FROM fleet_node_transfers').fetchone()[0], 'needs_reconcile')
        self.assertIsNotNone(self.life.plan('xray:1'))

    def test_job_confirmation_failure_cannot_remove_an_accepted_node(self):
        update = self.transfer.update
        failed = False
        def confirm(job, state, message, context=None):
            nonlocal failed
            if state == 'succeeded' and not failed:
                failed = True
                raise OSError('Synthetic job write failure')
            return update(job, state, message, context)
        self.transfer.update = confirm
        actions = self.worker(False)
        self.assertEqual(actions, ['install', 'observer'])
        self.assertEqual(self.transfer.job('a' * 32)['state'], 'succeeded')


if __name__ == '__main__':
    unittest.main()
