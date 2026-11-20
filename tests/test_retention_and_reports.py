from datetime import datetime, timedelta, timezone
import json
import time
import unittest
from unittest.mock import patch

import test_accounting
from hy2bridge.access import Access
from hy2bridge.meter import Meters
from hy2bridge.operations import Operations


class RetentionAndReportTests(unittest.TestCase):
    setUp = test_accounting.AccountingTests.setUp
    tearDown = test_accounting.AccountingTests.tearDown

    def test_stale_checks_expire_without_fabricating_a_payload_failure(self):
        ops = Operations(self.store)
        with self.store.connection(write=True) as db:
            db.executemany("INSERT INTO fleet_checks(id,node,state,requested_at,started_at) VALUES(?,?,?,?,?)", [
                ('requested', 'node', 'requested', 10, None),
                ('running', 'node', 'running', 20, 25),
                ('fresh', 'node', 'running', 90, 95),
            ])
        self.assertEqual(ops.expire_checks(now=100), 2)
        self.assertEqual(ops.expire_checks(now=100), 0)
        rows = {row['id']: row for row in ops.checks('node')}
        self.assertEqual(rows['requested']['completed_at'], 40)
        self.assertEqual(rows['running']['completed_at'], 50)
        self.assertEqual(rows['fresh']['state'], 'running')
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM fleet_events').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT used_traffic FROM users').fetchone()[0], 0)

    def test_job_retention_preserves_failed_running_and_every_managed_registration(self):
        ops = Operations(self.store)
        now = 200 * 86400
        with self.store.connection(write=True) as db:
            db.executescript('''CREATE TABLE fleet_jobs(id TEXT PRIMARY KEY,state TEXT,created_at REAL);
                                CREATE TABLE fleet_managed(id TEXT PRIMARY KEY,active INTEGER);''')
            db.executemany('INSERT INTO fleet_jobs VALUES(?,?,?)', [
                ('old-success', 'succeeded', 1), ('old-rollback', 'rolled_back', 1),
                ('failed', 'failed', 1), ('running', 'running', 1),
                ('active', 'succeeded', 1), ('partial', 'rolled_back', 1),
                ('recent-success', 'succeeded', now - 86400), ('recent-rollback', 'rolled_back', now - 86400),
            ])
            db.executemany('INSERT INTO fleet_managed VALUES(?,?)', [('active', 1), ('partial', 0)])
        ops.prune(now=now)
        with self.store.connection() as db:
            kept = {row['id'] for row in db.execute('SELECT id FROM fleet_jobs')}
        self.assertEqual(kept, {'failed', 'running', 'active', 'partial', 'recent-success', 'recent-rollback'})

    def test_diagnostic_caps_preserve_latest_rows_and_accounting(self):
        ops = Operations(self.store)
        now = 100000
        with self.store.connection(write=True) as db:
            db.executescript('''CREATE TABLE fleet_health_history(node TEXT,minute INTEGER,state TEXT,metrics TEXT);
                                CREATE TABLE fleet_meter_samples(node TEXT,at REAL);
                                CREATE TABLE fleet_meter_gaps(node TEXT,start_at REAL,end_at REAL,reason TEXT,loss_possible INTEGER);''')
            db.executemany("INSERT INTO fleet_health_history VALUES('node',?,'healthy','{}')", [(now - value,) for value in range(5)])
            db.executemany("INSERT INTO fleet_meter_samples VALUES('node',?)", [(now - value,) for value in range(5)])
            db.executemany("INSERT INTO fleet_meter_gaps VALUES('node',?,?,'sample_delay',0)", [(now - value - 1, now - value) for value in range(5)])
            db.execute('UPDATE users SET used_traffic=123')
        with patch('hy2bridge.operations.HEALTH_RETENTION_ROWS', 3), patch('hy2bridge.operations.METER_RETENTION_ROWS', 3), patch('hy2bridge.operations.GAP_RETENTION_ROWS', 3):
            ops.prune(now=now)
        with self.store.connection() as db:
            for table, column in [('fleet_health_history', 'minute'), ('fleet_meter_samples', 'at'), ('fleet_meter_gaps', 'end_at')]:
                self.assertEqual([row[0] for row in db.execute(f'SELECT {column} FROM {table} ORDER BY {column} DESC')], [now, now - 1, now - 2])
            self.assertEqual(db.execute('SELECT used_traffic FROM users').fetchone()[0], 123)
            self.assertEqual(db.execute("SELECT trimmed_before FROM fleet_retention_state WHERE table_name='fleet_meter_gaps'").fetchone()[0], now - 3)

    def test_completed_job_cap_preserves_referenced_and_failed_jobs(self):
        ops = Operations(self.store)
        with self.store.connection(write=True) as db:
            db.executescript('''CREATE TABLE fleet_jobs(id TEXT PRIMARY KEY,state TEXT,created_at REAL);
                                CREATE TABLE fleet_managed(id TEXT PRIMARY KEY,active INTEGER);''')
            db.executemany('INSERT INTO fleet_jobs VALUES(?,?,?)', [
                ('first', 'succeeded', 100), ('second', 'rolled_back', 200),
                ('third', 'succeeded', 300), ('managed', 'succeeded', 1), ('failed', 'failed', 1)])
            db.execute("INSERT INTO fleet_managed VALUES('managed',1)")
        with patch('hy2bridge.operations.COMPLETED_JOB_ROWS', 2):
            ops.prune(now=500)
        with self.store.connection() as db:
            self.assertEqual({row[0] for row in db.execute('SELECT id FROM fleet_jobs')},
                             {'second', 'third', 'managed', 'failed'})

    def test_report_rejects_unbounded_dates_and_discloses_pruned_gap_diagnostics(self):
        ops = Operations(self.store)
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(days=1)
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO hy2_samples VALUES('hy', ?, ?)",
                       (now.replace(tzinfo=None).isoformat(' '), time.time()))
            db.execute("INSERT INTO fleet_retention_state VALUES('fleet_meter_gaps', ?)", (start.timestamp() + 1,))
        self.assertFalse(ops.traffic(start, now + timedelta(hours=1), detail=False)['gap_history_complete'])
        self.assertTrue(ops.traffic(start, now + timedelta(hours=1), protocol='xray', detail=False)['gap_history_complete'])
        for begin, end in [(now, now), (now, start), (now - timedelta(days=367), now)]:
            with self.assertRaises(ValueError):
                ops.traffic(begin, end, detail=False)

    def test_recent_gap_is_retained_when_it_started_before_the_retention_window(self):
        ops = Operations(self.store)
        now = 200 * 86400
        with self.store.connection(write=True) as db:
            db.execute('CREATE TABLE fleet_meter_gaps(node TEXT,start_at REAL,end_at REAL,reason TEXT,loss_possible INTEGER)')
            db.executemany('INSERT INTO fleet_meter_gaps VALUES(?,?,?,?,?)', [
                ('node', 1, 2, 'sample_delay', 0), ('node', 1, now, 'sample_delay', 0)])
        ops.prune(now=now)
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT end_at FROM fleet_meter_gaps').fetchone()[0], now)

    def test_compact_matches_detail_for_filters_tags_deleted_names_and_zero_samples(self):
        ops = Operations(self.store)
        access = Access(self.store)
        access.save(1, ['group'], None)
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        hour = now.replace(tzinfo=None).isoformat(' ')
        old = (now - timedelta(hours=2)).replace(tzinfo=None).isoformat(' ')
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO hy2_hourly VALUES('hy', 'test-uuid', 1, 'alice', ?, 100, 200)", (hour,))
            db.execute("INSERT INTO hy2_hourly VALUES('hy', 'old-uuid', 99, '(deleted)', ?, 10, 20)", (old,))
            db.execute("INSERT INTO fleet_xray_hourly VALUES('xr', 1, '2026-01-01 00:00:00', 'alice', ?, 250)", (hour,))
            db.execute("INSERT INTO fleet_xray_hourly VALUES('xr', 99, '', NULL, ?, 70)", (old,))
            db.execute("INSERT INTO hy2_samples VALUES('hy', ?, ?)", ((now - timedelta(hours=1)).replace(tzinfo=None).isoformat(' '), time.time()))
        for filters in [{}, {'protocol': 'xray'}, {'protocol': 'hysteria2'}, {'node': 'hy'}, {'username': 'alice'}, {'tag': 'group'}]:
            with self.subTest(filters=filters):
                complete = ops.traffic(now - timedelta(days=1), now + timedelta(hours=1), **filters)
                compact = ops.traffic(now - timedelta(days=1), now + timedelta(hours=1), detail=False, **filters)
                for key in compact:
                    if key != 'rows':
                        self.assertEqual(compact[key], complete[key], key)
                self.assertEqual(compact['rows'], [])

    def test_large_compact_report_is_complete_and_detail_refuses_instead_of_truncating(self):
        ops = Operations(self.store)
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        with self.store.connection(write=True) as db:
            db.executemany('INSERT INTO fleet_xray_hourly VALUES(?,?,?,?,?,?)', [
                ('node-' + str(node), 1, '2026-01-01', 'alice',
                 (now - timedelta(hours=hour)).replace(tzinfo=None).isoformat(' '), node + 1)
                for node in range(100) for hour in range(600)])
        compact = ops.traffic(now - timedelta(days=30), now + timedelta(hours=1), detail=False)
        self.assertEqual(compact['row_count'], 60000)
        self.assertEqual(compact['total'], 600 * sum(range(1, 101)))
        self.assertEqual(len(compact['series']), 600)
        self.assertEqual(len(compact['nodes']), 100)
        self.assertEqual(compact['users'][0]['xray'], compact['total'])
        with self.assertRaises(ValueError):
            ops.traffic(now - timedelta(days=30), now + timedelta(hours=1))
        with self.store.connection() as db:
            plan = db.execute('EXPLAIN QUERY PLAN SELECT * FROM fleet_xray_hourly WHERE hour>=? AND hour<?',
                              ('2026-01-01', '2027-01-01')).fetchall()
            self.assertTrue(any('fleet_xray_time' in row['detail'] for row in plan))
