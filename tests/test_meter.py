from unittest.mock import patch
import unittest
from datetime import datetime,timedelta,timezone
import test_accounting
from test_accounting import connect
from hy2bridge.meter import Meters
from hy2bridge.operations import Operations


class MeterTests(unittest.TestCase):
    tearDown=test_accounting.AccountingTests.tearDown
    def setUp(self):
        test_accounting.AccountingTests.setUp(self)
        self.ops=Operations(self.store);self.ops.ensure_node('legacy')
        with patch('hy2bridge.meter.time.time',return_value=1000):
            self.meter=Meters(self.store,[{'node':'legacy','token':'meter-only-token-'+'a'*32}])
        self.ops.meters=self.meter

    def batch(self,seq=1,tx=100,rx=200):return test_accounting.AccountingTests.batch(self,seq,tx,rx)
    def send(self,at,batch,epoch='a'*64):
        with patch('hy2bridge.meter.time.time',return_value=at):return self.meter.ingest('legacy',batch,at,epoch)

    def test_atomic_counters_retry_interval_rate_and_restart_gap(self):
        batch=self.batch();self.assertEqual(self.send(1000,batch)['added'],300)
        self.assertTrue(self.send(1001,batch)['duplicate'])
        self.assertEqual(self.send(1010,self.batch(2,150,350))['added'],200)
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT used_traffic FROM users').fetchone()[0],500)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM fleet_meter_samples').fetchone()[0],2)
            self.assertEqual(db.execute('SELECT rate FROM fleet_meter_state').fetchone()[0],20)
        self.send(1020,self.batch(3,160,360),'b'*64)
        with self.store.connection() as db:
            self.assertIsNone(db.execute('SELECT rate FROM fleet_meter_state').fetchone()[0])
            self.assertEqual(db.execute('SELECT loss_possible FROM fleet_meter_gaps').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT used_traffic FROM users').fetchone()[0],520)
        self.send(1070,self.batch(4,180,400),'b'*64)
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT loss_possible FROM fleet_meter_gaps WHERE reason='sample_delay'").fetchone()[0],0)

    def test_revocation_race_rolls_back_usage_with_metadata(self):
        self.send(1000,self.batch())
        with self.store.connection(write=True) as db:db.execute('DELETE FROM fleet_meters')
        with self.assertRaises(ValueError):self.send(1010,self.batch(2,200,400))
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT used_traffic FROM users').fetchone()[0],300)
            self.assertEqual(db.execute('SELECT seq FROM hy2_nodes').fetchone()[0],1)

    def test_separate_credentials_and_stale_meter_event_recovery(self):
        self.assertTrue(self.meter.authorize('legacy','Bearer '+'meter-only-token-'+'a'*32))
        self.assertFalse(self.meter.authorize('other','Bearer '+'meter-only-token-'+'a'*32))
        with patch('hy2bridge.meter.time.time',return_value=1040):self.meter.check_health()
        with self.store.connection() as db:self.assertIsNone(db.execute("SELECT resolved_at FROM fleet_events WHERE code='meter_unavailable'").fetchone()[0])
        self.send(1041,self.batch())
        with self.store.connection() as db:self.assertIsNotNone(db.execute("SELECT resolved_at FROM fleet_events WHERE code='meter_unavailable'").fetchone()[0])

    def test_unknown_history_is_not_zero_but_confirmed_idle_is_zero(self):
        now=datetime.now(timezone.utc)
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_xray_hourly VALUES('xray:local',1,'2026-01-01','alice',?,100)",((now-timedelta(hours=2)).replace(minute=0,second=0,microsecond=0,tzinfo=None).isoformat(' '),))
        empty=self.ops.traffic(now-timedelta(days=1),now+timedelta(hours=1))
        self.assertIsNone(empty['series'][0]['hysteria2'])
        self.store.ingest('legacy',self.batch(tx=0,rx=0))
        measured=self.ops.traffic(now-timedelta(days=1),now+timedelta(hours=1))
        self.assertIsNone(measured['series'][0]['hysteria2'])
        self.assertEqual(measured['series'][-1]['hysteria2'],0)
