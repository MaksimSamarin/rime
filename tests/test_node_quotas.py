import time
import unittest
from datetime import datetime,timezone
import test_accounting
from hy2bridge.operations import Operations
from hy2bridge import quotas


def ts(value):return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()


class NodeQuotaTests(unittest.TestCase):
    def setUp(self):
        test_accounting.AccountingTests.setUp(self)
        self.ops=Operations(self.store)
        with self.store.connection(write=True) as db:
            db.execute('CREATE TABLE node_usages(node_id INTEGER,created_at TEXT,uplink INTEGER,downlink INTEGER)')
        self.quota=quotas.NodeQuotas(self.store);quotas.current=self.quota

    def tearDown(self):
        quotas.current=None;test_accounting.AccountingTests.tearDown(self)

    def setting(self,limit=100,direction='total',action='stop',period='none',reset_at=None):
        return dict(limit_bytes=limit,direction=direction,action=action,period=period,reset_at=reset_at)

    def add(self,node,incoming,outgoing,hour=None):
        with self.store.connection(write=True) as db:
            db.execute('INSERT INTO fleet_node_traffic VALUES(?,?,?,?) ON CONFLICT(node,hour) DO UPDATE SET incoming=incoming+excluded.incoming,outgoing=outgoing+excluded.outgoing',
                       (node,hour or int(time.time())//3600*3600,incoming,outgoing))

    def test_hy2_duplicate_and_user_reset_do_not_reset_node_quota(self):
        self.quota.save('n1',self.setting(),'admin')
        batch=test_accounting.AccountingTests.batch(self,tx=80,rx=25)
        self.store.ingest('n1',batch);self.store.ingest('n1',batch)
        self.assertEqual(self.quota.state('n1')['used_bytes'],105)
        self.assertEqual(self.store.policy('n1')['allowed'],[])
        with self.store.connection(write=True) as db:db.execute('UPDATE users SET used_traffic=0')
        self.assertTrue(self.quota.blocked('n1'));self.assertEqual(self.store.policy('n2')['allowed'],['test-uuid'])
        self.quota.reset('n1','admin');self.assertFalse(self.quota.blocked('n1'))
        self.assertEqual(self.store.policy('n1')['allowed'],['test-uuid'])

    def test_raw_directions_not_user_coefficient_and_restart_safe(self):
        self.quota.save('xray:4',self.setting(direction='outgoing'),'admin')
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO node_usages VALUES(4,'2026-09-26 00:00:00',999,20)")
            db.execute('UPDATE node_usages SET downlink=90')
        self.assertEqual(self.quota.state('xray:4')['used_bytes'],90)
        self.assertFalse(self.quota.blocked('xray:4'))
        quotas.NodeQuotas(self.store)
        with self.store.connection(write=True) as db:db.execute('DELETE FROM node_usages')
        self.assertEqual(self.quota.state('xray:4')['used_bytes'],90)

    def test_warning_levels_deduplicate_and_warn_never_blocks(self):
        self.quota.save('n1',self.setting(action='warn'),'admin')
        for added,code in [(80,'node_quota_80'),(15,'node_quota_95'),(10,'node_quota_exceeded')]:
            self.add('n1',added,0);self.quota.sync();self.quota.sync()
            open_events=[e for e in self.ops.events() if e['resolved_at'] is None]
            self.assertEqual(len(open_events),1);self.assertEqual(open_events[0]['code'],code)
        self.assertFalse(self.quota.blocked('n1'))
        self.quota.reset('n1','admin');self.quota.sync()
        self.assertTrue(all(e['resolved_at'] is not None for e in self.ops.events()))

    def test_edit_limit_does_not_erase_used_traffic(self):
        self.quota.save('n1',self.setting(),'admin');self.add('n1',105,0)
        self.quota.save('n1',self.setting(limit=200),'admin')
        self.assertEqual(self.quota.state('n1')['used_bytes'],105)
        self.assertFalse(self.quota.blocked('n1'))

    def test_calendar_reset_uses_posting_hour_without_dropping_new_period_bytes(self):
        start=ts('2026-01-30T12:00:00');reset=ts('2026-01-31T00:00:00')
        self.quota.save('n1',self.setting(period='monthly',reset_at=reset),'admin',now=start)
        self.add('n1',80,0,ts('2026-01-30T13:00:00'))
        self.add('n1',21,4,ts('2026-01-31T00:00:00'))
        state=self.quota.state('n1',now=reset+3600)
        self.assertEqual(state['used_bytes'],25)
        self.assertEqual(state['next_reset'],ts('2026-02-28T00:00:00'))
        self.assertEqual(quotas.next_boundary(state['next_reset'],'monthly',31),ts('2026-03-31T00:00:00'))

    def test_blocked_native_config_keeps_api_and_original_subscription_config(self):
        self.quota.save('xray:local',self.setting(),'admin');self.add('xray:local',101,0)
        config={'api':{'tag':'API'},'routing':{'rules':[{'inboundTag':['API_INBOUND'],'outboundTag':'API'}]},
                'inbounds':[{'tag':'API_INBOUND'},{'tag':'vpn','protocol':'vless'}]}
        filtered=quotas.filter_config(config,'xray:local')
        self.assertEqual([i['tag'] for i in filtered['inbounds']],['API_INBOUND'])
        self.assertEqual(len(config['inbounds']),2)
        self.assertEqual(len(quotas.filter_config(config,'xray:other')['inbounds']),2)

    def test_remote_restore_preserves_selected_node_access(self):
        from hy2bridge import access
        access.current=access.Access(self.store)
        try:
            access.current.save(1,[],['xray:other'])
            self.quota.save('xray:4',self.setting(),'admin');self.add('xray:4',101,0)
            self.quota.reset('xray:4','admin')
            config={'inbounds':[{'tag':'vpn','settings':{'clients':[{'email':'1.alice'},{'email':'probe'}]}}]}
            restored=quotas.enforcement_config(config,'xray:4')
            self.assertEqual(restored['inbounds'][0]['settings']['clients'],[{'email':'probe'}])
            self.assertEqual(len(config['inbounds'][0]['settings']['clients']),2)
        finally:access.current=None
