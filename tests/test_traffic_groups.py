from datetime import datetime,timedelta,timezone
import unittest
import test_accounting
from hy2bridge.access import Access
from hy2bridge.operations import Operations


class TrafficGroupsTests(unittest.TestCase):
    def setUp(self):
        test_accounting.AccountingTests.setUp(self)
        Operations(self.store)
    tearDown=test_accounting.AccountingTests.tearDown

    def report(self,group,**filters):
        now=datetime(2026,11,7,tzinfo=timezone.utc)
        return Operations(self.store).traffic(now-timedelta(days=1),now+timedelta(days=1),detail=False,group_by=group,**filters)

    def seed(self):
        Access(self.store).save(1,['krit','shared'],None)
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO hy2_hourly VALUES('hy','test-uuid',1,'alice','2026-11-07 00:00:00',100,200)")
            db.execute("INSERT INTO fleet_xray_hourly VALUES('xray:1',1,'2026-01-01 00:00:00','alice','2026-11-07 00:00:00',50)")
            # Same numeric id, obsolete credentials: must not inherit Alice's tags.
            db.execute("INSERT INTO hy2_hourly VALUES('old','obsolete',1,'old_alice','2026-11-07 01:00:00',10,0)")
            db.execute("INSERT INTO fleet_xray_hourly VALUES('old',1,'2025-01-01','old_alice','2026-11-07 01:00:00',20)")

    def test_tags_do_not_leak_between_account_incarnations_and_disclose_overlap(self):
        self.seed();report=self.report('tag')
        totals={g['label']:g['total'] for g in report['chart_groups']}
        self.assertEqual(totals,{'krit':350,'shared':350,'Без тега':30})
        self.assertEqual(report['total'],380)
        self.assertIn('несколькими тегами',report['chart_note'])
        filtered=self.report('tag',tag='krit')
        self.assertEqual(filtered['total'],350)
        self.assertEqual(len(filtered['chart_series']),1)

    def test_node_and_user_series_preserve_totals_and_unknown_hours(self):
        self.seed()
        for mode in ['node','user']:
            result=self.report(mode)
            self.assertEqual(sum(g['total'] for g in result['chart_groups']),result['total'])
            self.assertEqual(result['rows'],[])
            self.assertTrue(any(value is None for row in result['chart_series'] for key,value in row.items() if key!='hour'))

    def test_many_users_are_bounded_and_remainder_is_not_discarded(self):
        with self.store.connection(write=True) as db:
            for i in range(20):db.execute('INSERT INTO fleet_xray_hourly VALUES(?,?,?,?,?,?)',('n',i,'old','u'+str(i),'2026-11-07 00:00:00',i+1))
        result=self.report('user')
        self.assertEqual(result['chart_group_count'],20)
        self.assertEqual(len(result['chart_groups']),6)
        self.assertEqual(sum(g['total'] for g in result['chart_groups']),210)
        self.assertEqual(result['chart_groups'][-1]['label'],'Остальные')
        self.assertEqual(sum(v for k,v in result['chart_series'][0].items() if k!='hour'),210)

    def test_empty_and_invalid_grouping(self):
        self.assertEqual(self.report('user')['chart_groups'],[])
        self.assertEqual(self.report('user')['chart_series'],[])
        with self.assertRaises(ValueError):self.report('untrusted')
