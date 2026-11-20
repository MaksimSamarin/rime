import json
import unittest
import test_accounting
from hy2bridge.history import read_history,CHART_FIELDS


class HistoryViewsTests(unittest.TestCase):
    setUp=test_accounting.AccountingTests.setUp
    tearDown=test_accounting.AccountingTests.tearDown

    def test_views_preserve_samples_states_gaps_and_exact_values(self):
        with self.store.connection(write=True) as db:
            db.execute('CREATE TABLE fleet_health_history(node TEXT,minute INTEGER,state TEXT,metrics TEXT)')
            metrics={'cpu_percent':0,'cpu_load1':.3,'mem_available_bytes':None,'mem_total_bytes':100,'disk_total_bytes':1000,'disk_free_bytes':300,'online_connections':7,'connection_details':{'groups':['unused']}}
            db.executemany('INSERT INTO fleet_health_history VALUES(?,?,?,?)',[
                ('a',60,'healthy',json.dumps(metrics)),('a',240,'offline','{}'),('b',180,'healthy','{}')])
        full=read_history(self.store,0,'a')
        timeline=read_history(self.store,0,'a','timeline')
        charts=read_history(self.store,0,'a','charts')
        self.assertEqual(timeline,[{k:r[k] for k in ('node','minute','state')} for r in full])
        self.assertEqual([r['minute'] for r in charts],[60,240])
        for original,compact in zip(full,charts):
            self.assertEqual(compact['metrics'],{k:original['metrics'].get(k) for k in CHART_FIELDS})
        self.assertEqual(len(read_history(self.store,0)),3)
        with self.assertRaises(ValueError):read_history(self.store,0,view='invalid')
