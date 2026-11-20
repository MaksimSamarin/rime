"""Cumulative native counters survive lost replies, retries and DB rollback."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import tempfile
import threading
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from sqlalchemy import (BigInteger, Column, DateTime, Integer, MetaData, String,
                        Table, UniqueConstraint, create_engine, delete, insert, select, update)
from sqlalchemy.orm import sessionmaker


class API:
    def __init__(self, lock=None):
        self.control_lock = lock or threading.RLock()
        self.epoch = 'core-one'
        self.usage_epoch = lambda:self.epoch
        self.users = [('1.alice','uplink',100),('1.alice','downlink',20)]
        self.outbound = [('DIRECT','uplink',70),('DIRECT','downlink',30)]
        self.fail_reply = False
        self.requests = []

    def query(self, kind, values, reset):
        self.requests.append((kind,reset))
        if self.fail_reply:
            self.fail_reply = False
            raise TimeoutError('Synthetic reply loss after a non-destructive server read')
        return [SimpleNamespace(type='user' if kind=='users' else 'outbound',
                                name=name,link=direction,value=value) for name,direction,value in values]

    def get_users_stats(self, reset, timeout):
        return self.query('users',self.users,reset)

    def get_outbounds_stats(self, reset, timeout):
        return self.query('outbound',self.outbound,reset)


class NativeUsageCursorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.engine = create_engine('sqlite:///'+str(Path(temporary.name)/'usage.sqlite3'),
                                    connect_args={'check_same_thread':False})
        self.addCleanup(self.engine.dispose)
        md = MetaData()
        definitions = {
            'User':Table('users',md,Column('id',Integer,primary_key=True),Column('username',String(34)),
                Column('admin_id',Integer),Column('used_traffic',BigInteger),Column('online_at',DateTime)),
            'Admin':Table('admins',md,Column('id',Integer,primary_key=True),Column('users_usage',BigInteger)),
            'Node':Table('nodes',md,Column('id',Integer,primary_key=True)),
            'System':Table('system',md,Column('id',Integer,primary_key=True),
                Column('uplink',BigInteger),Column('downlink',BigInteger)),
            'NodeUserUsage':Table('node_user_usages',md,Column('id',Integer,primary_key=True),
                Column('node_id',Integer),Column('user_id',Integer),Column('created_at',DateTime),
                Column('used_traffic',BigInteger),UniqueConstraint('node_id','user_id','created_at')),
            'NodeUsage':Table('node_usages',md,Column('id',Integer,primary_key=True),Column('node_id',Integer),
                Column('created_at',DateTime),Column('uplink',BigInteger),Column('downlink',BigInteger),
                UniqueConstraint('node_id','created_at'))}
        self.tables = definitions
        md.create_all(self.engine)
        with self.engine.begin() as db:
            db.execute(insert(definitions['User']).values(id=1,username='alice',admin_id=1,used_traffic=0))
            db.execute(insert(definitions['Admin']),[{'id':1,'users_usage':0},{'id':2,'users_usage':0}])
            db.execute(insert(definitions['Node']).values(id=5))
            db.execute(insert(definitions['System']).values(id=1,uplink=0,downlink=0))
        sessions = sessionmaker(bind=self.engine)

        class GetDB:
            def __enter__(self):
                self.db = sessions()
                return self.db

            def __exit__(self, *_):
                self.db.close()

        database = ModuleType('app.db')
        database.GetDB = GetDB
        models = ModuleType('app.db.models')
        for name,table in definitions.items():
            setattr(models,name,SimpleNamespace(__table__=table))
        spec = importlib.util.spec_from_file_location('native_usage_fixture',
            Path(__file__).resolve().parents[1]/'app/utils/native_usage.py')
        self.module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules,{'app':ModuleType('app'),'app.db':database,'app.db.models':models}):
            spec.loader.exec_module(self.module)
        self.api = API()

    def row(self, name):
        with self.engine.connect() as db:
            return db.execute(select(self.tables[name])).mappings().first()

    def count(self, table):
        with self.engine.connect() as db:
            return len(db.execute(select(table)).all())

    def collect(self, kind='users', **kwargs):
        return self.module.record_native_usage(self.api,5,kind,**kwargs)

    def test_lost_reply_then_retry_charges_exact_bytes_once(self):
        self.api.fail_reply = True
        with self.assertRaises(TimeoutError):
            self.collect()
        self.assertEqual(self.row('User')['used_traffic'],0)
        self.collect()
        self.collect()
        self.assertEqual(self.row('User')['used_traffic'],120)
        self.assertEqual(self.row('Admin')['users_usage'],120)
        self.assertEqual(self.row('NodeUserUsage')['used_traffic'],120)
        self.assertTrue(all(reset is False for _,reset in self.api.requests))

    def test_cursor_and_all_charges_roll_back_before_retry(self):
        with patch.object(self.module,'_prune',side_effect=RuntimeError('Synthetic transaction failure')):
            with self.assertRaises(RuntimeError):
                self.collect()
        self.assertEqual(self.row('User')['used_traffic'],0)
        self.assertEqual(self.row('Admin')['users_usage'],0)
        self.assertEqual(self.count(self.module.cursors),0)
        self.assertIsNone(self.row('NodeUserUsage'))
        self.collect()
        self.assertEqual(self.row('User')['used_traffic'],120)
        self.assertEqual(self.count(self.module.cursors),2)

    def test_new_epoch_and_one_counter_decrease_are_independent(self):
        self.collect()
        self.api.epoch = 'core-two'
        self.api.users = [('1.alice','uplink',7),('1.alice','downlink',3)]
        self.collect()
        self.api.users = [('1.alice','uplink',2),('1.alice','downlink',4)]
        self.collect()
        self.collect()
        self.assertEqual(self.row('User')['used_traffic'],133)

    def test_user_coefficient_carries_fraction_and_changes_only_future_delta(self):
        self.api.users = [('1.alice','uplink',1),('1.alice','downlink',1)]
        self.collect(coefficient=.5)
        self.assertEqual(self.row('User')['used_traffic'],1)
        self.api.users[0] = ('1.alice','uplink',2)
        self.collect(coefficient=.5)
        self.collect(coefficient=.5)
        self.api.users[0] = ('1.alice','uplink',3)
        self.collect(coefficient=.5)
        self.assertEqual(self.row('User')['used_traffic'],2)
        self.api.users[0] = ('1.alice','uplink',4)
        self.collect(coefficient=3)
        self.assertEqual(self.row('User')['used_traffic'],5)
        self.assertEqual(self.row('NodeUserUsage')['used_traffic'],5)

    def test_zero_coefficient_advances_cursors_without_rebilling_free_bytes(self):
        self.collect(coefficient=0)
        self.collect('outbound',coefficient=0)
        self.assertEqual(self.row('User')['used_traffic'],0)
        self.assertIsNotNone(self.row('User')['online_at'])
        self.assertEqual(self.row('NodeUserUsage')['used_traffic'],0)
        self.assertEqual(self.row('System')['uplink'],70)
        self.api.users[0] = ('1.alice','uplink',101)
        self.collect(coefficient=1)
        self.collect(coefficient=1)
        self.assertEqual(self.row('User')['used_traffic'],1)

    def test_fractional_delta_preserves_confirmed_zero_history_but_idle_does_not(self):
        self.api.users = [('1.alice','uplink',0)]
        self.collect(coefficient=.5)
        self.assertIsNone(self.row('NodeUserUsage'))
        self.assertIsNone(self.row('User')['online_at'])
        self.api.users = [('1.alice','uplink',1)]
        self.collect(coefficient=.5)
        self.assertEqual(self.row('NodeUserUsage')['used_traffic'],0)
        self.assertIsNotNone(self.row('User')['online_at'])
        with self.engine.begin() as db:
            db.execute(delete(self.tables['NodeUserUsage']))
        self.collect(coefficient=.5)
        self.assertIsNone(self.row('NodeUserUsage'))
        self.api.users = [('1.alice','uplink',2)]
        self.collect(coefficient=.5)
        self.assertEqual(self.row('NodeUserUsage')['used_traffic'],1)
        self.assertEqual(self.row('User')['used_traffic'],1)

    def test_reused_numeric_user_id_does_not_charge_a_different_username(self):
        self.collect()
        with self.engine.begin() as db:
            db.execute(delete(self.tables['User']).where(self.tables['User'].c.id==1))
            db.execute(delete(self.tables['NodeUserUsage']))
            db.execute(insert(self.tables['User']).values(id=1,username='bob',admin_id=2,used_traffic=0))
        self.api.users = [('1.alice','uplink',200),('1.bob','uplink',9)]
        self.collect()
        self.assertEqual(self.row('User')['used_traffic'],9)
        with self.engine.connect() as db:
            amounts = dict(db.execute(select(self.tables['Admin'].c.id,self.tables['Admin'].c.users_usage)).all())
        self.assertEqual(amounts,{1:120,2:9})

    def test_parallel_collectors_with_stable_physical_lock_do_not_charge_twice(self):
        other = API(lock=self.api.control_lock)
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda api:self.module.record_native_usage(api,5,'users'),[self.api,other]))
        self.assertEqual(sum(value['charged'] for value in results),120)
        self.assertEqual(self.row('User')['used_traffic'],120)

    def test_epoch_change_during_fetch_discards_unstable_snapshot(self):
        epochs = iter(['core-one','core-two'])
        self.api.usage_epoch = lambda:next(epochs)
        with self.assertRaises(ValueError):
            self.collect()
        self.assertEqual(self.row('User')['used_traffic'],0)
        self.api.usage_epoch = lambda:'core-two'
        self.collect()
        self.assertEqual(self.row('User')['used_traffic'],120)

    def test_outbound_cursors_system_and_hourly_records_commit_together(self):
        self.collect('outbound')
        self.collect('outbound')
        self.assertEqual((self.row('System')['uplink'],self.row('System')['downlink']),(70,30))
        self.assertEqual((self.row('NodeUsage')['uplink'],self.row('NodeUsage')['downlink']),(70,30))
        self.api.outbound[0] = ('DIRECT','uplink',10)
        self.collect('outbound')
        self.assertEqual(self.row('System')['uplink'],80)

    def test_disabled_hourly_history_keeps_balances_and_cursors(self):
        self.collect(history=False)
        self.collect('outbound',history=False)
        self.assertEqual(self.row('User')['used_traffic'],120)
        self.assertEqual(self.row('System')['uplink'],70)
        self.assertIsNone(self.row('NodeUserUsage'))
        self.assertIsNone(self.row('NodeUsage'))

    def test_stale_old_epoch_cursors_and_removed_user_fractions_are_pruned(self):
        self.api.users = [('1.alice','uplink',1)]
        self.collect(coefficient=.5)
        old = datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(days=91)
        with self.engine.begin() as db:
            db.execute(update(self.module.cursors).values(seen_at=old))
            db.execute(update(self.module.remainders).values(seen_at=old))
            db.execute(delete(self.tables['User']))
        self.api.epoch = 'core-two'
        self.api.users = []
        self.collect()
        self.assertEqual(self.count(self.module.cursors),0)
        self.assertEqual(self.count(self.module.remainders),0)

    def test_missing_epoch_keeps_legacy_detection_false(self):
        self.assertFalse(self.module.uses_cumulative_usage(SimpleNamespace()))
        self.assertFalse(self.module.uses_cumulative_usage(SimpleNamespace(usage_epoch='')))
        self.assertTrue(self.module.uses_cumulative_usage(self.api))

    def test_removed_node_cursors_and_fraction_rows_are_pruned(self):
        self.api.users = [('1.alice','uplink',1)]
        self.collect(coefficient=.5)
        with self.engine.begin() as db:
            db.execute(delete(self.tables['Node']).where(self.tables['Node'].c.id==5))
            db.execute(insert(self.tables['Node']).values(id=6))
        self.module.record_native_usage(self.api,6,'users',coefficient=.5)
        with self.engine.connect() as db:
            cursor_nodes = set(db.execute(select(self.module.cursors.c.node_id)).scalars())
            remainder_nodes = set(db.execute(select(self.module.remainders.c.node_id)).scalars())
        self.assertEqual(cursor_nodes,{6})
        self.assertEqual(remainder_nodes,{6})


if __name__=='__main__':
    unittest.main()
