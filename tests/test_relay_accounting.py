import tempfile
import time
from pathlib import Path
import unittest

from hy2bridge.store import Store
from hy2bridge.relay_accounting import RelayAccounting
from hy2bridge.relay_control import allocate_ports, forwarding_service


class RelayAccountingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        path = Path(self.temporary.name) / 'database.sqlite3'
        import sqlite3
        with sqlite3.connect(path) as database:
            database.execute('CREATE TABLE fleet_tunnel_services(id TEXT PRIMARY KEY,entry TEXT)')
            database.executemany('INSERT INTO fleet_tunnel_services VALUES(?,?)', [('service-a','entry'),('service-b','entry'),('other','other-entry')])
            database.execute('CREATE TABLE users(id INTEGER,used_traffic INTEGER)')
            database.execute('INSERT INTO users VALUES(1,12345)')
        self.store = Store(path)
        self.accounting = RelayAccounting(self.store)

    def packet(self, sequence, rx, tx, epoch='process-1', spool='sender-1', service='service-a'):
        return {'spool':spool,'epoch':epoch,'seq':sequence,'observed_at':time.time(),
                'totals':{service:{'rx':rx,'tx':tx}}}

    def totals(self, service='service-a'):
        with self.store.connection() as database:
            row = database.execute('SELECT rx,tx FROM fleet_relay_totals WHERE service=?',(service,)).fetchone()
            return tuple(row) if row else (0,0)

    def test_delivery_retry_and_late_old_sequence_do_not_charge_twice(self):
        first = self.packet(1,100,200)
        self.accounting.ingest('entry',first)
        self.accounting.ingest('entry',first)
        self.accounting.ingest('entry',self.packet(2,130,250))
        self.accounting.ingest('entry',first)
        self.assertEqual(self.totals(),(130,250))

    def test_observer_restart_with_the_same_forwarder_epoch_keeps_the_cursor(self):
        self.accounting.ingest('entry',self.packet(1,100,200))
        self.accounting.ingest('entry',self.packet(1,130,250,spool='sender-2'))
        self.assertEqual(self.totals(),(130,250))

    def test_forwarder_restart_and_delayed_previous_epoch_are_independent(self):
        self.accounting.ingest('entry',self.packet(1,100,200))
        self.accounting.ingest('entry',self.packet(2,20,30,epoch='process-2'))
        self.accounting.ingest('entry',self.packet(3,110,220,epoch='process-1'))
        self.assertEqual(self.totals(),(130,250))

    def test_one_counter_reset_does_not_charge_the_other_counter_again(self):
        self.accounting.ingest('entry',self.packet(1,100,200))
        self.accounting.ingest('entry',self.packet(2,10,220))
        self.assertEqual(self.totals(),(110,220))

    def test_transport_accounting_does_not_modify_vpn_user_consumption(self):
        self.accounting.ingest('entry',self.packet(1,100,200))
        with self.store.connection() as database:
            self.assertEqual(database.execute('SELECT used_traffic FROM users').fetchone()[0],12345)

    def test_one_entry_keeps_separate_counters_for_multiple_exits(self):
        self.accounting.ingest('entry',self.packet(1,100,200))
        self.accounting.ingest('entry',self.packet(2,40,50,service='service-b'))
        self.assertEqual(self.totals(),(100,200))
        self.assertEqual(self.totals('service-b'),(40,50))

    def test_entry_cannot_write_counters_for_another_entry(self):
        with self.assertRaises(ValueError):
            self.accounting.ingest('entry',self.packet(1,100,200,service='other'))
        self.assertEqual(self.totals('other'),(0,0))


class RelayPortTests(unittest.TestCase):
    def test_existing_tcp_proxy_and_udp_vpn_reservations_are_kept(self):
        services=[{'origin_port':443,'protocol':'tcp'},{'origin_port':443,'protocol':'udp'},
                  {'origin_port':3128,'protocol':'tcp'}]
        allocated=allocate_ports(services,{(443,'tcp'),(443,'udp'),(3128,'tcp')})
        self.assertTrue(all((value['public_port'],value['protocol']) not in {(443,'tcp'),(443,'udp'),(3128,'tcp')} for value in allocated))
        self.assertEqual(len({(v['public_port'],v['protocol']) for v in allocated}),3)

    def test_udp_forwarding_retains_datagrams_and_client_channels(self):
        config=forwarding_service('a'*32,10443,'192.0.2.1',443,'udp')
        self.assertTrue(config['listener']['metadata']['keepAlive'])
        self.assertEqual(config['listener']['metadata']['readBufferSize'],'65535')
        self.assertEqual(config['handler']['metadata']['bufferSize'],'65535')
