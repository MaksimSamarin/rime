import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest


spec = importlib.util.spec_from_file_location('relay_observer', Path(__file__).parents[1]/'relay-runtime'/'observer.py')
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class RelayObserverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.journal = observer.Journal(Path(temporary.name)/'transport.sqlite3')

    def event(self, generation, rx, tx):
        return {'kind':'service','type':'stats','service':'rime-'+'a'*32+'-'+generation,
                'stats':{'inputBytes':tx,'outputBytes':rx}}

    def packets(self):
        with self.journal.connect() as database:
            return [json.loads(row[0]) for row in database.execute('SELECT body FROM pending ORDER BY seq')]

    def test_retired_and_current_generations_never_mix_their_counters(self):
        self.journal.observe([self.event('b'*8,100,200),self.event('c'*8,10,20)],'boot')
        self.journal.collect('boot',{'cpu_percent':5})
        packets = self.packets()
        totals = [packet['totals']['a'*32] for packet in packets if packet['totals']]
        self.assertEqual(totals,[{'epoch':'boot-'+'b'*8,'rx':100,'tx':200},
                                 {'epoch':'boot-'+'c'*8,'rx':10,'tx':20}])
        self.assertEqual(packets[-1]['health'],{'cpu_percent':5})

    def test_retried_and_late_statistics_preserve_monotonic_snapshots(self):
        self.journal.observe([self.event('b'*8,100,200)],'boot')
        self.journal.observe([self.event('b'*8,90,210)],'boot')
        self.journal.collect('boot',{})
        self.assertEqual(self.packets()[0]['totals']['a'*32],{'epoch':'boot-'+'b'*8,'rx':100,'tx':210})
        self.journal.collect('boot',{})
        self.assertEqual(len([packet for packet in self.packets() if packet['totals']]),1)

    def test_meter_restart_keeps_unreported_counters_and_process_generations(self):
        self.journal.observe([self.event('b'*8,100,200)],'old-boot')
        observer.Journal(self.journal.path).observe([self.event('b'*8,10,20)],'new-boot')
        self.journal.collect('new-boot',{})
        self.assertEqual(len([packet for packet in self.packets() if packet['totals']]),2)

    def test_many_services_share_one_packet_without_hiding_old_generations(self):
        events = []
        for number in range(100):
            event = self.event('b'*8,100,200)
            event['service'] = 'rime-'+format(number,'032x')+'-'+'b'*8
            events.append(event)
        self.journal.observe(events,'boot')
        self.journal.collect('boot',{})
        self.assertEqual(len(self.packets()),2)
        self.assertEqual(len(self.packets()[0]['totals']),100)

    def test_local_retired_cursors_and_delivery_backlog_expire(self):
        self.journal.observe([self.event('b'*8,100,200)],'boot')
        self.journal.collect('boot',{})
        with self.journal.connect() as database:
            database.execute('UPDATE observations SET seen_at=?',(time.time()-7*86400,))
            database.execute('UPDATE pending SET observed_at=?',(time.time()-7*86400,))
        self.journal.collect('boot',{})
        with self.journal.connect() as database:
            self.assertEqual(database.execute('SELECT count(*) FROM observations').fetchone()[0],0)
            self.assertEqual(database.execute('SELECT count(*) FROM pending').fetchone()[0],1)

    def test_invalid_counter_rolls_back_the_entire_observation(self):
        with self.assertRaises(ValueError):
            self.journal.observe([self.event('b'*8,100,200),self.event('c'*8,-1,20)],'boot')
        self.journal.collect('boot',{})
        self.assertEqual(self.packets()[0]['totals'],{})
