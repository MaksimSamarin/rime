"""Idempotent transport accounting that does not charge VPN user balances."""
import hashlib
import json
import time
from datetime import datetime, timezone


class UnknownRelayService(ValueError):
    """A transaction rejected because an entry service is no longer registered."""


class RelayAccounting:
    def __init__(self, store):
        self.store = store
        with store.connection(write=True) as database:
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_relay_receipts(
                entry TEXT NOT NULL,epoch TEXT NOT NULL,seq INTEGER NOT NULL,digest TEXT NOT NULL,
                seen_at REAL NOT NULL,PRIMARY KEY(entry,epoch))''')
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_relay_cursors(
                entry TEXT NOT NULL,service TEXT NOT NULL,epoch TEXT NOT NULL,
                rx INTEGER NOT NULL,tx INTEGER NOT NULL,seen_at REAL NOT NULL,PRIMARY KEY(entry,service,epoch))''')
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_relay_totals(
                service TEXT PRIMARY KEY,entry TEXT NOT NULL,rx INTEGER NOT NULL,tx INTEGER NOT NULL,
                resets INTEGER NOT NULL DEFAULT 0)''')
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_relay_hourly(
                entry TEXT NOT NULL,service TEXT NOT NULL,hour TEXT NOT NULL,rx INTEGER NOT NULL,tx INTEGER NOT NULL,
                PRIMARY KEY(entry,service,hour))''')

    def ingest(self, entry, packet):
        digest = hashlib.sha256(json.dumps(packet, sort_keys=True).encode()).hexdigest()
        spool, sequence = packet['spool'], packet['seq']
        observed = packet['observed_at']
        if not time.time() - 7 * 86400 <= observed <= time.time() + 300:
            raise ValueError('Relay observation timestamp is outside the accepted window')
        hour = datetime.fromtimestamp(observed, timezone.utc).strftime('%Y-%m-%d %H:00:00')
        with self.store.connection(write=True) as database:
            previous = database.execute('SELECT * FROM fleet_relay_receipts WHERE entry=? AND epoch=?', (entry, spool)).fetchone()
            if previous and sequence < previous['seq']:
                return {'received': True, 'duplicate': True}
            if previous and sequence == previous['seq'] and digest == previous['digest']:
                return {'received': True, 'duplicate': True}
            if previous and sequence <= previous['seq']:
                raise ValueError('Relay journal sequence conflicts with an accepted observation')
            for identity, values in packet['totals'].items():
                owner = database.execute('SELECT entry FROM fleet_tunnel_services WHERE id=?', (identity,)).fetchone()
                if owner is None or owner['entry'] != entry:
                    raise UnknownRelayService('Relay service does not belong to the authenticated entry')
                epoch = values.get('epoch', packet['epoch'])
                old = database.execute('SELECT * FROM fleet_relay_cursors WHERE entry=? AND service=? AND epoch=?', (entry, identity, epoch)).fetchone()
                rx, tx = values['rx'], values['tx']
                if type(rx) is not int or type(tx) is not int or not 0 <= min(rx, tx) <= max(rx, tx) <= 2**60:
                    raise ValueError('Invalid relay counters')
                another = database.execute('SELECT 1 FROM fleet_relay_cursors WHERE entry=? AND service=? AND epoch<>?', (entry, identity, epoch)).fetchone()
                reset = bool((old and (rx < old['rx'] or tx < old['tx'])) or (not old and another))
                delta_rx = rx if not old or rx < old['rx'] else rx - old['rx']
                delta_tx = tx if not old or tx < old['tx'] else tx - old['tx']
                database.execute('''INSERT INTO fleet_relay_totals(service,entry,rx,tx,resets) VALUES(?,?,?,?,?)
                    ON CONFLICT(service) DO UPDATE SET rx=rx+excluded.rx,tx=tx+excluded.tx,resets=resets+excluded.resets''',
                    (identity, entry, delta_rx, delta_tx, int(reset)))
                database.execute('INSERT OR REPLACE INTO fleet_relay_cursors VALUES(?,?,?,?,?,?)', (entry, identity, epoch, rx, tx, time.time()))
                database.execute('''INSERT INTO fleet_relay_hourly VALUES(?,?,?,?,?) ON CONFLICT(entry,service,hour)
                    DO UPDATE SET rx=rx+excluded.rx,tx=tx+excluded.tx''', (entry, identity, hour, delta_rx, delta_tx))
            database.execute('INSERT OR REPLACE INTO fleet_relay_receipts VALUES(?,?,?,?,?)', (entry, spool, sequence, digest, time.time()))
        return {'received': True, 'duplicate': False}

    def prune(self):
        with self.store.connection(write=True) as database:
            database.execute('DELETE FROM fleet_relay_receipts WHERE seen_at<?', (time.time() - 8 * 86400,))
            database.execute("DELETE FROM fleet_relay_hourly WHERE hour<strftime('%Y-%m-%d %H:00:00','now','-90 days')")
            database.execute('''DELETE FROM fleet_relay_cursors WHERE seen_at<? AND epoch NOT IN
                (SELECT newer.epoch FROM fleet_relay_cursors newer WHERE newer.service=fleet_relay_cursors.service
                 ORDER BY newer.seen_at DESC LIMIT 2)''', (time.time() - 90 * 86400,))
