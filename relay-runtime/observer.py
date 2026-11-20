"""Bounded relay transport journal and host-resource observations."""
import argparse
import hmac
import hashlib
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import re
import shutil
import sqlite3
import ssl
import time
import threading
import urllib.request
import urllib.error
import uuid


class Resources:
    def __init__(self):
        self.previous = None

    def snapshot(self, directory):
        value = resources(directory)
        cpu = [int(number) for number in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
        sample = (sum(cpu), cpu[3] + cpu[4])
        if self.previous and sample[0] > self.previous[0]:
            value['cpu_percent'] = max(0,min(100,round(100 * (1-(sample[1]-self.previous[1])/(sample[0]-self.previous[0])),2)))
        self.previous = sample
        value['load_1m'] = float(Path('/proc/loadavg').read_text().split()[0])
        value['cpu_count'] = len([line for line in Path('/proc/stat').read_text().splitlines() if re.match(r'^cpu\d+ ',line)])
        listeners = set()
        for protocol in ['tcp','udp']:
            for suffix in ['', '6']:
                for line in Path('/proc/net/'+protocol+suffix).read_text().splitlines()[1:]:
                    fields = line.split()
                    if fields[3] in ['0A','07']:
                        listeners.add((int(fields[1].rsplit(':',1)[1],16),protocol))
        value['listeners'] = sorted(listeners)[:2048]
        return value


class Journal:
    def __init__(self, path):
        self.path = path
        with self.connect() as database:
            database.execute('CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT)')
            database.execute('CREATE TABLE IF NOT EXISTS pending(seq INTEGER PRIMARY KEY,observed_at REAL,body TEXT)')
            database.execute('CREATE TABLE IF NOT EXISTS quarantine(seq INTEGER PRIMARY KEY,observed_at REAL,body TEXT,status INTEGER,reason TEXT,quarantined_at REAL)')
            database.execute('''CREATE TABLE IF NOT EXISTS observations(service TEXT,epoch TEXT,
                rx INTEGER,tx INTEGER,seen_at REAL,dirty INTEGER,PRIMARY KEY(service,epoch))''')
            database.execute('INSERT OR IGNORE INTO metadata VALUES(?,?)', ('spool', uuid.uuid4().hex))
            database.execute("INSERT OR IGNORE INTO metadata VALUES('seq','0')")

    def connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def observe(self, events, epoch):
        now = time.time()
        with self.connect() as database:
            for event in events:
                identity = re.fullmatch(r'rime-([a-f0-9]{32})-([a-f0-9]{8})', event.get('service',''))
                if not identity or event.get('kind') != 'service' or event.get('type') != 'stats':
                    continue
                stats = event['stats']
                rx, tx = stats['outputBytes'], stats['inputBytes']
                if type(rx) is not int or type(tx) is not int or not 0 <= min(rx,tx) <= max(rx,tx) <= 2**60:
                    raise ValueError('Invalid forwarding counter')
                service, generation = identity.groups()
                # Monotonic reports can be retried or arrive after a hot replacement.
                # Every generation has its own durable cursor, including retired ones.
                database.execute('''INSERT INTO observations VALUES(?,?,?,?,?,1)
                    ON CONFLICT(service,epoch) DO UPDATE SET rx=max(rx,excluded.rx),tx=max(tx,excluded.tx),
                    seen_at=excluded.seen_at,dirty=1''',(service,epoch+'-'+generation,rx,tx,now))

    def collect(self, epoch, health):
        with self.connect() as database:
            groups = {}
            for service, generation, rx, tx, observed_at in database.execute(
                    'SELECT service,epoch,rx,tx,seen_at FROM observations WHERE dirty=1').fetchall():
                groups.setdefault(service,[]).append((observed_at,{'epoch':generation,'rx':rx,'tx':tx}))
            # Batch different services together. Only overlapping generations of
            # the same logical service require separate delivery packets.
            for offset in range(max((len(values) for values in groups.values()),default=0)):
                batch = {service:values[offset] for service,values in groups.items() if len(values)>offset}
                self.enqueue(database, {'epoch':epoch,'observed_at':max(value[0] for value in batch.values()),
                    'totals':{service:value[1] for service,value in batch.items()}})
            database.execute('UPDATE observations SET dirty=0 WHERE dirty=1')
            self.enqueue(database, {'epoch':epoch,'observed_at':time.time(),'totals':{},'health':health})
            database.execute('DELETE FROM observations WHERE seen_at<?',(time.time()-6*86400,))
            database.execute('DELETE FROM pending WHERE observed_at<?', (time.time() - 6 * 86400,))
            # Preserve the last counters of every process/service generation.
            # Coalesce only snapshots with the same counter identities and hour.
            old = database.execute('SELECT seq,observed_at,body FROM pending ORDER BY seq DESC LIMIT -1 OFFSET 2048').fetchall()
            latest = set()
            remove = []
            for sequence, observed_at, raw in old:
                value = json.loads(raw)
                signature = (int(observed_at/3600),value['epoch'],tuple(sorted(
                    (identity,counter['epoch']) for identity,counter in value['totals'].items())))
                if signature in latest:remove.append((sequence,))
                else:latest.add(signature)
            database.executemany('DELETE FROM pending WHERE seq=?',remove)
        if Path(self.path).stat().st_size > 64 * 1024**2:
            with self.connect() as database:
                database.execute('VACUUM')

    @staticmethod
    def enqueue(database, packet, spool=None, order=None):
        sequence = int(database.execute("SELECT value FROM metadata WHERE key='seq'").fetchone()[0]) + 1
        spool = spool or database.execute("SELECT value FROM metadata WHERE key='spool'").fetchone()[0]
        if 'health' in packet:
            # Resource snapshots are replaceable. Give health its own receipt
            # stream so prioritizing it never skips older traffic counters.
            database.execute("DELETE FROM pending WHERE json_type(body,'$.health') IS NOT NULL")
            spool+='-health'
        packet.update(seq=sequence, spool=spool)
        if order is not None:packet['_delivery_order']=order
        database.execute('INSERT INTO pending VALUES(?,?,?)', (sequence, packet['observed_at'], json.dumps(packet)))
        database.execute("UPDATE metadata SET value=? WHERE key='seq'", (str(sequence),))

    def first(self):
        with self.connect() as database:
            return database.execute("""SELECT seq,body FROM pending ORDER BY
                CASE WHEN json_type(body,'$.health') IS NOT NULL THEN 0 ELSE 1 END,
                COALESCE(json_extract(body,'$._delivery_order'),seq),seq LIMIT 1""").fetchone()

    def acknowledge(self, sequence):
        with self.connect() as database:
            database.execute('DELETE FROM pending WHERE seq=?', (sequence,))

    def quarantine(self, sequence, status, reason):
        with self.connect() as database:
            row=database.execute('SELECT body FROM pending WHERE seq=?',(sequence,)).fetchone()
            database.execute('''INSERT OR REPLACE INTO quarantine
                SELECT seq,observed_at,body,?,?,? FROM pending WHERE seq=?''',
                (int(status),str(reason)[:128],time.time(),sequence))
            database.execute('DELETE FROM pending WHERE seq=?',(sequence,))
            if row:
                packet=json.loads(row[0])
                if status==409 and reason=='unknown_service' and len(packet.get('totals',{}))>1:
                    # One unknown service must not poison every other service
                    # in a batch after the panel restores an older database.
                    # Fragments stay before later snapshots. Their separate
                    # receipt stream cannot make the panel skip later packets
                    # from the original stream despite a newer delivery seq.
                    spool=hashlib.sha256((packet['spool']+':fragment:'+str(packet['seq'])).encode()).hexdigest()
                    for service,counter in packet['totals'].items():
                        self.enqueue(database,{'epoch':packet['epoch'],'observed_at':packet['observed_at'],
                                               'totals':{service:counter}},spool=spool,
                                     order=packet.get('_delivery_order',packet['seq']))
            database.execute('DELETE FROM quarantine WHERE quarantined_at<?',(time.time()-6*86400,))
            database.execute('DELETE FROM quarantine WHERE seq IN (SELECT seq FROM quarantine ORDER BY quarantined_at DESC LIMIT -1 OFFSET 256)')

    def quarantine_count(self):
        with self.connect() as database:
            return database.execute('SELECT count(*) FROM quarantine').fetchone()[0]


def deliver(journal, opener, config, limit=16):
    """Quarantine permanent per-packet rejection; preserve retryable failures."""
    for _ in range(limit):
        row=journal.first()
        if row is None:break
        packet=json.loads(row[1])
        packet.pop('_delivery_order',None)
        request=urllib.request.Request(config['panel_url'].rstrip('/')+'/api/fleet/relays/'+config['id']+'/telemetry',
            data=json.dumps(packet).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+config['token']})
        try:
            with opener.open(request,timeout=8) as response:
                accepted=json.loads(response.read(4096))
        except urllib.error.HTTPError as error:
            if error.code in (400,409,422):
                reason='permanent_packet_rejection'
                try:
                    raw=error.read(4097)
                    detail=json.loads(raw).get('detail') if len(raw)<=4096 else None
                    if error.code==409 and isinstance(detail,dict) and detail.get('code')=='relay_service_unregistered':
                        reason='unknown_service'
                except (OSError,ValueError,AttributeError,TypeError):pass
                journal.quarantine(row[0],error.code,reason)
                continue
            raise
        if accepted.get('received') is not True:break
        journal.acknowledge(row[0])


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        expected='Bearer '+self.server.observer_token
        authorization=self.headers.get('Authorization','')
        if not authorization.isascii() or not hmac.compare_digest(authorization,expected):
            self.send_error(401)
            return
        try:
            length=int(self.headers.get('Content-Length','0'))
            if self.path!='/observe' or not 0<length<=65536:
                raise ValueError('Invalid observation request')
            self.connection.settimeout(3)
            value=json.loads(self.rfile.read(length))
            if not isinstance(value.get('events'),list) or len(value['events'])>128:
                raise ValueError('Invalid observation events')
            boot=json.loads((self.server.directory/'boot.json').read_text())['epoch']
            self.server.journal.observe(value['events'],boot)
            self.send_response(200);self.end_headers();self.wfile.write(b'{"ok":true}')
        except (OSError,ValueError,KeyError,TypeError):self.send_error(400)

    def log_message(self,*_):pass


def make_receiver(config, journal):
    token=config.get('observer_token')
    if not isinstance(token,str) or not 24<=len(token)<=128 or not token.isascii():
        raise ValueError('A separate local observer token is required')
    receiver=HTTPServer(('127.0.0.1',config['metrics_port']),Receiver)
    receiver.observer_token=token
    receiver.directory=Path(config['directory'])
    receiver.journal=journal
    return receiver


def resources(directory):
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        values[key] = int(value.strip().split()[0]) * 1024
    disk = shutil.disk_usage(directory)
    return {'mem_total_bytes': values['MemTotal'], 'mem_available_bytes': values.get('MemAvailable', values['MemFree']),
            'disk_total_bytes': disk.total, 'disk_free_bytes': disk.free}


def run(config):
    directory = Path(config['directory'])
    journal = Journal(directory / 'transport.sqlite3')
    receiver = make_receiver(config,journal)
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    context = ssl.create_default_context()
    if config.get('panel_ca_file'):
        context.load_verify_locations(cafile=config['panel_ca_file'])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    host = Resources()
    while True:
        try:
            boot = json.loads((directory / 'boot.json').read_text())['epoch']
            health=host.snapshot(directory)
            health['quarantined_packets']=journal.quarantine_count()
            journal.collect(boot, health)
            deliver(journal,opener,config)
        except (OSError, ValueError):
            pass
        time.sleep(15)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    run(json.loads(Path(parser.parse_args().config).read_text()))
