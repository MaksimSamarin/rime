"""Legacy Hy2 non-destructive metering, with durable delivery and explicit gaps."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import time
import urllib.parse
import urllib.request


class Meters:
    def __init__(self,store,entries=()):
        self.store=store
        with store.connection(write=True) as db:
            db.execute('CREATE TABLE IF NOT EXISTS fleet_meters(node TEXT PRIMARY KEY,token_hash TEXT NOT NULL,created_at REAL NOT NULL)')
            if 'created_at' not in {r['name'] for r in db.execute('PRAGMA table_info(fleet_meters)')}:
                db.execute('ALTER TABLE fleet_meters ADD COLUMN created_at REAL NOT NULL DEFAULT 0')
                db.execute('UPDATE fleet_meters SET created_at=? WHERE created_at=0',(time.time(),))
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_meter_state(node TEXT PRIMARY KEY,started_at REAL NOT NULL,
                seen_at REAL NOT NULL,source_at REAL NOT NULL,epoch TEXT NOT NULL,rate REAL,interval_seconds REAL NOT NULL)''')
            if 'counter_started_at' not in {r['name'] for r in db.execute('PRAGMA table_info(fleet_meter_state)')}:
                db.execute('ALTER TABLE fleet_meter_state ADD COLUMN counter_started_at REAL')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_meter_samples(node TEXT NOT NULL,spool TEXT NOT NULL,seq INTEGER NOT NULL,
                at REAL NOT NULL,bytes INTEGER NOT NULL,rate REAL,interval_seconds REAL NOT NULL,PRIMARY KEY(node,spool,seq))''')
            db.execute('CREATE INDEX IF NOT EXISTS fleet_meter_samples_time ON fleet_meter_samples(at)')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_meter_gaps(id INTEGER PRIMARY KEY,node TEXT NOT NULL,
                start_at REAL NOT NULL,end_at REAL NOT NULL,reason TEXT NOT NULL,loss_possible INTEGER NOT NULL)''')
            for entry in entries:
                if len(entry['token'])<32:raise ValueError('A separate meter credential is required')
                if not db.execute("SELECT 1 FROM fleet_inventory WHERE id=? AND protocol='hysteria2'",(entry['node'],)).fetchone():raise ValueError('Meter node must exist')
                db.execute('INSERT INTO fleet_meters VALUES(?,?,?) ON CONFLICT(node) DO UPDATE SET token_hash=excluded.token_hash',
                           (entry['node'],hashlib.sha256(entry['token'].encode()).hexdigest(),time.time()))

    def authorize(self,node,header):
        if not header.startswith('Bearer '):return False
        with self.store.connection() as db:row=db.execute('SELECT token_hash FROM fleet_meters WHERE node=?',(node,)).fetchone()
        return bool(row and hmac.compare_digest(row['token_hash'],hashlib.sha256(header[7:].encode()).hexdigest()))

    def ingest(self,node,batch,source_at,epoch,counter_started_at=None):
        now=time.time()
        if not now-3600<=source_at<=now+30:raise ValueError('Source sample time is outside the allowed range')
        if counter_started_at is not None and not 0<=counter_started_at<=source_at:raise ValueError('Invalid counter start time')
        def commit(db,added):
            if not db.execute('SELECT 1 FROM fleet_meters WHERE node=?',(node,)).fetchone():raise ValueError('Meter registration was removed')
            previous=db.execute('SELECT * FROM fleet_meter_state WHERE node=?',(node,)).fetchone()
            interval=max(0,source_at-previous['source_at']) if previous else 0
            changed=bool(previous and previous['epoch']!=epoch)
            rate=added/interval if previous and interval>0 and not changed else None
            if previous and (changed or interval>30):
                db.execute('INSERT INTO fleet_meter_gaps(node,start_at,end_at,reason,loss_possible) VALUES(?,?,?,?,?)',
                    (node,previous['source_at'],source_at,'core_restart' if changed else 'sample_delay',int(changed)))
            db.execute('''INSERT INTO fleet_meter_state VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(node) DO UPDATE SET
                seen_at=excluded.seen_at,source_at=excluded.source_at,epoch=excluded.epoch,rate=excluded.rate,interval_seconds=excluded.interval_seconds,counter_started_at=excluded.counter_started_at''',
                (node,now,now,source_at,epoch,rate,interval,counter_started_at))
            db.execute('INSERT INTO fleet_meter_samples VALUES(?,?,?,?,?,?,?)',(node,batch['spool'],batch['seq'],now,added,rate,interval))
            db.execute('DELETE FROM fleet_meter_samples WHERE at<?',(now-7*86400,))
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_events'").fetchone():
                db.execute("UPDATE fleet_events SET resolved_at=?,last_at=? WHERE node=? AND code='meter_unavailable' AND resolved_at IS NULL",(now,now,node))
        return self.store.ingest(node,batch,commit_hook=commit)

    def status(self,node,db=None):
        if db is None:
            with self.store.connection() as connection:return self.status(node,connection)
        if not db.execute('SELECT 1 FROM fleet_meters WHERE node=?',(node,)).fetchone():return None
        row=db.execute('SELECT * FROM fleet_meter_state WHERE node=?',(node,)).fetchone()
        if row is None:return {'state':'pending','history_started_at':None,'average_bytes_per_second':None}
        totals=db.execute('SELECT COALESCE(SUM(tx),0),COALESCE(SUM(rx),0) FROM hy2_totals WHERE node=?',(node,)).fetchone()
        gaps=db.execute('SELECT COUNT(*) FROM fleet_meter_gaps WHERE node=? AND loss_possible=1',(node,)).fetchone()[0]
        return {'state':'active' if time.time()-row['seen_at']<=30 else 'stale','history_started_at':row['started_at'],
                'last_received_at':row['seen_at'],'source_at':row['source_at'],'average_bytes_per_second':row['rate'],
                'counter_started_at':row['counter_started_at'],
                'interval_seconds':row['interval_seconds'],'upload_bytes':totals[0],'download_bytes':totals[1],
                'total_bytes':totals[0]+totals[1],'possible_loss_intervals':gaps,'counter_basis':'VPN payload; tx=user upload, rx=user download'}

    def check_health(self):
        now=time.time()
        with self.store.connection(write=True) as db:
            for row in db.execute('SELECT m.node,m.created_at,s.seen_at FROM fleet_meters m LEFT JOIN fleet_meter_state s ON s.node=m.node').fetchall():
                seen=row['seen_at'] or row['created_at']
                if now-seen<=30:continue
                old=db.execute("SELECT id FROM fleet_events WHERE node=? AND code='meter_unavailable' AND resolved_at IS NULL",(row['node'],)).fetchone()
                if old:db.execute('UPDATE fleet_events SET last_at=? WHERE id=?',(now,old['id']))
                else:db.execute("INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,'meter_unavailable','error',?,?)",(row['node'],seen+30,now))


class MeterAgent:
    def __init__(self,config):
        import fcntl
        try:from .spool import Spool
        except ImportError:from spool import Spool
        self.config=config;self.settings=config['meter']
        url=urllib.parse.urlsplit(self.settings['url'])
        if url.scheme!='https' or url.username or url.password or not url.path.startswith('/api/fleet/meters/'):
            raise ValueError('Meter delivery requires verified HTTPS')
        if len(self.settings['token'])<32:raise ValueError('Meter credential is too short')
        stats=urllib.parse.urlsplit(config['stats_url'])
        if stats.scheme not in ('http','https') or stats.hostname not in ('127.0.0.1','localhost','::1'):raise ValueError('Meter stats must be loopback')
        path=Path(self.settings['spool']);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.lock=path.with_suffix('.lock').open('a');fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.spool=Spool(path)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=self.settings.get('ca_file'))))

    def epoch(self):
        if self.settings.get('pid_file'):pid=int(Path(self.settings['pid_file']).read_text())
        else:
            service=self.settings.get('service','hysteria.service')
            if not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service',service):raise ValueError('Invalid VPN service name')
            pid=int(subprocess.check_output(['systemctl','show',service,'-p','MainPID','--value'],text=True,timeout=2))
        data=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
        if data[0]=='Z':raise ValueError('VPN process is not running')
        raw=Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+str(pid)+':'+data[19]
        boot=int(next(line.split()[1] for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime ')))
        return hashlib.sha256(raw.encode()).hexdigest(),boot+int(data[19])/os.sysconf('SC_CLK_TCK')

    def cycle(self):
        epoch,started=self.epoch();request=urllib.request.Request(self.config['stats_url'].rstrip('/')+'/traffic',headers={'Authorization':self.config['stats_secret']})
        with self.http.open(request,timeout=2) as response:
            raw=response.read(4*1024*1024+1)
            if len(raw)>4*1024*1024:raise ValueError('Traffic response too large')
            stats=json.loads(raw)
        if not isinstance(stats,dict) or len(stats)>10000:raise ValueError('Invalid traffic statistics')
        if self.epoch()[0]!=epoch:raise ValueError('VPN restarted during the sample')
        batch=self.spool.observe(epoch,stats)
        payload={**batch,'source_epoch':epoch,'source_at':time.time(),'counter_started_at':started}
        request=urllib.request.Request(self.settings['url'],data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+self.settings['token']})
        with self.http.open(request,timeout=5) as response:result=json.loads(response.read(4096))
        if result.get('accepted')!=batch['seq']:raise ValueError('Meter batch not acknowledged')
        return result
