"""Credentials for resource telemetry; never grant accounting or VPN control."""
import hashlib
import hmac
import re
import time


class Observers:
    def __init__(self, store, entries=None):
        self.store = store
        if entries is not None and (len({e['node'] for e in entries})!=len(entries) or len({e['token'] for e in entries})!=len(entries)):
            raise ValueError('Each resource observer requires a unique node and credential')
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_observers(
                node TEXT PRIMARY KEY,token_hash TEXT NOT NULL,kind TEXT NOT NULL,
                domain TEXT NOT NULL,port INTEGER NOT NULL)''')
            db.execute("CREATE TABLE IF NOT EXISTS fleet_observer_sources(node TEXT PRIMARY KEY,source TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO fleet_observer_sources SELECT node,'configuration' FROM fleet_observers")
            if entries is None:return
            for entry in entries:
                node=entry['node'];token=entry['token'];kind=entry['kind']
                if not re.fullmatch(r'[a-zA-Z0-9:_-]{1,64}',node) or len(token)<32:
                    raise ValueError('Invalid resource observer credential')
                if kind=='native':
                    if not re.fullmatch(r'xray:\d+',node) or not db.execute('SELECT 1 FROM nodes WHERE id=?',(int(node[5:]),)).fetchone():
                        raise ValueError('Observer must reference an existing native node')
                elif kind=='legacy_hy2':
                    if node.startswith('xray:') or db.execute('SELECT 1 FROM fleet_managed WHERE id=?',(node,)).fetchone():
                        raise ValueError('Observer conflicts with an existing managed node')
                    db.execute('''INSERT INTO fleet_inventory(id,name,protocol,address,created_at)
                        VALUES(?,?,'hysteria2',?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,address=excluded.address''',
                        (node,entry['name'],entry['address'],time.time()))
                else:raise ValueError('Unknown resource observer kind')
                port=entry['port']
                if not isinstance(port,int) or not 1<=port<=65535:raise ValueError('Invalid observer VPN port')
                db.execute('''INSERT INTO fleet_observers(node,token_hash,kind,domain,port) VALUES(?,?,?,?,?) ON CONFLICT(node) DO UPDATE
                    SET token_hash=excluded.token_hash,kind=excluded.kind,domain=excluded.domain,port=excluded.port''',
                    (node,hashlib.sha256(token.encode()).hexdigest(),kind,entry['domain'],port))
                db.execute("INSERT INTO fleet_observer_sources VALUES(?,'configuration') ON CONFLICT(node) DO UPDATE SET source='configuration'",(node,))
            allowed={entry['node'] for entry in entries}
            for row in db.execute("SELECT node FROM fleet_observer_sources WHERE source='configuration'").fetchall():
                if row['node'] not in allowed:
                    db.execute('DELETE FROM fleet_observers WHERE node=?',(row['node'],))
                    db.execute('DELETE FROM fleet_observer_sources WHERE node=?',(row['node'],))

    def authorize(self,node,header):
        if not header.startswith('Bearer '):return False
        with self.store.connection() as db:
            row=db.execute('SELECT token_hash FROM fleet_observers WHERE node=?',(node,)).fetchone()
        return bool(row and hmac.compare_digest(row['token_hash'],hashlib.sha256(header[7:].encode()).hexdigest()))

    def external(self,node):
        with self.store.connection() as db:
            row=db.execute('SELECT kind FROM fleet_observers WHERE node=?',(node,)).fetchone()
        return bool(row and row['kind']=='legacy_hy2')

    def register_native(self,node,token,domain,port):
        if not re.fullmatch(r'xray:\d+',node) or len(token)<32:raise ValueError('Invalid native observer')
        with self.store.connection(write=True) as db:
            if not db.execute('SELECT 1 FROM nodes WHERE id=?',(int(node[5:]),)).fetchone():raise ValueError('Native node missing')
            digest=hashlib.sha256(token.encode()).hexdigest()
            if db.execute('SELECT 1 FROM fleet_observers WHERE token_hash=? AND node<>?',(digest,node)).fetchone():raise ValueError('Observer credential is already assigned')
            db.execute("INSERT INTO fleet_observers(node,token_hash,kind,domain,port) VALUES(?,?,'native',?,?) ON CONFLICT(node) DO UPDATE SET token_hash=excluded.token_hash,domain=excluded.domain,port=excluded.port",
                (node,digest,domain,port))
            db.execute("INSERT INTO fleet_observer_sources VALUES(?,'provisioned') ON CONFLICT(node) DO UPDATE SET source='provisioned'",(node,))
