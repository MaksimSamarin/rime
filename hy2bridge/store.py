"""Atomic cumulative accounting in the same SQLite transaction as Marzban usage.

Never writes subscription tokens, UUIDs, expiration or user status. Marzban's own
review job remains responsible for its status transitions and Xray operations.
"""
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


class Conflict(ValueError):
    pass


class Store:
    def __init__(self, path):
        self.path = str(Path(path).resolve())

    @contextmanager
    def connection(self, write=False):
        db = sqlite3.connect('file:' + Path(self.path).as_posix() + '?mode=rw', uri=True, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            if write:
                db.execute('BEGIN IMMEDIATE')
            yield db
            if write:
                db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def initialize(self):
        with self.connection(write=True) as db:
            cols = {r['name'] for r in db.execute('PRAGMA table_info(users)')}
            if not {'id','username','status','used_traffic','data_limit','expire','admin_id','online_at','created_at'} <= cols:
                raise RuntimeError('Unsupported Marzban schema')
            for sql in (
                '''CREATE TABLE IF NOT EXISTS hy2_nodes (
                   node TEXT PRIMARY KEY, spool TEXT NOT NULL, seq INTEGER NOT NULL,
                   digest TEXT NOT NULL, seen_at REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS hy2_totals (
                   node TEXT NOT NULL, auth TEXT NOT NULL, tx INTEGER NOT NULL, rx INTEGER NOT NULL,
                   PRIMARY KEY(node,auth))''',
                '''CREATE TABLE IF NOT EXISTS hy2_hourly (
                   node TEXT NOT NULL, auth TEXT NOT NULL, user_id INTEGER NOT NULL, username TEXT NOT NULL,
                   hour TEXT NOT NULL, tx INTEGER NOT NULL, rx INTEGER NOT NULL, PRIMARY KEY(node,auth,hour))''',
                '''CREATE TABLE IF NOT EXISTS hy2_identities (
                   auth TEXT PRIMARY KEY, user_id INTEGER NOT NULL, username TEXT NOT NULL,
                   created_at TEXT NOT NULL, admin_id INTEGER)''',
            ):
                db.execute(sql)
            if 'auth' not in {r['name'] for r in db.execute('PRAGMA table_info(hy2_hourly)')}:
                raise RuntimeError('Older prototype ledger; explicit migration required')
            db.execute('CREATE INDEX IF NOT EXISTS hy2_hourly_time ON hy2_hourly(hour,node,username)')

    @staticmethod
    def remember(db, users):
        for auth,user in users.items():
            old=db.execute('SELECT * FROM hy2_identities WHERE auth=?',(auth,)).fetchone()
            if old and (old['user_id'],old['username'],old['created_at']) != (user['id'],user['username'],user['created_at']):
                raise Conflict('Previously issued UUID reassigned to a different user')
            db.execute('INSERT OR IGNORE INTO hy2_identities VALUES(?,?,?,?,?)',
                       (auth,user['id'],user['username'],user['created_at'],user['admin_id']))

    @staticmethod
    def users(db):
        result = {}
        rows = db.execute('''SELECT u.*, p.settings FROM users u JOIN proxies p ON p.user_id=u.id
                             WHERE p.type IN ('VLESS','vless') ''').fetchall()
        for row in rows:
            auth = json.loads(row['settings']).get('id')
            if auth:
                if auth in result:
                    raise Conflict('Ambiguous VLESS UUID; refusing authorization')
                result[auth] = dict(row)
        return result

    @staticmethod
    def allowed(user):
        # The native review job activates on_hold from online_at on first payload.
        return (user['status'] in ('active','on_hold')
                and (not user['expire'] or user['expire'] > time.time())
                and (not user['data_limit'] or user['used_traffic'] < user['data_limit']))

    def policy(self,node=None):
        with self.connection(write=True) as db:
            users=self.users(db)
            self.remember(db,users)
            barriers=[];paused=set()
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_barriers'").fetchone():
                # A deadline must not resume forwarding during a slow native flush.
                for row in db.execute('SELECT * FROM fleet_barriers'):
                    auths=json.loads(row['auths']);paused.update(auths)
                    if node in json.loads(row['targets']):barriers.append({'id':row['id'],'auths':auths})
            return {'allowed': [auth for auth, user in users.items() if self.allowed(user) and auth not in paused],'barriers':barriers}

    def ingest(self, node, batch):
        spool, seq, totals = batch['spool'], batch['seq'], batch['totals']
        digest = hashlib.sha256(json.dumps(batch, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        hour = now.replace(minute=0, second=0, microsecond=0).isoformat(' ')
        added = 0
        with self.connection(write=True) as db:
            old = db.execute('SELECT * FROM hy2_nodes WHERE node=?', (node,)).fetchone()
            if old:
                if old['spool'] != spool:
                    raise Conflict('Node spool changed; manual accounting reconciliation required')
                if seq < old['seq']:
                    raise Conflict('Stale sequence')
                if seq == old['seq']:
                    if old['digest'] != digest:
                        raise Conflict('Sequence replay has a different payload')
                    return {'accepted': seq, 'added': 0, 'duplicate': True}
            users = self.users(db)
            self.remember(db,users)
            for auth, counts in totals.items():
                previous = db.execute('SELECT tx,rx FROM hy2_totals WHERE node=? AND auth=?', (node,auth)).fetchone()
                tx,rx = counts['tx'],counts['rx']
                dt,dr = tx-(previous['tx'] if previous else 0),rx-(previous['rx'] if previous else 0)
                if min(dt,dr) < 0:
                    raise Conflict('Cumulative counters went backwards')
                if not dt+dr:
                    continue
                identity=db.execute('SELECT * FROM hy2_identities WHERE auth=?',(auth,)).fetchone()
                if identity is None:
                    raise Conflict('Usage belongs to an unknown UUID; reconciliation required')
                # Deleted/revoked UUIDs may still have queued counters. Keep their
                # history without charging a subsequently reused numeric user ID.
                current=db.execute('SELECT admin_id FROM users WHERE id=? AND username=? AND created_at=?',
                                   (identity['user_id'],identity['username'],identity['created_at'])).fetchone()
                db.execute('''UPDATE users SET used_traffic=COALESCE(used_traffic,0)+?,online_at=?
                              WHERE id=? AND username=? AND created_at=?''',
                           (dt+dr,now.isoformat(' '),identity['user_id'],identity['username'],identity['created_at']))
                admin_id=current['admin_id'] if current else identity['admin_id']
                if admin_id is not None:
                    db.execute('UPDATE admins SET users_usage=users_usage+? WHERE id=?', (dt+dr,admin_id))
                db.execute('''INSERT INTO hy2_hourly VALUES(?,?,?,?,?,?,?)
                              ON CONFLICT(node,auth,hour) DO UPDATE SET tx=tx+excluded.tx,rx=rx+excluded.rx''',
                           (node,auth,identity['user_id'],identity['username'],hour,dt,dr))
                db.execute('''INSERT INTO hy2_totals VALUES(?,?,?,?)
                              ON CONFLICT(node,auth) DO UPDATE SET tx=excluded.tx,rx=excluded.rx''', (node,auth,tx,rx))
                added += dt+dr
            db.execute('''INSERT INTO hy2_nodes VALUES(?,?,?,?,?) ON CONFLICT(node) DO UPDATE
                          SET seq=excluded.seq,digest=excluded.digest,seen_at=excluded.seen_at''',
                       (node,spool,seq,digest,time.time()))
        return {'accepted': seq, 'added': added, 'duplicate': False}

    def report(self):
        with self.connection() as db:
            return {
                'nodes': [dict(r) for r in db.execute('SELECT node,seq,seen_at FROM hy2_nodes')],
                'usage': [dict(r) for r in db.execute('''SELECT node,username,user_id,hour,tx,rx
                    FROM hy2_hourly ORDER BY hour DESC LIMIT 1000''')],
            }
