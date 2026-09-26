"""Node-local durable cumulative ledger; never clears Hysteria counters."""
import sqlite3
import uuid
from contextlib import closing


class Spool:
    def __init__(self, path):
        self.path = str(path)
        with closing(self.db()) as db, db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS meta(id TEXT NOT NULL,seq INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS raw(epoch TEXT,auth TEXT,tx INTEGER,rx INTEGER,PRIMARY KEY(epoch,auth));
            CREATE TABLE IF NOT EXISTS totals(auth TEXT PRIMARY KEY,tx INTEGER,rx INTEGER);
            CREATE TABLE IF NOT EXISTS epochs(epoch TEXT PRIMARY KEY,seen_at TEXT DEFAULT CURRENT_TIMESTAMP);
            ''')
            if not db.execute('SELECT 1 FROM meta').fetchone():
                db.execute('INSERT INTO meta VALUES(?,0)',(str(uuid.uuid4()),))

    def db(self):
        # context manager commits but callers close via finally where needed.
        return sqlite3.connect(self.path,timeout=10)

    def observe(self, epoch, stats):
        db = self.db()
        try:
            with db:
                db.execute('BEGIN IMMEDIATE')
                db.execute('INSERT OR IGNORE INTO epochs(epoch) VALUES(?)',(epoch,))
                for auth, values in stats.items():
                    tx,rx = values['tx'],values['rx']
                    if type(tx) is not int or type(rx) is not int or min(tx,rx)<0 or max(tx,rx)>2**60:
                        raise ValueError('Invalid traffic counter')
                    old = db.execute('SELECT tx,rx FROM raw WHERE epoch=? AND auth=?',(epoch,auth)).fetchone()
                    dt,dr = tx-(old[0] if old else 0),rx-(old[1] if old else 0)
                    if min(dt,dr)<0:
                        raise ValueError('Counters reset without a new process epoch')
                    db.execute('''INSERT INTO totals VALUES(?,?,?) ON CONFLICT(auth) DO UPDATE
                                  SET tx=tx+excluded.tx,rx=rx+excluded.rx''',(auth,dt,dr))
                    db.execute('''INSERT INTO raw VALUES(?,?,?,?) ON CONFLICT(epoch,auth) DO UPDATE
                                  SET tx=excluded.tx,rx=excluded.rx''',(epoch,auth,tx,rx))
                db.execute('UPDATE meta SET seq=seq+1')
                spool,seq = db.execute('SELECT id,seq FROM meta').fetchone()
                return {'spool':spool,'seq':seq,'totals':{
                    auth:{'tx':tx,'rx':rx} for auth,tx,rx in db.execute('SELECT * FROM totals')}}
        finally:
            db.close()
