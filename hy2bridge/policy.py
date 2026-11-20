"""Persistent node-local authorization; controller freshness is observational."""
import json
import math
import sqlite3
import time
from contextlib import closing


class LocalPolicy:
    def __init__(self, path):
        self.path = path
        self.value = None
        with closing(sqlite3.connect(path, timeout=10)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS local_policy(id INTEGER PRIMARY KEY CHECK(id=1),data TEXT NOT NULL)')
            row = db.execute('SELECT data FROM local_policy WHERE id=1').fetchone()
            if row:
                self.value = self.validate(json.loads(row[0]))

    @staticmethod
    def validate(value):
        if not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] < 1:
            raise ValueError('Missing policy version')
        allowed = value.get('allowed')
        if not isinstance(allowed, list) or not all(isinstance(a, str) for a in allowed):
            raise ValueError('Invalid allowed identities')
        rules = value.get('rules')
        if not isinstance(rules, dict) or set(rules) != set(allowed):
            raise ValueError('Incomplete local policy')
        for rule in rules.values():
            if not isinstance(rule, dict):
                raise ValueError('Invalid local rule')
            for key in ('expire', 'remaining_bytes', 'accounted_bytes'):
                n = rule.get(key)
                if key == 'remaining_bytes' and n is None:
                    continue
                if type(n) not in (int, float) or not math.isfinite(n) or n < 0:
                    raise ValueError('Invalid local limit')
        return value

    def replace(self, value):
        # Copy through JSON: the caller cannot mutate an accepted policy later.
        value = self.validate(json.loads(json.dumps(value)))
        if self.value and value['version'] < self.value['version']:
            raise ValueError('Stale policy version')
        if self.value and value['version'] == self.value['version'] and value != self.value:
            raise ValueError('Conflicting policy version')
        with closing(sqlite3.connect(self.path, timeout=10)) as db, db:
            db.execute('INSERT INTO local_policy VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                       (json.dumps(value, sort_keys=True),))
        self.value = value

    def permits(self, auth, totals, now=None):
        if not self.value or not isinstance(auth, str):
            return False
        rule = self.value['rules'].get(auth)
        if rule is None:
            return False
        if rule['expire'] and (time.time() if now is None else now) >= rule['expire']:
            return False
        remaining = rule['remaining_bytes']
        return remaining is None or max(0, totals.get(auth, 0) - rule['accounted_bytes']) < remaining
