"""Sudo-facing update status and a narrow request queue for the host worker."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid

from update_runtime.releases import ReleaseCatalog, UpdateError, version_key

ACTIVE_PHASES = {'queued', 'checking', 'downloading', 'backup', 'installing', 'verifying', 'rollback'}
JOB_FIELDS = {'id', 'version', 'phase', 'error', 'started_at', 'updated_at', 'completed_at', 'progress'}


class Updates:
    def __init__(self, directory, current_version, database=None, catalog=None, supported=True):
        self.directory = Path(directory)
        self.current_version = current_version
        self.database = database
        self.catalog = catalog or ReleaseCatalog()
        self.checked_at = None
        self.latest = None
        self.supported=supported

    def read(self, name):
        path = self.directory / name
        try:
            if path.is_symlink() or path.stat().st_size > 65536:
                return {}
            value = json.loads(path.read_text())
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def status(self):
        agent = self.read('agent.json')
        job = {key: value for key, value in self.read('status.json').items() if key in JOB_FIELDS}
        if job.get('phase') == 'queued' and time.time() - job.get('updated_at', 0) > 60:
            job.update(phase='failed', error='agent_unavailable')
        latest = self.latest
        return {
            'current_version': self.current_version, 'enabled': self.supported and agent.get('protocol') == 1,
            'checked_at': self.checked_at, 'latest': latest,
            'available': bool(latest and version_key(latest['version']) > version_key(self.current_version)),
            'job': job,
        }

    def check(self):
        if self.checked_at is None or time.time() - self.checked_at > 15:
            release = self.catalog.latest()
            self.latest = {key: release[key] for key in ['id', 'tag', 'version', 'notes', 'published_at', 'manifest_sha256']} if release else None
            self.checked_at = time.time()
        return self.status()

    def write(self, name, value):
        temporary = self.directory / ('.' + name + '.' + uuid.uuid4().hex)
        with temporary.open('x') as output:
            json.dump(value, output)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o600)
        temporary.replace(self.directory / name)

    @contextlib.contextmanager
    def lock(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise UpdateError('agent_unavailable')
        with (self.directory / '.request.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def ensure_idle(self):
        if not self.database:
            return
        with sqlite3.connect('file:' + str(self.database) + '?mode=ro', uri=True, timeout=5) as database:
            tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table in ['fleet_jobs', 'fleet_proxy_jobs', 'fleet_relay_jobs']:
                if table in tables and database.execute('SELECT 1 FROM ' + table + " WHERE state='running' LIMIT 1").fetchone():
                    raise UpdateError('node_operation_running')
            if 'fleet_node_transfers' in tables and database.execute("SELECT 1 FROM fleet_node_transfers WHERE state='switched' LIMIT 1").fetchone():
                raise UpdateError('node_operation_running')

    def enqueue(self, version):
        if not self.supported:raise UpdateError('unsupported_database')
        release = self.catalog.by_tag('v' + version)
        if version_key(version) <= version_key(self.current_version):
            raise UpdateError('version_not_newer')
        with self.lock():
            status = self.status()
            if not status['enabled']:
                raise UpdateError('agent_unavailable')
            if status['job'].get('phase') in ACTIVE_PHASES:
                raise UpdateError('update_running')
            self.ensure_idle()
            job = {'id': uuid.uuid4().hex, 'version': release['version'], 'phase': 'queued', 'updated_at': time.time()}
            self.write('status.json', job)
            self.write('request.json', {
                'id': job['id'], 'tag': release['tag'], 'release_id': release['id'],
                'manifest_sha256': release['manifest_sha256'], 'requested_at': time.time(),
            })
        return self.status()
