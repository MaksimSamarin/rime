"""Host-side Docker update worker, triggered by a local systemd.path unit."""
import argparse
import contextlib
import copy
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import tarfile
import time
import uuid
import urllib.parse

from .releases import REPOSITORY, ReleaseCatalog, UpdateError, version_key
from .artifacts import archive_identity, new_layer_bytes
from .leases import hold,set_barrier,clear_barrier


def available_for_update(path, configuration):
    usage=shutil.disk_usage(path)
    minimum=int(configuration.get('minimum_free_bytes',2*1024**3))
    percent=float(configuration.get('minimum_free_percent',10))
    if minimum<0 or not 0<=percent<=50:raise UpdateError('invalid_host_configuration')
    reserve=max(minimum,int(usage.total*percent/100))
    if usage.free<reserve:raise UpdateError('insufficient_disk_space')
    return usage.free-reserve


def replacement_configuration(old, previous, candidate):
    """Carry explicit deployment overrides, not inherited base-image defaults."""
    result=copy.deepcopy(old)
    before=previous.get('Config',{});after=candidate.get('Config',{})
    for field in ['Cmd','Entrypoint','User','WorkingDir','Shell','Healthcheck','StopSignal','StopTimeout']:
        if result.get(field)==before.get(field):
            if field in after:result[field]=copy.deepcopy(after[field])
            else:result.pop(field,None)
    defaults=dict(item.split('=',1) for item in before.get('Env',[]))
    environment=dict(item.split('=',1) for item in after.get('Env',[]))
    environment.update((key,value) for key,value in
        (item.split('=',1) for item in old.get('Env',[])) if defaults.get(key)!=value)
    result['Env']=[key+'='+value for key,value in environment.items()]
    result['Labels']={key:value for key,value in (old.get('Labels') or {}).items()
                      if not key.startswith('com.docker.compose.')}
    result['Labels'].update((key,value) for key,value in (after.get('Labels') or {}).items()
                            if not key.startswith('com.docker.compose.'))
    return result


class DockerConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/var/run/docker.sock')


class Docker:
    def request(self, method, path, value=None, file=None, timeout=60, missing_ok=False):
        connection = DockerConnection('localhost', timeout=timeout)
        headers = {'Content-Type': 'application/json'}
        body = json.dumps(value).encode() if value is not None else b''
        if file is not None:
            headers = {'Content-Type': 'application/x-tar', 'Content-Length': str(os.fstat(file.fileno()).st_size)}
            body = file
        try:
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            if response.status == 404 and missing_ok:
                return None
            if response.status == 304:
                return None
            if response.status >= 300 or len(raw) > 4 * 1024 * 1024:
                raise UpdateError('docker_operation_failed')
            if not raw:
                return None
            try:
                value = json.loads(raw)
                if isinstance(value, dict) and ('error' in value or 'errorDetail' in value):
                    raise UpdateError('docker_operation_failed')
                return value
            except ValueError:
                records = [json.loads(line) for line in raw.splitlines() if line.strip()]
                if any('error' in record for record in records):
                    raise UpdateError('docker_operation_failed')
                return records
        finally:
            connection.close()

    def inspect(self, name, missing_ok=False):
        return self.request('GET', '/containers/' + urllib.parse.quote(name, safe='') + '/json', missing_ok=missing_ok)

    def execute(self, container, args, timeout=20):
        created = self.request('POST', '/containers/' + container + '/exec', {
            'AttachStdout': True, 'AttachStderr': True, 'Cmd': args,
        })
        self.request('POST', '/exec/' + created['Id'] + '/start', {'Detach': True, 'Tty': False})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.request('GET', '/exec/' + created['Id'] + '/json')
            if not state['Running']:
                return state['ExitCode'] == 0
            time.sleep(.2)
        return False


class Worker:
    def __init__(self, config, docker=None, catalog=None):
        self.config = config
        if 'container' in config and (not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}',config['container'])
                or re.fullmatch(r'[a-fA-F0-9]{64}',config['container'])):
            raise UpdateError('invalid_host_configuration')
        self.data = Path(config['data_directory']).resolve()
        self.public = self.data / '.updates'
        self.private = Path(config['state_directory']).resolve()
        if self.data == Path('/') or self.private == self.data or self.data in self.private.parents:
            raise UpdateError('invalid_host_configuration')
        self.private.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.private.chmod(0o700)
        self.docker = docker or Docker()
        self.catalog = catalog or ReleaseCatalog(config.get('api_root', 'https://api.github.com'), config.get('lab', False),
            public_keys=config.get('lab_release_public_keys') if config.get('lab') else None)
        self.job = None
        self.folder = None

    def public_directory(self):
        return os.open(self.public, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def read_public(self, name):
        directory = self.public_directory()
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(descriptor, 'rb') as source:
                raw = source.read(65537)
            if len(raw) > 65536:
                raise UpdateError('invalid_update_request')
            return json.loads(raw)
        finally:
            os.close(directory)

    @contextlib.contextmanager
    def request_lock(self):
        directory = self.public_directory()
        descriptor = os.open('.request.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            os.fchown(descriptor, self.config.get('panel_uid', 0), self.config.get('panel_gid', 0))
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield directory
        finally:
            os.close(descriptor)
            os.close(directory)

    def finish_request(self):
        with self.request_lock() as directory:
            try:
                current = self.read_public('request.json')
            except FileNotFoundError:
                return
            if current.get('id') == self.job['id']:
                os.unlink('request.json', dir_fd=directory)
                os.fsync(directory)
        self.clear_cancel()

    def write_public(self, name, value):
        directory = self.public_directory()
        temporary = '.' + name + '.' + str(os.getpid())
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, 'w') as target:
                json.dump(value, target)
                target.flush()
                os.fsync(target.fileno())
                os.fchown(target.fileno(), self.config.get('panel_uid', 0), self.config.get('panel_gid', 0))
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            os.close(directory)

    def status(self, phase, **fields):
        value = {
            'id': self.job['id'], 'version': self.job['tag'].removeprefix('v'),
            **({'operation': self.job['operation']} if self.job.get('operation') else {}),
            'phase': phase, 'started_at': self.job['requested_at'], 'updated_at': time.time(), **fields,
        }
        if phase in {'succeeded', 'rolled_back', 'failed'}:
            value['completed_at'] = time.time()
            (self.folder / 'outcome.json').write_text(json.dumps({'phase': phase, 'at': value['completed_at']}))
        self.write_public('status.json', value)

    def save(self, state):
        temporary = self.folder / 'journal.next.json'
        with temporary.open('w') as target:
            json.dump(state, target)
            target.flush()
            os.fsync(target.fileno())
        temporary.replace(self.folder / 'journal.json')

    def ensure_idle(self):
        database = Path(self.config['database'])
        with sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True, timeout=10) as source:
            tables = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table in ['fleet_jobs', 'fleet_proxy_jobs', 'fleet_relay_jobs']:
                if table in tables and source.execute('SELECT 1 FROM ' + table + " WHERE state='running' LIMIT 1").fetchone():
                    raise UpdateError('node_operation_running')
            if 'fleet_node_transfers' in tables and source.execute("SELECT 1 FROM fleet_node_transfers WHERE state='switched' LIMIT 1").fetchone():
                raise UpdateError('node_operation_running')

    @staticmethod
    def resume_offset(response, expected):
        """First byte of the body: 0 for a full answer, the range start for 206, None if unusable."""
        code = getattr(response, 'status', None) or response.getcode()
        if code == 200:
            return 0
        match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', (response.headers.get('Content-Range') or '').strip())
        if code != 206 or not match or int(match.group(3)) != expected:
            return None
        return int(match.group(1))

    def cancel_requested(self):
        try:
            value = self.read_public('cancel.json')
        except (OSError, ValueError, UpdateError):
            return False
        return isinstance(value, dict) and value.get('id') == self.job['id']

    def check_cancel(self):
        """Stop before the backup starts when the panel queued a cancel request for this job."""
        if self.cancel_requested():
            raise UpdateError('update_cancelled')

    def clear_cancel(self, stale_only=False):
        directory = self.public_directory()
        try:
            try:
                descriptor = os.open('cancel.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                return
            with os.fdopen(descriptor, 'rb') as source:
                raw = source.read(4097)
            try:
                value = json.loads(raw)
            except ValueError:
                value = {}
            if not stale_only or not isinstance(value, dict) or value.get('id') != self.job['id']:
                os.unlink('cancel.json', dir_fd=directory)
        finally:
            os.close(directory)

    def publish_rollback(self):
        """Offer the image this job replaced, when the worker would accept the rollback right now."""
        directory = self.public_directory()
        try:
            with contextlib.suppress(FileNotFoundError):
                os.unlink('rollback.json', dir_fd=directory)
        finally:
            os.close(directory)
        try:
            target = self.manual_release(self.job['id'])
        except (OSError, ValueError, KeyError, UpdateError):
            return None
        offer = {'parent': self.job['id'], 'version': target['version'],
                 'from': self.job['tag'].removeprefix('v'), 'published_at': time.time()}
        self.write_public('rollback.json', offer)
        return offer

    def fetch(self, artifact, path):
        """Download the release archive and verify it, resuming after dropped connections.

        Slow routes to GitHub close long transfers before the end. Each retry asks for the
        remaining bytes with Range and keeps hashing in file order, so a resumed archive is
        verified exactly like one fetched in a single response.
        """
        expected = artifact['size']
        limit = int(self.config.get('download_retries', 8))
        delay = float(self.config.get('download_retry_delay', 5))
        digest = hashlib.sha256()
        size = failures = retries = 0
        with path.open('wb') as target:
            while size < expected:
                before = size
                try:
                    headers = {'Range': 'bytes=%d-' % size} if size else None
                    with self.catalog.open(artifact['url'], headers) as response:
                        offset = self.resume_offset(response, expected) if size else 0
                        if offset == 0 and size:
                            # The server ignored the range and sent the whole file again.
                            target.seek(0)
                            target.truncate()
                            digest = hashlib.sha256()
                            size = before = 0
                        if offset == size:
                            while block := response.read(256 * 1024):
                                self.check_cancel()
                                size += len(block)
                                if size > expected:
                                    raise UpdateError('release_checksum_mismatch')
                                digest.update(block)
                                target.write(block)
                                self.status('downloading', progress=round(size / expected * 100), retries=retries)
                except UpdateError as error:
                    if error.code != 'release_unavailable':
                        raise
                except (OSError, http.client.HTTPException):
                    pass
                if size >= expected:
                    break
                failures = 0 if size > before else failures + 1
                if failures > limit:
                    raise UpdateError('release_unavailable')
                retries += 1
                self.status('downloading', progress=round(size / expected * 100), retries=retries)
                pause = time.monotonic() + min(delay * 2 ** max(failures - 1, 0), 60)
                while True:
                    self.check_cancel()
                    left = pause - time.monotonic()
                    if left <= 0:
                        break
                    time.sleep(min(left, 1))
        if size != expected or digest.hexdigest() != artifact['sha256']:
            raise UpdateError('release_checksum_mismatch')

    def download(self, release):
        artifact = release['artifact']
        path = self.folder / 'image.tar.gz'
        needed = artifact['size']
        if available_for_update(self.private,self.config) < needed:
            raise UpdateError('insufficient_disk_space')
        self.fetch(artifact, path)
        identity = archive_identity(path)
        repository = self.config.get('lab_image_prefix') if self.config.get('lab') else 'rime'
        reference = repository + ':' + release['version']
        if identity['image_id'] != artifact['image_id'] or identity['tags'] != [reference]:
            raise UpdateError('image_identity_mismatch')
        root = Path(self.docker.request('GET', '/info')['DockerRootDir'])
        if self.config.get('lab'):
            root = self.private
        current = self.docker.inspect(self.config['container'])
        previous = self.docker.request('GET', '/images/' + urllib.parse.quote(current['Image'],safe='') + '/json')
        existing = set(previous.get('RootFS',{}).get('Layers',[]))
        # Loading needs space for temporary extraction and the new layer store.
        # Shared base layers already present in the current image are reused.
        budget = available_for_update(root,self.config)//2
        new_layer_bytes(path, existing, budget)
        with path.open('rb') as source:
            self.docker.request('POST', '/images/load?quiet=1', file=source, timeout=300)
        image = self.docker.request('GET', '/images/' + urllib.parse.quote(reference, safe='') + '/json')
        labels = image.get('Config', {}).get('Labels') or {}
        if labels.get('org.opencontainers.image.source') != 'https://github.com/' + REPOSITORY:
            raise UpdateError('image_identity_mismatch')
        if labels.get('org.opencontainers.image.version') != release['version'] or labels.get('org.opencontainers.image.revision') != release['revision']:
            raise UpdateError('image_identity_mismatch')
        saved = identity['config']
        if image.get('Os') != saved.get('os') or image.get('Architecture') != saved.get('architecture'):
            raise UpdateError('image_identity_mismatch')
        if image.get('RootFS', {}).get('Layers') != saved.get('rootfs', {}).get('diff_ids'):
            raise UpdateError('image_identity_mismatch')
        for key in ['Env', 'Cmd', 'Entrypoint', 'User', 'WorkingDir', 'Labels']:
            if image['Config'].get(key) != saved.get('config', {}).get(key):
                raise UpdateError('image_identity_mismatch')
        path.unlink()
        available_for_update(root,self.config)
        return image['Id']

    def backup(self):
        database = Path(self.config['database']).resolve()
        if self.data not in database.parents:
            raise UpdateError('invalid_host_configuration')
        files = [path for path in self.data.rglob('*') if path.is_file() and not path.is_symlink()
                 and self.public not in path.parents and 'backups' not in path.parts
                 and 'maintenance-backups' not in path.parts and not path.name.endswith('.log')]
        if available_for_update(self.private,self.config) < sum(path.stat().st_size for path in files)+database.stat().st_size:
            raise UpdateError('insufficient_disk_space')
        self.sqlite_snapshot()
        database_info = database.stat()
        (self.folder / 'database-mode.json').write_text(json.dumps({
            'uid': database_info.st_uid, 'gid': database_info.st_gid,
            'mode': stat.S_IMODE(database_info.st_mode),
        }))
        database_name = 'data/' + str(database.relative_to(self.data))

        def selected(member):
            parts = Path(member.name).parts
            if '.updates' in parts or 'backups' in parts or 'maintenance-backups' in parts:
                return None
            if member.name.endswith(('.log', '-wal', '-shm', '-journal')):
                return None
            if member.name == database_name:
                return None
            return member

        with tarfile.open(self.folder / 'data.tar.gz', 'w:gz', compresslevel=1) as archive:
            archive.add(self.data, arcname='data', filter=selected)
            archive.add(self.folder / 'database.sqlite3', arcname=database_name)
        available_for_update(self.private,self.config)

    def require_rollback_compatible(self, version):
        if version_key(version)>=version_key('0.9.0'):return
        # Besides cumulative accounting, unmodified older controllers lack the
        # authenticated native API and the hub's mandatory private-API guard.
        # Do not even boot such a target for a readiness trial.
        raise UpdateError('downgrade_requires_preparation')

    def database_revisions(self, path=None):
        with sqlite3.connect('file:'+str(path or self.config['database'])+'?mode=ro',uri=True) as database:
            if not database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alembic_version'").fetchone():return []
            return sorted(row[0] for row in database.execute('SELECT version_num FROM alembic_version'))

    def manual_release(self, parent):
        if not re.fullmatch(r'[a-f0-9]{32}',parent):raise UpdateError('invalid_update_request')
        path=self.private/parent/'journal.json'
        if path.is_symlink():raise UpdateError('invalid_update_request')
        journal=json.loads(path.read_text())
        if journal.get('phase')!='succeeded':raise UpdateError('rollback_not_available')
        current=self.docker.inspect(self.config['container'])
        if current['Id']!=journal.get('new_id'):raise UpdateError('rollback_not_current')
        version=journal.get('old_version')
        version_key(version)
        self.require_rollback_compatible(version)
        if self.database_revisions()!=journal.get('database_revisions',[]):
            raise UpdateError('rollback_schema_incompatible')
        image=self.docker.request('GET','/images/'+journal['old']['Image']+'/json')
        if not image:raise UpdateError('rollback_not_available')
        return {'version':version,'runtime_image_id':image['Id'],
                'expected_current_id':current['Id'],'manual':True}

    def enqueue_rollback(self,parent,confirmation):
        if confirmation!='rollback':raise UpdateError('rollback_confirmation_required')
        with self.request_lock():
            if (self.public/'request.json').exists():raise UpdateError('update_running')
            release=self.manual_release(parent)
            job={'id':uuid.uuid4().hex,'operation':'rollback','parent':parent,
                 'tag':'v'+release['version'],'requested_at':time.time()}
            self.write_public('request.json',job)
            self.write_public('status.json',{'id':job['id'],'version':release['version'],
                'phase':'queued','updated_at':time.time()})

    def health_token(self):
        token=secrets.token_urlsafe(48)
        directory=self.public_directory()
        try:
            descriptor=os.open('.health-token',os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(descriptor,'w') as target:
                target.write(token);target.flush();os.fsync(target.fileno())
                os.fchmod(target.fileno(),0o600)
                os.fchown(target.fileno(),self.config.get('panel_uid',0),self.config.get('panel_gid',0))
        finally:os.close(directory)

    def sqlite_snapshot(self):
        path = self.folder / 'database.sqlite3'
        temporary=self.folder/('database-next-'+secrets.token_hex(16)+'.sqlite3')
        try:
            with contextlib.closing(sqlite3.connect('file:' + self.config['database'] + '?mode=ro', uri=True, timeout=10)) as source:
                with contextlib.closing(sqlite3.connect(temporary)) as target:
                    source.backup(target)
                    if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':raise UpdateError('database_backup_failed')
            temporary.chmod(0o600)
            temporary.replace(path)
        finally:temporary.unlink(missing_ok=True)

    def health(self, container, version):
        script = 'from update_runtime.health import check;check(EXPECTED)'
        deadline = time.monotonic() + self.config.get('health_timeout', 90)
        while time.monotonic() < deadline:
            current = self.docker.inspect(container)
            if current['State'].get('OOMKilled') or current.get('RestartCount', 0):
                return False
            if current['State']['Running'] and self.docker.execute(container, ['python', '-c', 'EXPECTED=' + repr(version) + '\n' + script]):
                return True
            time.sleep(1)
        return False

    def rollback(self, journal):
        self.status('rollback')
        candidate = journal.get('new_id')
        previous = self.docker.inspect(journal['old']['Id'])
        if candidate and previous['State']['Running']:
            self.docker.request('POST', '/containers/' + previous['Id'] + '/stop?t=15')
        try:
            if candidate:
                current = self.docker.inspect(candidate, missing_ok=True)
                if current and current['State']['Running']:
                    self.docker.request('POST', '/containers/' + candidate + '/stop?t=15')
                if current:
                    self.docker.request('DELETE', '/containers/' + candidate)
                restore_error=None
                try:
                    with tarfile.open(self.folder / 'data.tar.gz') as archive:self.restore_files(archive)
                except BaseException as error:restore_error=error
                database = Path(self.config['database'])
                for suffix in ['-wal', '-shm', '-journal']:
                    Path(str(database) + suffix).unlink(missing_ok=True)
                parent=database.parent.resolve()
                if parent!=self.data and self.data not in parent.parents:raise UpdateError('invalid_backup')
                temporary=parent/('.rime-db-restore-'+secrets.token_hex(16))
                try:
                    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with (self.folder/'database.sqlite3').open('rb') as source,os.fdopen(descriptor,'wb') as target:
                        shutil.copyfileobj(source,target)
                        target.flush()
                        os.fsync(target.fileno())
                    attributes = json.loads((self.folder / 'database-mode.json').read_text())
                    temporary.chmod(attributes['mode'])
                    os.chown(temporary, attributes['uid'], attributes['gid'])
                    temporary.replace(database)
                finally:temporary.unlink(missing_ok=True)
                if restore_error:raise restore_error
        finally:
            previous = self.docker.inspect(journal['old']['Id'])
            name = self.config['container']
            if previous['Name'] != '/' + name:
                self.docker.request('POST', '/containers/' + previous['Id'] + '/rename?name=' + urllib.parse.quote(name, safe=''))
            self.docker.request('POST', '/containers/' + previous['Id'] + '/update', {'RestartPolicy': journal['old']['HostConfig']['RestartPolicy']})
            if not previous['State']['Running']:
                self.docker.request('POST', '/containers/' + previous['Id'] + '/start')
            self.select_image(journal['old']['Image'])
        journal['phase'] = 'rolled_back'
        self.save(journal)
        self.status('rolled_back', error='candidate_failed')
        clear_barrier(self.public,self.job['id'])

    def restore_files(self, archive):
        members=[]
        root_member=None
        for member in archive.getmembers():
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'data':
                raise UpdateError('invalid_backup')
            relative=Path(*path.parts[1:])
            if relative==Path('.'):
                root_member=member
                continue
            if any(part in {'.updates','backups','maintenance-backups'} for part in relative.parts):
                raise UpdateError('invalid_backup')
            if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
                raise UpdateError('invalid_backup')
            members.append((member,relative))

        expected={str(relative) for member,relative in members}
        def confined_parent(path):
            parent=path.parent.resolve()
            if parent!=self.data and self.data not in parent.parents:raise UpdateError('invalid_backup')

        # Restore original directories before touching their children. A failed
        # candidate may have replaced a directory with an external symlink.
        for member,relative in sorted(members,key=lambda value:len(value[1].parts)):
            if not member.isdir():continue
            path=self.data/relative
            confined_parent(path)
            if path.is_symlink() or path.is_file():path.unlink()
            path.mkdir(exist_ok=True)

        for base,directories,files in os.walk(self.data,topdown=True,followlinks=False):
            for name in list(directories)+files:
                path=Path(base)/name
                relative=path.relative_to(self.data)
                ignored=any(part in {'.updates','backups','maintenance-backups'} for part in relative.parts) or name.endswith(('.log','-wal','-shm','-journal'))
                if ignored:
                    if name in directories:directories.remove(name)
                    continue
                if str(relative) in expected:continue
                confined_parent(path)
                if path.is_dir() and not path.is_symlink():
                    if path.resolve()!=self.data and self.data in path.resolve().parents:shutil.rmtree(path)
                    else:raise UpdateError('invalid_backup')
                else:path.unlink()
                if name in directories:directories.remove(name)

        for member,relative in members:
            if not member.isfile():continue
            path=self.data/relative
            confined_parent(path)
            if path.is_symlink():path.unlink()
            if path.is_dir():shutil.rmtree(path)
            temporary=path.parent/('.rime-restore-'+secrets.token_hex(16))
            try:
                descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with archive.extractfile(member) as source,os.fdopen(descriptor,'wb') as target:
                    shutil.copyfileobj(source,target)
                    target.flush()
                    os.fsync(target.fileno())
                temporary.replace(path)
            finally:temporary.unlink(missing_ok=True)

        for member,relative in members:
            if not (member.issym() or member.islnk()):continue
            path=self.data/relative
            confined_parent(path)
            if path.is_dir() and not path.is_symlink():shutil.rmtree(path)
            elif path.exists() or path.is_symlink():path.unlink()
            if member.issym():os.symlink(member.linkname,path)
            else:
                target=Path(member.linkname)
                if target.is_absolute() or '..' in target.parts or not target.parts or target.parts[0]!='data':raise UpdateError('invalid_backup')
                source=self.data/Path(*target.parts[1:])
                if source.resolve()!=self.data and self.data not in source.resolve().parents:raise UpdateError('invalid_backup')
                os.link(source,path,follow_symlinks=False)

        # Ownership matters for private keys and non-root panel installations.
        for member,relative in sorted(members,key=lambda value:len(value[1].parts),reverse=True):
            path=self.data/relative
            confined_parent(path)
            os.chown(path,member.uid,member.gid,follow_symlinks=False)
            if not member.issym():
                path.chmod(member.mode)
                os.utime(path,(member.mtime,member.mtime),follow_symlinks=False)
        if root_member:
            os.chown(self.data,root_member.uid,root_member.gid)
            self.data.chmod(root_member.mode)

    def select_image(self, image):
        repository, tag = self.config.get('image_alias', 'rime:current').rsplit(':', 1)
        query = urllib.parse.urlencode({'repo': repository, 'tag': tag})
        self.docker.request('POST', '/images/' + image + '/tag?' + query)

    def install(self, release):
        deadline=time.monotonic()+self.config.get('quiesce_timeout',60)
        self.status('backup')
        while True:
            try:
                with hold(self.public, exclusive=True, owner=(self.config.get('panel_uid', 0), self.config.get('panel_gid', 0))):
                    self.install_locked(release)
                return
            except BlockingIOError:
                if time.monotonic()>=deadline:raise UpdateError('node_operation_running') from None
                time.sleep(.25)
            except UpdateError as error:
                if error.code!='node_operation_running' or time.monotonic()>=deadline:raise
                time.sleep(.25)

    def install_locked(self, release):
        old = self.docker.inspect(self.config['container'])
        if not old['State']['Running']:
            raise UpdateError('panel_not_running')
        if release.get('manual') and old['Id']!=release['expected_current_id']:
            raise UpdateError('rollback_not_current')
        comparison = r'''
import ast,re
from pathlib import Path
current=next(ast.literal_eval(n.value) for n in ast.parse(Path('/code/app/__init__.py').read_text()).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='__version__' for t in n.targets))
def key(value):
 m=re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-rc\.?(\d+))?',value)
 assert m
 major,minor,patch,rc=m.groups()
 return int(major),int(minor),int(patch),rc is None,int(rc or 0)
assert key(NEW)>key(current)
'''
        if not release.get('manual') and not self.docker.execute(old['Id'], ['python', '-c', 'NEW=' + repr(release['version']) + '\n' + comparison]):
            raise UpdateError('version_not_newer')
        if any(mount['Destination'] == '/code' or mount['Destination'].startswith('/code/') for mount in old['Mounts']):
            raise UpdateError('source_mount_overrides_image')
        self.ensure_idle()
        self.health_token()
        self.status('backup')
        self.backup()
        self.ensure_idle()
        journal = {'phase': 'installing', 'old': old, 'new_id': None, 'version': release['version'],
                   'old_version':getattr(self,'installed_version',self.config.get('current_version')),
                   'database_revisions':self.database_revisions()}
        self.save(journal)
        set_barrier(self.public,self.job['id'],(self.config.get('panel_uid',0),self.config.get('panel_gid',0)))
        try:
            self.status('installing')
            self.docker.request('POST', '/containers/' + old['Id'] + '/stop?t=20')
            self.sqlite_snapshot()
            self.docker.request('POST', '/containers/' + old['Id'] + '/update', {'RestartPolicy': {'Name': 'no'}})
            previous_name = 'rime-update-before-' + self.job['id']
            self.docker.request('POST', '/containers/' + old['Id'] + '/rename?name=' + previous_name)
            previous_image = self.docker.request('GET', '/images/' + old['Image'] + '/json')
            candidate_image = self.docker.request('GET', '/images/' + release['runtime_image_id'] + '/json')
            config = replacement_configuration(old['Config'],previous_image,candidate_image)
            config['Image'] = release['runtime_image_id']
            config['HostConfig'] = copy.deepcopy(old['HostConfig'])
            config['Labels'] = {**(config.get('Labels') or {}), 'rime.update': self.job['id']}
            for key, value in (candidate_image['Config'].get('Labels') or {}).items():
                if key.startswith('org.opencontainers.image.'):
                    config['Labels'][key] = value
            if config['HostConfig']['NetworkMode'].startswith('container:'):
                config['Hostname'] = ''
                config['Domainname'] = ''
                config['ExposedPorts'] = {}
                config['HostConfig']['PortBindings'] = {}
            created = self.docker.request('POST', '/containers/create?name=' + urllib.parse.quote(self.config['container'], safe=''), config)
            journal['new_id'] = created['Id']
            self.save(journal)
            self.docker.request('POST', '/containers/' + created['Id'] + '/start')
            journal['phase'] = 'verifying'
            self.save(journal)
            self.status('verifying')
            if not self.health(created['Id'], release['version']):
                raise UpdateError('candidate_failed')
            self.select_image(release['runtime_image_id'])
            journal['phase'] = 'succeeded'
            self.save(journal)
            self.status('succeeded')
            clear_barrier(self.public,self.job['id'])
        except BaseException:
            self.rollback(journal)
            raise

    def prune(self):
        completed = []
        for folder in self.private.iterdir():
            if not folder.is_dir() or folder.is_symlink() or not re.fullmatch(r'[a-f0-9]{32}', folder.name):
                continue
            journal = folder / 'journal.json'
            if journal.is_file():
                state = json.loads(journal.read_text())
                if state.get('phase') in {'succeeded', 'rolled_back'}:
                    completed.append((folder, state))
            elif folder != self.folder and (folder/'outcome.json').is_file() and folder.stat().st_mtime < time.time()-7*86400:
                if json.loads((folder/'outcome.json').read_text()).get('phase')=='failed':
                    shutil.rmtree(folder)
        completed.sort(key=lambda item: item[0].stat().st_mtime, reverse=True)
        keep = max(2, int(self.config.get('keep_backups', 2)))
        for folder, journal in completed[keep:]:
            previous = self.docker.inspect(journal['old']['Id'], missing_ok=True)
            if previous and not previous['State']['Running']:
                if previous['Name'] != '/rime-update-before-' + folder.name:
                    continue
                self.docker.request('DELETE', '/containers/' + previous['Id'])
            self.retire_image(journal['old']['Image'])
            if folder.resolve().parent != self.private:
                raise UpdateError('invalid_host_configuration')
            shutil.rmtree(folder)

    def retire_image(self, identity):
        image = self.docker.request('GET','/images/'+identity+'/json',missing_ok=True)
        if not image:return
        labels = image.get('Config',{}).get('Labels') or {}
        if labels.get('org.opencontainers.image.source')!='https://github.com/'+REPOSITORY:return
        version = labels.get('org.opencontainers.image.version','')
        if not re.fullmatch(r'\d+\.\d+\.\d+',version):return
        filters = urllib.parse.quote(json.dumps({'ancestor':[identity]}),safe='')
        if self.docker.request('GET','/containers/json?all=1&filters='+filters):return
        prefix = self.config.get('lab_image_prefix','rime') if self.config.get('lab') else 'rime'
        tag = prefix+':'+version
        if tag in (image.get('RepoTags') or []):
            self.docker.request('DELETE','/images/'+urllib.parse.quote(tag,safe='')+'?force=false',missing_ok=True)

    def discard_unneeded_backup(self):
        if (self.folder/'journal.json').exists():return
        for name in ['data.tar.gz','database.sqlite3','database-mode.json']:
            (self.folder/name).unlink(missing_ok=True)

    def run(self):
        with (self.private / 'worker.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.request_lock() as directory:
                try:
                    self.job = self.read_public('request.json')
                    if not isinstance(self.job, dict) or not re.fullmatch(r'[a-f0-9]{32}', self.job.get('id', '')):
                        raise UpdateError('invalid_update_request')
                    version_key(self.job.get('tag', ''))
                except (ValueError, TypeError):
                    self.write_public('status.json', {'phase': 'failed', 'error': 'invalid_update_request', 'updated_at': time.time()})
                    os.unlink('request.json', dir_fd=directory)
                    return
            self.folder = self.private / self.job['id']
            self.folder.mkdir(mode=0o700, exist_ok=True)
            journal_path = self.folder / 'journal.json'
            if journal_path.exists():
                journal = json.loads(journal_path.read_text())
                if journal['phase'] in {'succeeded', 'rolled_back'}:
                    clear_barrier(self.public,self.job['id'])
                    self.finish_request()
                    return
                with hold(self.public,exclusive=True,owner=(self.config.get('panel_uid',0),self.config.get('panel_gid',0))):
                    self.rollback(journal)
                self.finish_request()
                return
            if not time.time() - 60 <= self.job.get('requested_at', 0) <= time.time() + 5:
                self.status('failed', error='request_expired')
                self.finish_request()
                return
            try:
                self.clear_cancel(stale_only=True)
                self.check_cancel()
                self.status('checking')
                self.ensure_idle()
                manual=self.job.get('operation')=='rollback'
                release = self.manual_release(self.job.get('parent','')) if manual else self.catalog.by_tag(self.job['tag'])
                self.check_cancel()
                if not manual and (release['id'] != self.job.get('release_id') or release['manifest_sha256'] != self.job.get('manifest_sha256')):
                    raise UpdateError('release_changed')
                installed = self.private / 'installed-version.json'
                current = json.loads(installed.read_text())['version'] if installed.exists() else self.config['current_version']
                self.installed_version=current
                if not manual and version_key(release['version']) <= version_key(current):
                    raise UpdateError('version_not_newer')
                if not manual:
                    self.status('downloading', progress=0)
                    release['runtime_image_id'] = self.download(release)
                    (self.folder/'candidate.json').write_text(json.dumps({'image':release['runtime_image_id']}))
                # Last point to stop: install() starts with the backup and the container swap.
                self.check_cancel()
                self.install(release)
                installed.write_text(json.dumps({'version': release['version']}))
                try:
                    self.publish_rollback()
                except (OSError, ValueError):
                    pass
                try:
                    self.prune()
                except (OSError, ValueError):
                    (self.private / 'cleanup-needed').touch()
            except Exception as error:
                state = self.read_public('status.json')
                if journal_path.exists() and json.loads(journal_path.read_text()).get('phase') not in {'succeeded', 'rolled_back'}:
                    self.status('rollback', error='rollback_retry')
                    raise
                if state.get('phase') != 'rolled_back':
                    self.status('failed', error=error.code if isinstance(error, UpdateError) else 'update_failed')
            finally:
                (self.folder / 'image.tar.gz').unlink(missing_ok=True)
                if self.read_public('status.json').get('phase') in {'succeeded', 'rolled_back', 'failed'}:
                    self.discard_unneeded_backup()
                    try:
                        if self.read_public('status.json').get('phase')!='succeeded' and (self.folder/'candidate.json').exists():
                            self.retire_image(json.loads((self.folder/'candidate.json').read_text())['image'])
                        self.prune()
                    except (OSError,ValueError,UpdateError):
                        (self.private/'cleanup-needed').touch()
                    self.finish_request()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--rollback')
    parser.add_argument('--confirm')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    worker=Worker(config)
    if args.rollback:worker.enqueue_rollback(args.rollback,args.confirm)
    worker.run()


if __name__ == '__main__':
    main()
