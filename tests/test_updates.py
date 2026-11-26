import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import time
import unittest
import urllib.request
from unittest.mock import patch

from hy2bridge.updates import Updates
from update_runtime.releases import REPOSITORY, ReleaseCatalog, UpdateError, version_key
from update_runtime.worker import Worker


def release():
    return {'id': '7', 'tag': 'v0.3.1', 'version': '0.3.1', 'notes': 'Release notes',
            'published_at': '2026-11-14T12:00:00Z', 'manifest_sha256': 'a' * 64,
            'revision': 'b' * 40, 'artifact': {'image_id': 'sha256:' + 'c' * 64,
                                           'sha256': 'd' * 64, 'size': 42,
                                           'url': 'https://github.com/MaksimSamarin/rime/releases/download/v0.3.1/rime-linux-amd64.tar.gz'}}


class Catalog:
    def latest(self):
        return release()

    def by_tag(self, tag):
        return {**release(), 'version': tag.removeprefix('v'), 'tag': tag}


class UpdateQueueTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.directory = self.root / '.updates'
        self.directory.mkdir()
        (self.directory / 'agent.json').write_text('{"protocol":1}')
        self.database = self.root / 'db.sqlite3'
        with sqlite3.connect(self.database) as database:
            database.execute('CREATE TABLE fleet_jobs(id TEXT,state TEXT)')
        self.updates = Updates(self.directory, '0.3.0', self.database, Catalog())

    def test_status_does_not_contact_github_or_return_private_metadata(self):
        (self.directory / 'status.json').write_text(json.dumps({'phase': 'failed', 'error': 'update_failed', 'environment': 'private-password'}))
        with patch.object(self.updates.catalog, 'latest', side_effect=AssertionError('Unexpected request')):
            status = self.updates.status()
        self.assertNotIn('private-password', json.dumps(status))
        self.assertIsNone(status['checked_at'])

    def test_button_check_reports_latest_ready_version(self):
        status = self.updates.check()
        self.assertTrue(status['available'])
        self.assertEqual(status['latest']['version'], '0.3.1')
        self.assertNotIn('artifact', status['latest'])

    def test_request_contains_only_release_identity(self):
        self.updates.enqueue('0.3.1')
        value = json.loads((self.directory / 'request.json').read_text())
        self.assertEqual(set(value), {'id', 'tag', 'release_id', 'manifest_sha256', 'requested_at'})
        self.assertEqual(value['release_id'], '7')

    def test_two_requests_cannot_start_concurrent_updates(self):
        self.updates.enqueue('0.3.1')
        with self.assertRaises(UpdateError) as context:
            self.updates.enqueue('0.3.2')
        self.assertEqual(context.exception.code, 'update_running')

    def test_active_node_installation_delays_panel_update(self):
        with sqlite3.connect(self.database) as database:
            database.execute("INSERT INTO fleet_jobs VALUES('job','running')")
        with self.assertRaises(UpdateError) as context:
            self.updates.enqueue('0.3.1')
        self.assertEqual(context.exception.code, 'node_operation_running')
        self.assertFalse((self.directory / 'request.json').exists())

    def test_missing_host_worker_is_reported_before_queueing(self):
        (self.directory / 'agent.json').unlink()
        with self.assertRaises(UpdateError) as context:
            self.updates.enqueue('0.3.1')
        self.assertEqual(context.exception.code, 'agent_unavailable')

    def test_expired_unclaimed_request_is_visible_as_failed(self):
        (self.directory / 'status.json').write_text(json.dumps({'phase': 'queued', 'updated_at': time.time() - 70}))
        status = self.updates.status()
        self.assertEqual(status['job']['error'], 'agent_unavailable')

    def test_version_comparison_preserves_current_candidate_installations(self):
        self.assertLess(version_key('0.2.0-rc6'), version_key('0.3.0'))
        self.assertLess(version_key('0.3.0-rc1'), version_key('0.3.0'))
        with self.assertRaises(UpdateError):
            self.updates.enqueue('0.2.0')


class UpdateControlTests(UpdateQueueTests):
    """Stop and rollback requests the panel queues for the host worker."""

    def job(self, phase, **fields):
        value = {'id': 'a' * 32, 'version': '0.3.1', 'phase': phase, 'updated_at': time.time(), **fields}
        (self.directory / 'status.json').write_text(json.dumps(value))
        return value

    def test_cancel_is_queued_only_before_the_backup(self):
        for phase in ['queued', 'checking', 'downloading']:
            with self.subTest(phase=phase):
                self.job(phase)
                (self.directory / 'cancel.json').unlink(missing_ok=True)
                self.assertTrue(self.updates.status()['cancellable'])
                status = self.updates.cancel()
                self.assertEqual(json.loads((self.directory / 'cancel.json').read_text())['id'], 'a' * 32)
                self.assertTrue(status['cancel_requested'])
                self.assertFalse(status['cancellable'])
        for phase in ['backup', 'installing', 'verifying', 'rollback', 'succeeded']:
            with self.subTest(phase=phase):
                self.job(phase)
                (self.directory / 'cancel.json').unlink(missing_ok=True)
                with self.assertRaises(UpdateError) as context:
                    self.updates.cancel()
                self.assertEqual(context.exception.code, 'update_not_cancellable')
                self.assertFalse((self.directory / 'cancel.json').exists())

    def offer(self, **fields):
        value = {'parent': 'b' * 32, 'version': '0.2.9', 'from': '0.3.0', 'published_at': time.time(), **fields}
        (self.directory / 'rollback.json').write_text(json.dumps(value))

    def test_rollback_offer_applies_only_to_the_running_version(self):
        self.assertIsNone(self.updates.status()['rollback'])
        self.offer()
        self.assertEqual(self.updates.status()['rollback'], {'version': '0.2.9'})
        self.offer(**{'from': '0.2.8'})
        self.assertIsNone(self.updates.status()['rollback'])
        self.offer(parent='short')
        self.assertIsNone(self.updates.status()['rollback'])

    def test_rollback_request_needs_confirmation_and_names_the_successful_job(self):
        self.offer()
        with self.assertRaises(UpdateError) as context:
            self.updates.enqueue_rollback('yes')
        self.assertEqual(context.exception.code, 'rollback_confirmation_required')
        status = self.updates.enqueue_rollback('rollback')
        request = json.loads((self.directory / 'request.json').read_text())
        self.assertEqual({key: request[key] for key in ['operation', 'parent', 'tag']},
                         {'operation': 'rollback', 'parent': 'b' * 32, 'tag': 'v0.2.9'})
        self.assertEqual(status['job']['operation'], 'rollback')
        self.assertEqual(status['job']['phase'], 'queued')

    def test_rollback_is_refused_without_offer_or_during_a_job(self):
        with self.assertRaises(UpdateError) as context:
            self.updates.enqueue_rollback('rollback')
        self.assertEqual(context.exception.code, 'rollback_not_available')
        self.offer()
        self.job('downloading')
        with self.assertRaises(UpdateError) as context:
            self.updates.enqueue_rollback('rollback')
        self.assertEqual(context.exception.code, 'update_running')
        self.assertFalse((self.directory / 'request.json').exists())


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        from update_runtime.signatures import sign_manifest,key_id
        import base64
        self.signing_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public=self.signing_key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.catalog = ReleaseCatalog('http://127.0.0.1:18088',allow_local=True,public_keys={key_id(public):base64.b64encode(public).decode()})
        artifact = {'name': 'rime-linux-amd64.tar.gz', 'sha256': 'a' * 64,
                    'image_id': 'sha256:' + 'b' * 64, 'size': 42}
        self.manifest = {'schema': 1, 'version': '0.3.1', 'repository': REPOSITORY,
                         'revision': 'c' * 40, 'artifacts': {'linux/amd64': artifact}}
        self.metadata = {'id': 7, 'tag_name': 'v0.3.1', 'assets': [
            {'name': 'rime-release.json', 'browser_download_url': 'https://github.com/MaksimSamarin/rime/releases/download/v0.3.1/rime-release.json'},
            {'name':'rime-release.sig','browser_download_url':'https://github.com/MaksimSamarin/rime/releases/download/v0.3.1/rime-release.sig'},
            {'name': artifact['name'], 'size': 42, 'browser_download_url': 'https://github.com/MaksimSamarin/rime/releases/download/v0.3.1/' + artifact['name']},
        ]}

    def signed_read(self,raw):
        from update_runtime.signatures import sign_manifest
        signature=sign_manifest(raw,self.signing_key)
        return [(self.manifest,raw),(signature,json.dumps(signature).encode())]

    def test_manifest_and_platform_are_verified(self):
        raw = json.dumps(self.manifest).encode()
        with patch.object(self.catalog, 'read_json', side_effect=self.signed_read(raw)):
            value = self.catalog.release(self.metadata, 'amd64')
        self.assertEqual(value['manifest_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(value['artifact']['size'], 42)

    def test_redirects_cannot_use_private_or_unrelated_download_hosts(self):
        for url in ['http://github.com/file', 'https://127.0.0.1/file', 'https://169.254.169.254/', 'https://example.org/image', 'https://user:password@github.com/file']:
            with self.subTest(url=url), self.assertRaises(UpdateError):
                self.catalog.validate_url(url)

    def test_manifest_for_another_repository_is_rejected(self):
        self.manifest['repository'] = 'other/repository'
        with patch.object(self.catalog, 'read_json', side_effect=self.signed_read(b'{}')):
            with self.assertRaises(UpdateError):
                self.catalog.release(self.metadata, 'amd64')

    def test_asset_digest_is_checked_before_loading_any_image(self):
        self.metadata['assets'][0]['digest'] = 'sha256:' + 'f' * 64
        with patch.object(self.catalog, 'read_json', side_effect=self.signed_read(b'{}')):
            with self.assertRaises(UpdateError) as context:
                self.catalog.release(self.metadata, 'amd64')
        self.assertEqual(context.exception.code, 'release_checksum_mismatch')

    def test_upstream_tags_and_unready_releases_do_not_offer_an_update(self):
        with patch.object(self.catalog, 'read_json', return_value=([{'tag_name': 'v0.8.4', 'assets': []}], b'[]')):
            self.assertIsNone(self.catalog.latest())


class WorkerBackupTests(unittest.TestCase):
    def restore_fixture(self,root):
        data=root/'data';data.mkdir()
        (data/'.updates').mkdir()
        database=data/'db.sqlite3'
        with sqlite3.connect(database) as connection:connection.execute('CREATE TABLE fixture(id INTEGER)')
        worker=Worker({'data_directory':str(data),'state_directory':str(root/'private'),'database':str(database)})
        worker.folder=worker.private/('a'*32);worker.folder.mkdir()
        return worker,data

    def test_restore_preserves_external_symlinks_without_writing_their_target(self):
        import tarfile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);worker,data=self.restore_fixture(root)
            outside=root/'outside.txt';outside.write_text('external fixture remains')
            (data/'certificate.link').symlink_to(outside)
            worker.backup()
            (data/'certificate.link').unlink();(data/'certificate.link').write_text('candidate change')
            (data/'candidate-only.key').write_text('candidate-only fixture')
            with tarfile.open(worker.folder/'data.tar.gz') as archive:worker.restore_files(archive)
            self.assertTrue((data/'certificate.link').is_symlink())
            self.assertEqual(outside.read_text(),'external fixture remains')
            self.assertFalse((data/'candidate-only.key').exists())
            self.assertTrue((data/'.updates').is_dir())

    def test_restore_replaces_an_escaping_candidate_directory_link(self):
        import shutil,tarfile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);worker,data=self.restore_fixture(root)
            (data/'nested').mkdir();(data/'nested'/'config.json').write_text('original configuration')
            worker.backup()
            shutil.rmtree(data/'nested')
            outside=root/'outside';outside.mkdir();(outside/'config.json').write_text('outside remains')
            (data/'nested').symlink_to(outside,target_is_directory=True)
            with tarfile.open(worker.folder/'data.tar.gz') as archive:worker.restore_files(archive)
            self.assertFalse((data/'nested').is_symlink())
            self.assertEqual((data/'nested'/'config.json').read_text(),'original configuration')
            self.assertEqual((outside/'config.json').read_text(),'outside remains')

    def test_private_file_ownership_survives_restore_for_nonroot_panels(self):
        import os,tarfile
        if os.geteuid()!=0:self.skipTest('Host ownership qualification requires root')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);worker,data=self.restore_fixture(root)
            key=data/'private.key';key.write_text('synthetic-existing-key');key.chmod(0o600);os.chown(key,1234,1234)
            worker.backup();key.unlink();key.write_text('candidate value')
            with tarfile.open(worker.folder/'data.tar.gz') as archive:worker.restore_files(archive)
            self.assertEqual(key.read_text(),'synthetic-existing-key')
            self.assertEqual((key.stat().st_uid,key.stat().st_gid,key.stat().st_mode&0o777),(1234,1234,0o600))

    def test_restore_detaches_candidate_hardlinks_and_restores_original_links(self):
        import os,tarfile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);worker,data=self.restore_fixture(root)
            original=data/'original.key';original.write_text('original fixture')
            os.link(original,data/'alias.key')
            worker.backup()
            outside=root/'outside.key';outside.write_text('outside remains')
            original.unlink();os.link(outside,original)
            with tarfile.open(worker.folder/'data.tar.gz') as archive:worker.restore_files(archive)
            self.assertEqual(outside.read_text(),'outside remains')
            self.assertEqual(original.read_text(),'original fixture')
            self.assertEqual(original.stat().st_ino,(data/'alias.key').stat().st_ino)

    def test_consistent_sqlite_and_data_are_backed_up_without_recursive_update_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'data'
            data.mkdir()
            queue = data / '.updates'
            queue.mkdir()
            (queue / 'request.json').write_text('{}')
            (data / 'identity.key').write_text('synthetic-preserved-key')
            database = data / 'db.sqlite3'
            with sqlite3.connect(database) as connection:
                connection.execute('CREATE TABLE users(uuid TEXT)')
                connection.execute("INSERT INTO users VALUES('synthetic-existing-uuid')")
            worker = Worker({'data_directory': str(data), 'state_directory': str(root / 'private'),
                             'database': str(database), 'container': 'synthetic-panel', 'current_version': '0.3.0'})
            worker.folder = worker.private / ('a' * 32)
            worker.folder.mkdir()
            worker.backup()
            with sqlite3.connect(worker.folder / 'database.sqlite3') as connection:
                self.assertEqual(connection.execute('SELECT uuid FROM users').fetchone()[0], 'synthetic-existing-uuid')
            import tarfile
            with tarfile.open(worker.folder / 'data.tar.gz') as archive:
                self.assertNotIn('data/.updates/request.json', archive.getnames())
                self.assertIn('data/identity.key', archive.getnames())


class Response:
    """Scripted download response: serves `body` from `start`, then ends early or raises."""
    def __init__(self, body, status=200, content_range=None, stop_after=None, error=None):
        self.body, self.status, self.position = body, status, 0
        self.headers = {'Content-Range': content_range} if content_range else {}
        self.stop_after, self.error = stop_after, error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getcode(self):
        return self.status

    def read(self, amount):
        limit = len(self.body) if self.stop_after is None else self.stop_after
        if self.position >= limit:
            if self.error is not None:
                raise self.error
            return b''
        block = self.body[self.position:min(self.position + amount, limit)]
        self.position += len(block)
        return block


class DownloadCatalog:
    def __init__(self, answers):
        self.answers, self.ranges = list(answers), []

    def open(self, url, headers=None):
        self.ranges.append((headers or {}).get('Range'))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


class WorkerDownloadTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        (root / 'data').mkdir()
        self.data = os.urandom(3 * 1024 * 1024 + 123)
        self.artifact = {'url': 'https://github.com/MaksimSamarin/rime/releases/download/v0.3.1/rime-linux-amd64.tar.gz',
                         'size': len(self.data), 'sha256': hashlib.sha256(self.data).hexdigest()}
        self.path = root / 'image.tar.gz'
        self.config = {'data_directory': str(root / 'data'), 'state_directory': str(root / 'private'),
                       'database': str(root / 'data' / 'db.sqlite3'), 'download_retry_delay': 0, 'download_retries': 2,
                       # Queue files are chowned to the panel user; CI runs unprivileged.
                       'panel_uid': os.getuid(), 'panel_gid': os.getgid()}
        self.statuses = []

    def worker(self, answers):
        catalog = DownloadCatalog(answers)
        worker = Worker(self.config, docker=object(), catalog=catalog)
        worker.status = lambda phase, **fields: self.statuses.append((phase, fields))
        return worker, catalog

    def rest(self, start, **extra):
        return Response(self.data[start:], 206, 'bytes %d-%d/%d' % (start, len(self.data) - 1, len(self.data)), **extra)

    def test_dropped_download_resumes_from_the_received_bytes(self):
        cut = 1024 * 1024 + 7
        worker, catalog = self.worker([Response(self.data, stop_after=cut), self.rest(cut)])
        worker.fetch(self.artifact, self.path)
        self.assertEqual(self.path.read_bytes(), self.data)
        self.assertEqual(catalog.ranges, [None, 'bytes=%d-' % cut])
        self.assertEqual(self.statuses[-1], ('downloading', {'progress': 100, 'retries': 1}))

    def test_read_timeout_and_reset_are_resumed(self):
        first, second = 1024 * 1024, 2 * 1024 * 1024
        worker, catalog = self.worker([
            Response(self.data, stop_after=first, error=socket.timeout('timed out')),
            self.rest(first, stop_after=second - first, error=ConnectionResetError()),
            UpdateError('release_unavailable'),
            self.rest(second),
        ])
        worker.fetch(self.artifact, self.path)
        self.assertEqual(self.path.read_bytes(), self.data)
        self.assertEqual(catalog.ranges, [None, 'bytes=%d-' % first, 'bytes=%d-' % second, 'bytes=%d-' % second])

    def test_server_that_ignores_range_restarts_from_the_first_byte(self):
        worker, catalog = self.worker([Response(self.data, stop_after=500000), Response(self.data)])
        worker.fetch(self.artifact, self.path)
        self.assertEqual(self.path.read_bytes(), self.data)

    def test_range_for_another_offset_is_not_appended(self):
        cut = 1024 * 1024
        worker, _ = self.worker([Response(self.data, stop_after=cut), self.rest(cut + 10), self.rest(cut)])
        worker.fetch(self.artifact, self.path)
        self.assertEqual(self.path.read_bytes(), self.data)

    def test_resumed_bytes_are_still_checked_against_the_release_digest(self):
        cut = 1024 * 1024
        forged = Response(b'x' * (len(self.data) - cut), 206, 'bytes %d-%d/%d' % (cut, len(self.data) - 1, len(self.data)))
        worker, _ = self.worker([Response(self.data, stop_after=cut), forged])
        with self.assertRaises(UpdateError) as context:
            worker.fetch(self.artifact, self.path)
        self.assertEqual(context.exception.code, 'release_checksum_mismatch')

    def test_download_without_progress_stops_after_the_retry_limit(self):
        worker, catalog = self.worker([UpdateError('release_unavailable')] * 3)
        with self.assertRaises(UpdateError) as context:
            worker.fetch(self.artifact, self.path)
        self.assertEqual(context.exception.code, 'release_unavailable')
        self.assertEqual(len(catalog.ranges), 3)

    def test_oversized_answer_is_rejected(self):
        worker, _ = self.worker([Response(self.data + b'extra')])
        with self.assertRaises(UpdateError) as context:
            worker.fetch(self.artifact, self.path)
        self.assertEqual(context.exception.code, 'release_checksum_mismatch')

    def job_worker(self, answers=()):
        worker, catalog = self.worker(list(answers))
        worker.public.mkdir(exist_ok=True)
        worker.job = {'id': 'c' * 32, 'tag': 'v0.9.5', 'requested_at': time.time()}
        return worker, catalog

    def test_cancel_request_stops_the_download_of_this_job(self):
        class CancellingResponse(Response):
            def __init__(self, body, public):
                super().__init__(body)
                self.public = public

            def read(self, amount):
                if self.position:
                    (self.public / 'cancel.json').write_text(json.dumps({'id': 'c' * 32}))
                return super().read(amount)
        worker, catalog = self.job_worker()
        catalog.answers = [CancellingResponse(self.data, worker.public)]
        with self.assertRaises(UpdateError) as context:
            worker.fetch(self.artifact, self.path)
        self.assertEqual(context.exception.code, 'update_cancelled')
        self.assertLess(self.path.stat().st_size, len(self.data))

    def test_cancel_for_another_job_is_ignored_and_cleared(self):
        worker, _ = self.job_worker([Response(self.data)])
        (worker.public / 'cancel.json').write_text(json.dumps({'id': 'd' * 32}))
        worker.fetch(self.artifact, self.path)
        self.assertEqual(self.path.read_bytes(), self.data)
        worker.clear_cancel(stale_only=True)
        self.assertFalse((worker.public / 'cancel.json').exists())
        (worker.public / 'cancel.json').write_text(json.dumps({'id': 'c' * 32}))
        worker.clear_cancel(stale_only=True)
        self.assertTrue((worker.public / 'cancel.json').exists())

    def test_successful_job_offers_the_version_it_replaced(self):
        worker, _ = self.job_worker()
        with patch.object(worker, 'manual_release', return_value={'version': '0.9.4'}) as release:
            offer = worker.publish_rollback()
        release.assert_called_once_with('c' * 32)
        stored = json.loads((worker.public / 'rollback.json').read_text())
        self.assertEqual({key: stored[key] for key in ['parent', 'version', 'from']},
                         {'parent': 'c' * 32, 'version': '0.9.4', 'from': '0.9.5'})
        self.assertEqual(offer['version'], '0.9.4')
        with patch.object(worker, 'manual_release', side_effect=UpdateError('rollback_schema_incompatible')):
            self.assertIsNone(worker.publish_rollback())
        self.assertFalse((worker.public / 'rollback.json').exists())

    def test_cancel_before_checking_ends_the_job_without_contacting_github(self):
        worker, catalog = self.job_worker()
        job = worker.job
        (worker.public / 'request.json').write_text(json.dumps({**job, 'release_id': '7', 'manifest_sha256': 'a' * 64}))
        (worker.public / 'cancel.json').write_text(json.dumps({'id': job['id']}))
        (worker.public / 'status.json').write_text(json.dumps({'id': job['id'], 'version': '0.9.5', 'phase': 'queued'}))
        del worker.status
        worker.run()
        status = json.loads((worker.public / 'status.json').read_text())
        self.assertEqual((status['phase'], status['error']), ('failed', 'update_cancelled'))
        self.assertEqual(catalog.ranges, [])
        self.assertFalse((worker.public / 'request.json').exists())
        self.assertFalse((worker.public / 'cancel.json').exists())

    def test_range_header_survives_the_github_redirect(self):
        catalog = ReleaseCatalog()
        handler = next(item for item in catalog.opener.handlers if type(item).__name__ == 'SafeRedirect')
        request = urllib.request.Request(self.artifact['url'], headers={'Range': 'bytes=10-'})
        target = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sig=x'
        redirected = handler.redirect_request(request, None, 302, 'Found', {}, target)
        self.assertEqual(redirected.get_header('Range'), 'bytes=10-')


if __name__ == '__main__':
    unittest.main()
