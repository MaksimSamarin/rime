import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
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


if __name__ == '__main__':
    unittest.main()
