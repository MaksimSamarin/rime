"""Regression cases for updater audit findings, using synthetic local state."""
import base64
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from update_runtime.releases import UpdateError
from update_runtime.worker import Worker


class UpdateAuditTests(unittest.TestCase):
    def test_unsigned_manifest_is_not_a_release(self):
        from update_runtime.releases import ReleaseCatalog,REPOSITORY
        manifest={'schema':1,'repository':REPOSITORY,'version':'0.9.1','revision':'a'*40,
            'artifacts':{'linux/amd64':{'name':'rime-linux-amd64.tar.gz','sha256':'b'*64,
                                      'image_id':'sha256:'+'c'*64,'size':42}}}
        metadata={'id':1,'tag_name':'v0.9.1','assets':[
            {'name':'rime-release.json','browser_download_url':'https://github.com/MaksimSamarin/rime/releases/download/v0.9.1/rime-release.json'},
            {'name':'rime-linux-amd64.tar.gz','size':42,'browser_download_url':'https://github.com/MaksimSamarin/rime/releases/download/v0.9.1/rime-linux-amd64.tar.gz'}]}
        catalog=ReleaseCatalog()
        with patch.object(catalog,'read_json',return_value=(manifest,json.dumps(manifest).encode())):
            with self.assertRaises(UpdateError):catalog.release(metadata,'amd64')

    def test_installer_resolves_full_compose_id_to_container_name(self):
        from scripts.install_updater import container_name
        self.assertEqual(container_name({'Id':'a'*64,'Name':'/rime-panel'}),'rime-panel')
        with self.assertRaises(SystemExit):
            container_name({'Name':'/'+'a'*64})

    def test_update_directory_never_contains_non_sqlite_credentials(self):
        from update_runtime.paths import update_directory, sqlite_database
        url='mysql+pymysql://private_user:private_password@db/private'
        self.assertIsNone(sqlite_database(url))
        self.assertNotIn('private_password',str(update_directory(url,{})))
        self.assertNotIn('mysql',str(update_directory(url,{})))
        with self.assertRaises(ValueError):update_directory(url,{'RIME_UPDATE_DIRECTORY':'relative'})

    def test_relative_sqlite_requires_an_explicit_persistent_update_directory(self):
        from update_runtime.paths import update_directory
        self.assertEqual(str(update_directory('sqlite:///relative.db',{})),'/var/lib/marzban/.updates')
        self.assertEqual(str(update_directory('sqlite:////var/lib/rime/database.sqlite3',{})),'/var/lib/rime/.updates')

    def test_manifest_signature_rejects_tampering_and_foreign_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        from update_runtime.signatures import verify_signature,sign_manifest
        key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
        raw=b'{"version":"0.9.1"}'
        envelope=sign_manifest(raw,key)
        verify_signature(raw,envelope,{envelope['key_id']:public})
        with self.assertRaises(UpdateError):verify_signature(raw+b' ',envelope,{envelope['key_id']:public})
        with self.assertRaises(UpdateError):verify_signature(raw,envelope,{})

    def test_distribution_host_verifies_ed25519_with_openssl_without_python_crypto(self):
        import builtins,shutil
        if not shutil.which('openssl'):self.skipTest('OpenSSL is unavailable')
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        from update_runtime.signatures import verify_signature,sign_manifest
        key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
        raw=b'closed signed manifest';signature=sign_manifest(raw,key)
        original=builtins.__import__
        def without_crypto(name,*args,**kwargs):
            if name=='cryptography.hazmat.primitives.asymmetric.ed25519':raise ImportError('Fixture system Python')
            return original(name,*args,**kwargs)
        with patch('builtins.__import__',side_effect=without_crypto):
            verify_signature(raw,signature,{signature['key_id']:public})
            with self.assertRaises(UpdateError):verify_signature(raw+b'tampered',signature,{signature['key_id']:public})

    def test_container_environment_preserves_only_operator_overrides(self):
        from update_runtime.worker import replacement_configuration
        previous={'Config':{'Env':['PATH=/old','PYTHON_VERSION=3.10','MODE=default'],'Labels':{} }}
        candidate={'Config':{'Env':['PATH=/new','PYTHON_VERSION=3.12','MODE=new-default'],'Labels':{}}}
        old={'Env':['PATH=/old','PYTHON_VERSION=3.10','MODE=custom','OPERATOR=kept'],
             'Labels':{'com.docker.compose.project':'old','operator.label':'kept'}}
        value=replacement_configuration(old,previous,candidate)
        env=dict(item.split('=',1) for item in value['Env'])
        self.assertEqual(env,{'PATH':'/new','PYTHON_VERSION':'3.12','MODE':'custom','OPERATOR':'kept'})
        self.assertNotIn('com.docker.compose.project',value['Labels'])
        self.assertEqual(value['Labels']['operator.label'],'kept')

    def test_allocation_preserves_minimum_disk_reserve(self):
        from update_runtime.worker import available_for_update
        usage=type('Usage',(),{'total':20*1024**3,'free':3*1024**3})()
        with patch('update_runtime.worker.shutil.disk_usage',return_value=usage):
            self.assertEqual(available_for_update(Path('/tmp'),{}),1024**3)
            with self.assertRaises(UpdateError):available_for_update(Path('/tmp'),{'minimum_free_bytes':4*1024**3})

    def test_backup_cannot_leave_only_thirty_megabytes_free(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);data=root/'data';data.mkdir();(data/'.updates').mkdir()
            database=data/'db.sqlite3'
            with sqlite3.connect(database) as db:db.execute('CREATE TABLE fixture(id INTEGER)')
            worker=Worker({'data_directory':str(data),'state_directory':str(root/'state'),'database':str(database),'container':'rime'})
            worker.folder=worker.private/('a'*32);worker.folder.mkdir()
            usage=type('Usage',(),{'total':20*1024**3,'free':35*1024**2})()
            with patch('update_runtime.worker.shutil.disk_usage',return_value=usage):
                with self.assertRaises(UpdateError):worker.backup()

    def test_abandoned_cutover_marker_blocks_new_mutations(self):
        from update_runtime.leases import acquire
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'.cutover.json').write_text('{"id":"abandoned-worker"}')
            blocked=False
            try:descriptor=acquire(folder)
            except BlockingIOError:blocked=True
            else:os.close(descriptor)
            self.assertTrue(blocked,'A dead worker must not release the durable mutation barrier')

    def test_persisted_barrier_survives_missing_worker_lock(self):
        from update_runtime.leases import acquire,set_barrier,clear_barrier
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'.cutover.json').write_text(json.dumps({'id':'a'*32}))
            with self.assertRaises(BlockingIOError):acquire(directory)
            descriptor=acquire(directory,exclusive=True);os.close(descriptor)
            clear_barrier(directory,'b'*32)
            with self.assertRaises(BlockingIOError):acquire(directory)
            clear_barrier(directory,'a'*32)
            descriptor=acquire(directory);os.close(descriptor)

    def test_legacy_downgrade_is_refused_with_cumulative_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);data=root/'data';data.mkdir();(data/'.updates').mkdir()
            database=data/'db.sqlite3'
            with sqlite3.connect(database) as db:
                db.execute('CREATE TABLE fleet_native_usage_cursors(node_id INTEGER)')
                db.execute('INSERT INTO fleet_native_usage_cursors VALUES(1)')
            worker=Worker({'data_directory':str(data),'state_directory':str(root/'state'),
                           'database':str(database),'container':'rime'})
            with self.assertRaises(UpdateError) as error:worker.require_rollback_compatible('0.2.0-rc6')
            self.assertEqual(error.exception.code,'downgrade_requires_preparation')
            worker.require_rollback_compatible('0.9.0')

    def test_downgrade_handover_does_not_recharge_cumulative_bytes(self):
        from types import SimpleNamespace
        from test_native_usage_cursors import NativeUsageCursorTests
        import importlib.util
        spec=importlib.util.spec_from_file_location('downgrade_fixture',Path(__file__).resolve().parents[1]/'app/utils/downgrade.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        handover=module.handover
        fixture=NativeUsageCursorTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.collect()
        self.assertEqual(fixture.row('User')['used_traffic'],120)
        node=SimpleNamespace(api=fixture.api,usage_coefficient=1)
        def restart(ident,node):
            node.api.epoch='core-after-handover'
            node.api.users=[('1.alice','uplink',0),('1.alice','downlink',0)]
        result=handover({5:node},lambda api,ident,kind,factor:
            fixture.module.record_native_usage(api,ident,kind,coefficient=factor),restart)
        self.assertNotEqual(result[0]['old_epoch'],result[0]['new_epoch'])
        node.api.users=[('1.alice','uplink',5)]
        # The legacy collector receives only bytes since the freshly verified
        # core epoch, not the 120 bytes accepted before maintenance.
        old_collector_total=sum(stat.value for stat in node.api.get_users_stats(reset=True,timeout=1))
        self.assertEqual(fixture.row('User')['used_traffic']+old_collector_total,125)

    def test_release_workflow_pins_actions_and_publishes_only_complete_draft(self):
        import re
        source=(Path(__file__).resolve().parents[1]/'.github/workflows/release.yml').read_text()
        workflows=Path(__file__).resolve().parents[1]/'.github/workflows'
        uses=re.findall(r'uses:\s*([^\s]+)','\n'.join(p.read_text() for p in workflows.glob('*.yml')))
        self.assertTrue(uses)
        self.assertTrue(all(re.fullmatch(r'actions/[a-z-]+@[a-f0-9]{40}',value) for value in uses))
        self.assertIn('--draft --verify-tag',source)
        self.assertLess(source.index('dist/rime-release.sig --clobber'),source.index('dist/rime-release.json --clobber'))
        self.assertLess(source.index('dist/rime-release.json --clobber'),source.index('--draft=false'))

    def test_manual_rollback_checks_current_container_and_schema_before_replacement(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);data=root/'data';data.mkdir();(data/'.updates').mkdir()
            database=data/'db.sqlite3'
            with sqlite3.connect(database) as db:
                db.execute('CREATE TABLE alembic_version(version_num TEXT)');db.execute("INSERT INTO alembic_version VALUES('old-head')")
            docker=Mock();docker.inspect.return_value={'Id':'current'};docker.request.return_value={'Id':'previous-image'}
            worker=Worker({'data_directory':str(data),'state_directory':str(root/'state'),
                           'database':str(database),'container':'rime'},docker=docker)
            parent=worker.private/('a'*32);parent.mkdir()
            state={'phase':'succeeded','new_id':'current','old_version':'0.9.0',
                   'old':{'Image':'previous-image'},'database_revisions':['old-head']}
            (parent/'journal.json').write_text(json.dumps(state))
            self.assertTrue(worker.manual_release('a'*32)['manual'])
            docker.request.reset_mock()
            with sqlite3.connect(database) as db:db.execute("UPDATE alembic_version SET version_num='new-head'")
            with self.assertRaises(UpdateError) as error:worker.manual_release('a'*32)
            self.assertEqual(error.exception.code,'rollback_schema_incompatible');docker.request.assert_not_called()
            docker.inspect.return_value={'Id':'another-panel'}
            with self.assertRaises(UpdateError) as error:worker.manual_release('a'*32)
            self.assertEqual(error.exception.code,'rollback_not_current')


if __name__=='__main__':unittest.main()
