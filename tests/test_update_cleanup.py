from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from update_runtime.worker import Worker


class UpdateCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root=Path(temporary.name)
        (root/'data').mkdir()
        self.docker=Mock()
        self.worker=Worker({'data_directory':str(root/'data'),'state_directory':str(root/'private')},docker=self.docker)
        self.worker.folder=self.worker.private/('a'*32)
        self.worker.folder.mkdir()

    def image(self):
        return {'Config':{'Labels':{'org.opencontainers.image.source':'https://github.com/MaksimSamarin/rime',
                                  'org.opencontainers.image.version':'0.9.0'}},'RepoTags':['rime:0.9.0']}

    def test_partial_backup_is_removed_when_cutover_never_started(self):
        for name in ['data.tar.gz','database.sqlite3','database-mode.json']:(self.worker.folder/name).write_text('partial fixture')
        self.worker.discard_unneeded_backup()
        self.assertEqual(list(self.worker.folder.iterdir()),[])

    def test_cutover_journal_keeps_its_recovery_files(self):
        (self.worker.folder/'journal.json').write_text('{}')
        (self.worker.folder/'database.sqlite3').write_text('preserve fixture')
        self.worker.discard_unneeded_backup()
        self.assertTrue((self.worker.folder/'database.sqlite3').exists())

    def test_unrelated_images_are_never_retired(self):
        image=self.image();image['Config']['Labels']['org.opencontainers.image.source']='https://example.invalid/another-project'
        self.docker.request.return_value=image
        self.worker.retire_image('sha256:fixture')
        self.assertEqual(self.docker.request.call_count,1)

    def test_an_image_referenced_by_a_container_is_preserved(self):
        self.docker.request.side_effect=[self.image(),[{'Id':'running-or-stopped-owner'}]]
        self.worker.retire_image('sha256:fixture')
        self.assertFalse(any(call.args[0]=='DELETE' for call in self.docker.request.call_args_list))

    def test_only_the_owned_unused_version_tag_is_removed(self):
        self.docker.request.side_effect=[self.image(),[],None]
        self.worker.retire_image('sha256:fixture')
        deletion=self.docker.request.call_args_list[-1]
        self.assertEqual(deletion.args,('DELETE','/images/rime%3A0.9.0?force=false'))
