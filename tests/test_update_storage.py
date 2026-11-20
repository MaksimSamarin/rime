import gzip
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from update_runtime.artifacts import new_layer_bytes
from update_runtime.releases import UpdateError


class UpdateStorageTests(unittest.TestCase):
    def archive(self, root):
        path = root/'image.tar.gz'
        contents = {'manifest.json':json.dumps([{'Config':'config.json','Layers':['old','new']}]).encode(),
                    'config.json':json.dumps({'rootfs':{'diff_ids':['old-id','new-id']}}).encode(),
                    'old':gzip.compress(b'a'*20000),'new':gzip.compress(b'b'*30000)}
        with tarfile.open(path,'w:gz') as archive:
            for name, body in contents.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info,io.BytesIO(body))
        return path

    def test_shared_layers_do_not_require_a_second_full_image_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(Path(directory))
            self.assertEqual(new_layer_bytes(path,{'old-id'},30000),30000)
            self.assertEqual(new_layer_bytes(path,set(),50000),50000)

    def test_compressed_layer_is_rejected_before_docker_exceeds_the_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(Path(directory))
            with self.assertRaises(UpdateError) as context:
                new_layer_bytes(path,{'old-id'},29999)
            self.assertEqual(context.exception.code,'insufficient_disk_space')
