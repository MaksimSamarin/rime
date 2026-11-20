import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from hy2bridge.provision import archive_image_candidates, Provisioner, ProvisionError
from hy2bridge.remote_install import resolve_image


class ImageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config=json.dumps({'architecture':'amd64','os':'linux','rootfs':{'diff_ids':[]}}).encode()
        self.expected='sha256:'+hashlib.sha256(self.config).hexdigest()
        self.manifest=json.dumps({'config':{'digest':self.expected},'layers':[]}).encode()
        self.platform='sha256:'+hashlib.sha256(self.manifest).hexdigest()
        self.path=Path(self.tmp.name)/'image.tar.gz'

    def archive(self, classic=False, wrong_config=False, corrupt_descriptor=False):
        config=b'{}' if wrong_config else self.config
        members={'config.json':config,'manifest.json':json.dumps([{'Config':'config.json'}]).encode()}
        if not classic:
            members['index.json']=json.dumps({'manifests':[
                {'digest':self.platform,'platform':{'architecture':'amd64','os':'linux'}},
                {'digest':'sha256:'+'f'*64,'platform':{'architecture':'arm64','os':'linux'}},
                {'digest':'sha256:'+'e'*64,'platform':{'architecture':'unknown','os':'unknown'}}]}).encode()
            members['blobs/sha256/'+self.platform.split(':')[1]]=b'{}' if corrupt_descriptor else self.manifest
        with tarfile.open(self.path,'w:gz') as archive:
            for name,raw in members.items():
                info=tarfile.TarInfo(name);info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_same_config_resolves_containerd_platform_manifest(self):
        checksum=self.archive()
        self.assertEqual(archive_image_candidates(self.path,checksum,self.expected),[self.platform])

    def test_nested_index_remains_bound_to_the_expected_config(self):
        index=json.dumps({'manifests':[{'digest':self.platform,'platform':{'architecture':'amd64','os':'linux'}}]}).encode()
        parent='sha256:'+hashlib.sha256(index).hexdigest()
        members={'manifest.json':json.dumps([{'Config':'config.json'}]).encode(),'config.json':self.config,
                 'index.json':json.dumps({'manifests':[{'digest':parent}]}).encode(),
                 'blobs/sha256/'+parent.split(':')[1]:index,
                 'blobs/sha256/'+self.platform.split(':')[1]:self.manifest}
        with tarfile.open(self.path,'w:gz') as archive:
            for name,raw in members.items():
                info=tarfile.TarInfo(name);info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
        checksum=hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(archive_image_candidates(self.path,checksum,self.expected),[self.platform,parent])

    def test_classic_archive_keeps_config_reference(self):
        checksum=self.archive(classic=True)
        self.assertEqual(archive_image_candidates(self.path,checksum,self.expected),[])

    def test_bundle_checksum_and_other_config_fail_closed(self):
        checksum=self.archive()
        with self.assertRaises(ProvisionError):archive_image_candidates(self.path,'0'*64,self.expected)
        checksum=self.archive(wrong_config=True)
        with self.assertRaises(ProvisionError):archive_image_candidates(self.path,checksum,self.expected)

    def test_corrupt_descriptor_is_rejected(self):
        checksum=self.archive(corrupt_descriptor=True)
        with self.assertRaises(ValueError):archive_image_candidates(self.path,checksum,self.expected)

    def test_classic_does_not_need_alias_and_containerd_uses_only_verified_digest(self):
        missing=subprocess.CompletedProcess([],1,'','Error: No such image')
        available=subprocess.CompletedProcess([],0,'[{}]','')
        with patch('hy2bridge.remote_install.subprocess.run',return_value=available) as run:
            self.assertEqual(resolve_image(self.expected,[self.platform]),self.expected)
            self.assertEqual(run.call_count,1)
        with patch('hy2bridge.remote_install.subprocess.run',side_effect=[missing,available]) as run:
            self.assertEqual(resolve_image(self.expected,[self.platform]),self.platform)
            self.assertEqual(run.call_args.args[0][-1],self.platform)

    def test_missing_image_is_distinct_from_unavailable_daemon(self):
        with patch('hy2bridge.remote_install.subprocess.run',return_value=subprocess.CompletedProcess([],1,'','No such image')):
            self.assertIsNone(resolve_image(self.expected,[self.platform]))
        with patch('hy2bridge.remote_install.subprocess.run',return_value=subprocess.CompletedProcess([],1,'','Cannot connect to Docker daemon')):
            with self.assertRaises(RuntimeError):resolve_image(self.expected,[self.platform])

    def test_mutable_tag_cannot_be_a_candidate(self):
        with self.assertRaises(ValueError):resolve_image(self.expected,['image:latest'])

    def test_remote_error_does_not_expose_remote_stderr(self):
        provision=object.__new__(Provisioner);provision.settings={}
        client=MagicMock();output=MagicMock()
        output.read.return_value=b'{"code":"image_unavailable","error":"secret-data"}'
        output.channel.recv_exit_status.return_value=1
        client.exec_command.return_value=(MagicMock(),output,io.BytesIO(b'password=secret'))
        with self.assertRaisesRegex(ProvisionError,'Docker') as caught:
            provision.remote(client,{'id':'a'*32})
        self.assertNotIn('secret',str(caught.exception))


if __name__=='__main__':unittest.main()
