from pathlib import Path
from types import SimpleNamespace
import hashlib,json,tempfile,unittest
from unittest.mock import patch
from hy2bridge import remote_install


class RemoteObserverTests(unittest.TestCase):
    def test_repeated_setup_reuses_only_owned_observer_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);job='d'*32;directory=root/'.local/share/fleet-nodes'/job;directory.mkdir(parents=True)
            files={'config.json':'{}','observer.py':'# test only'};digest=hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()
            main={'Config':{'Labels':{'fleet.job':job}},'State':{'Running':True}}
            observer={'Config':{'Labels':{'fleet.job':job,'fleet.observer.config':digest}},'State':{'Running':True}}
            created=[]
            def run(args):
                if args[:2]==['docker','inspect']:return json.dumps([main if args[2]=='fleet-'+job else observer])
                if args[:2]==['docker','run']:created.append(args);return 'test-container'
                raise AssertionError(args)
            def inspect(args,**kwargs):return SimpleNamespace(returncode=0 if created else 1,stdout=json.dumps([observer]) if created else '')
            config={'action':'observer','id':job,'files':files,'image':'node@sha256:'+'0'*64}
            with patch.object(Path,'home',return_value=root),patch.object(remote_install,'run',side_effect=run),patch.object(remote_install.subprocess,'run',side_effect=inspect),patch.object(remote_install.os,'getuid',return_value=1000,create=True),patch.object(remote_install.os,'getgid',return_value=1000,create=True):
                self.assertFalse(remote_install.main(config)['already_configured'])
                self.assertTrue(remote_install.main(config)['already_configured'])
                self.assertEqual(len(created),1)
                self.assertIn('container:fleet-'+job,created[0])
                self.assertTrue(any('/proc/meminfo' in arg for arg in created[0]))
                with self.assertRaises(RuntimeError):remote_install.main({**config,'files':{**files,'config.json':'{"different":true}'}})
            self.assertEqual(len(created),1)
