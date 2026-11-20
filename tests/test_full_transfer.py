import hashlib
import importlib.util
import json
import os
from pathlib import Path
import time
import unittest
import threading
import types
from unittest.mock import MagicMock,patch

import test_transfer
from hy2bridge.provision import Provisioner,ProvisionError
from hy2bridge.proxy_service import ProxyService
from hy2bridge.transfer import NodeTransfer


class FullTransferTests(unittest.TestCase):
    tearDown=test_transfer.TransferTests.tearDown
    engine=test_transfer.TransferTests.engine

    def setUp(self):
        test_transfer.TransferTests.setUp(self)
        with self.store.connection(write=True) as db:
            db.execute('DROP TABLE fleet_proxy_services')
            db.execute("INSERT INTO hosts VALUES(3,'Split','old.example',2053,'SPLIT')")
            db.execute("INSERT INTO fleet_host_nodes VALUES(3,'xray:1')")
        bundle=Path(self.tmp.name)/'proxy.tar.gz';bundle.write_bytes(b'synthetic')
        self.base.settings['proxy']={'image':'sha256:'+'1'*64,'image_bundle':str(bundle),'image_bundle_sha256':'2'*64}
        self.proxies=ProxyService(self.store,self.base)
        self.recovery=self.proxies.recovery
        self.transfer=NodeTransfer(self.base,self.operations,self.probe,self.life,self.recovery,self.proxies)
        self.transfer.reconnect=MagicMock()
        vpn={'protocol':'vless','config':{'inbounds':[
            {'tag':'VLESS_TEST','protocol':'vless','port':16443,'settings':{'decryption':'none'},'streamSettings':{'network':'grpc'}},
            {'tag':'SPLIT','protocol':'vless','port':16444,'settings':{'decryption':'none'},'streamSettings':{'network':'xhttp','xhttpSettings':{'path':'/preserve','extra':{'noGRPCHeader':True}}}}],
            'outbounds':[{'protocol':'freedom','tag':'DIRECT'}]}}
        self.recovery.remember_vpn('xray:1',vpn)
        self.identity='b'*32
        _,generation=self.proxies.node_identity('xray:1')
        config={'files':{'squid.conf':'http_port 3128\n','passwd':'original:original-hash\nsecond:second-hash\n'},'publish':[[3128,3128]]}
        with self.store.connection(write=True) as db:
            self.proxies.write_job(db,self.identity,'xray:1','succeeded','Original')
            db.execute('''INSERT INTO fleet_proxy_services(id,node,host,address,domain,http_port,https_port,username,
                password_hash,created_at,checked_at,result,active,node_generation,password_secret,legacy_squid)
                VALUES(?,'xray:1','1.1.1.1','1.1.1.1','old.example',3128,NULL,'original','original-hash',1,1,'{}',1,?, ?,0)''',
                (self.identity,generation,self.proxies.encrypted_password(self.identity,'original-secret')))
            self.recovery.remember_proxy('xray:1',self.identity,config,'old.example',db)

    def data(self):
        profile=self.transfer.prepare_profile('xray:1')
        value=test_transfer.TransferTests.data(self)
        value['_profile']=profile
        value['_proxy_probes']={self.identity:{'runtime_id':'c'*32,'username':'original','password':'temporary'}}
        self.transfer.install_proxies=MagicMock()
        return value

    def test_restored_observer_checks_primary_internal_vpn_port_instead_of_new_node_template(self):
        self.base.settings['vless_template'].update(image='node@sha256:'+'0'*64,inbound_port=443)
        data=self.data();data['vpn_port']=2053
        before=json.dumps(data['_profile'],sort_keys=True)
        result=self.transfer.observer_configuration('a'*32,data,'token'*12,{'node':'xray:1'})
        self.assertEqual(json.loads(result['files']['config.json'])['vpn_port'],16444)
        self.assertEqual(json.dumps(data['_profile'],sort_keys=True),before)
        self.assertEqual(self.base.settings['vless_template']['inbound_port'],443)

    def test_restored_observer_uses_container_port_when_public_port_differs(self):
        self.base.settings['vless_template'].update(image='node@sha256:'+'0'*64,inbound_port=443)
        data=self.data();data['vpn_port']=2053
        data['_profile']['vpn']['publish']=[[2053,18443,'tcp'],[443,443,'udp']]
        result=self.transfer.observer_configuration('a'*32,data,'token'*12,{'node':'xray:1'})
        self.assertEqual(json.loads(result['files']['config.json'])['vpn_port'],18443)
        data['vpn_port']=8443
        with self.assertRaises(ProvisionError):
            self.transfer.observer_configuration('a'*32,data,'token'*12,{'node':'xray:1'})

    def test_composite_snapshot_accepts_custom_transport_and_preserves_all_proxy_access(self):
        data=self.data()
        before=self.proxies.connection_info(self.identity)
        self.transfer.register_node('a'*32,data,'new-token'*8)
        with self.store.connection() as db:
            row=db.execute('SELECT * FROM fleet_proxy_services WHERE id=?',(self.identity,)).fetchone()
            self.assertEqual(row['runtime_id'],'c'*32)
            self.assertEqual(row['address'],'8.8.4.4')
            self.assertEqual(self.proxies.clear_password(dict(row)),'original-secret')
        with self.assertRaises(ProvisionError):self.proxies.connection_info(self.identity)
        data['_proxy_results']={self.identity:{'passed':True,'checks':[]}}
        self.transfer.accept_node('a'*32,data)
        self.assertEqual(self.proxies.connection_info(self.identity)['urls'],before['urls'])
        self.assertEqual(self.recovery.load('xray:1')['proxies'][self.identity]['files']['passwd'],
                         'original:original-hash\nsecond:second-hash\n')

    def test_saved_hy2_and_vless_options_require_no_connection_to_the_lost_source(self):
        self.operations.ensure_node('lost-hy2','Lost Hy2',address='192.0.2.1')
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_managed(id,protocol,name,domain,port,active) VALUES('lost-hy2','hysteria2','Lost Hy2','hy2.example',443,1)")
        vpn={'protocol':'hysteria2','config':{'listen':':24443','tls':{'cert':'/state/cert.pem','key':'/state/key.pem'},'auth':{'type':'http','http':{'url':'http://127.0.0.1:18081/auth'}}},'certificate':'saved-cert','certificate_key':'saved-private-key'}
        self.recovery.remember_vpn('lost-hy2',vpn)
        self.base.connect=MagicMock(side_effect=AssertionError('The lost source cannot be contacted'))
        self.operations.native_probe=MagicMock(side_effect=AssertionError('No live source probe'))
        for node,protocol in [('lost-hy2','hysteria2'),('xray:1','vless')]:
            options=self.transfer.options_for(node)
            self.assertEqual(options['protocol'],protocol)
            self.assertTrue(options['recovery']['available'])
        self.base.connect.assert_not_called()
        self.assertEqual(self.recovery.load('lost-hy2')['vpn'],vpn)

    def test_proxy_and_generation_rollback_restore_the_same_vault_envelope(self):
        data=self.data()
        with self.store.connection() as db:
            before=dict(db.execute('SELECT * FROM fleet_proxy_services WHERE id=?',(self.identity,)).fetchone())
            generation=tuple(db.execute('SELECT * FROM fleet_proxy_node_generations').fetchone())
        self.transfer.register_node('a'*32,data,'new-token'*8)
        self.transfer.restore_node('a'*32,{})
        with self.store.connection() as db:
            self.assertEqual(dict(db.execute('SELECT * FROM fleet_proxy_services WHERE id=?',(self.identity,)).fetchone()),before)
            self.assertEqual(tuple(db.execute('SELECT * FROM fleet_proxy_node_generations').fetchone()),generation)

    def test_port_conflict_between_a_restored_vpn_and_proxy_is_rejected(self):
        data=self.data()
        self.assertIn((2053,'tcp'),self.transfer.required_ports(data))
        self.assertIn((3128,'tcp'),self.transfer.required_ports(data))
        data['_profile']['proxies'][self.identity]['publish']=[[443,8443]]
        with self.assertRaises(ProvisionError):self.transfer.required_ports(data)

    def test_cleanup_targets_only_recorded_proxy_runtime_ids(self):
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO fleet_transfer_components VALUES(?,'proxy',?)",('a'*32,'c'*32))
        self.proxies.remote=MagicMock()
        with patch.object(Provisioner,'remote',return_value={'removed':True}):
            self.transfer.remote(MagicMock(),{'id':'a'*32,'action':'rollback'})
        self.assertEqual(self.proxies.remote.call_args.args[1],{'id':'c'*32,'action':'rollback','transfer_id':'a'*32})

    def test_older_saved_proxy_profile_gets_an_idempotent_writable_pid_path(self):
        first=self.transfer.prepare_profile('xray:1')
        config=first['proxies'][self.identity]['files']['squid.conf']
        self.assertEqual(config.count('pid_filename /run/squid/squid.pid'),1)
        self.assertEqual(self.transfer.prepare_profile('xray:1'),first)

    def test_node_profile_preserves_transport_keys_and_uses_current_authorized_clients(self):
        module_path=Path(__file__).parents[1]/'node-runtime/node_autonomy.py'
        spec=importlib.util.spec_from_file_location('transfer_node_profile',module_path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        profile=self.recovery.load('xray:1')['vpn']['config']
        profile['inbounds'][0]['streamSettings']['realitySettings']={'privateKey':'preserved-server-key'}
        profile['inbounds'][0]['settings']['clients']=[{'id':'revoked-backup-client'}]
        path=Path(self.tmp.name)/'node-profile.json';path.write_text(json.dumps(profile),encoding='utf-8')
        current={'inbounds':[{'tag':value['tag'],'protocol':'vless','settings':{'clients':[{'id':'current-only'}]}}
                             for value in profile['inbounds']]}
        with patch.dict(os.environ,{'RIME_NODE_PROFILE':str(path),'RIME_NODE_LISTEN':'0.0.0.0'},clear=True):
            result=json.loads(module.prepare_config(current))
        self.assertEqual(result['inbounds'][0]['settings']['clients'],[{'id':'current-only'}])
        self.assertEqual(result['inbounds'][0]['streamSettings']['realitySettings']['privateKey'],'preserved-server-key')
        self.assertEqual(result['inbounds'][1]['streamSettings']['xhttpSettings'],profile['inbounds'][1]['streamSettings']['xhttpSettings'])

    def test_literal_ip_and_sni_rewrite_is_transactional(self):
        with self.store.connection(write=True) as db:
            db.execute('ALTER TABLE hosts ADD COLUMN sni TEXT')
            db.execute("UPDATE hosts SET address='1.1.1.1' WHERE id IN (1,3)")
        profile=self.recovery.load('xray:1')
        for inbound in profile['vpn']['config']['inbounds']:inbound['streamSettings']['security']='tls'
        self.recovery.save('xray:1',profile)
        data=self.data()
        self.transfer.register_node('a'*32,data,'new-token'*8)
        with self.store.connection() as db:
            self.assertEqual([tuple(row) for row in db.execute('SELECT address,sni FROM hosts WHERE id IN (1,3)')],
                             [('8.8.4.4','1.1.1.1'),('8.8.4.4','1.1.1.1')])
        self.transfer.restore_node('a'*32,{})
        with self.store.connection() as db:self.assertEqual(db.execute('SELECT address FROM hosts WHERE id=1').fetchone()[0],'1.1.1.1')

    def test_reconnect_detaches_locally_without_stopping_the_old_node(self):
        old=MagicMock()
        xray=types.SimpleNamespace(nodes={1:old},operations=types.SimpleNamespace(NODE_LIFECYCLE_LOCK=threading.RLock(),connect_node=MagicMock()))
        with patch.dict('sys.modules',{'app':types.SimpleNamespace(xray=xray)}):
            NodeTransfer.reconnect(self.transfer,1)
        self.assertNotIn(1,xray.nodes)
        old.disconnect.assert_not_called();old.stop.assert_not_called()
        xray.operations.connect_node.assert_called_once_with(1)


if __name__=='__main__':unittest.main()
