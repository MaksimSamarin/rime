"""A verified destination identity switches and rolls back with node registration."""
import json
from pathlib import Path
import unittest

from hy2bridge.native_trust import NativeTrust
from hy2bridge.provision import ProvisionError
from hy2bridge.transfer import NodeTransfer
import test_full_transfer as full_transfer
import test_transfer as transfer_tests
from test_native_certificate_pinning import certificate


class NativeTrustTransferTests(unittest.TestCase):
    setUp=full_transfer.FullTransferTests.setUp
    tearDown=full_transfer.FullTransferTests.tearDown
    engine=full_transfer.FullTransferTests.engine
    data=full_transfer.FullTransferTests.data
    protected=transfer_tests.TransferTests.protected

    def prepared(self):
        root=Path(self.tmp.name)
        old,_=certificate(root,'old-management');new,key=certificate(root,'new-management')
        self.trust=NativeTrust(self.store,self.recovery)
        self.trust.enroll('xray:1',old.read_text())
        profile=self.recovery.load('xray:1')
        profile['vpn'].update(management_server_certificate=old.read_text(),management_certificate_verified=True)
        self.recovery.save('xray:1',profile)
        data=self.data()
        data['_management_server_certificate']=new.read_text()
        data['_profile']['vpn']['management_tls']={'certificate':new.read_text(),'key':key.read_text()}
        data['_targets']=[]
        self.before=self.protected()
        with self.store.connection() as db:self.old_pin=NativeTrust.snapshot(db,'xray:1')
        return data

    def test_failed_verified_destination_restores_pin_registration_and_user_identity(self):
        data=self.prepared();job='a'*32
        self.transfer.register_node(job,data,'new-token'*8)
        self.assertEqual(self.trust.expected('xray:1'),data['_management_server_certificate'])
        self.probe.run_targets.side_effect=ProvisionError('Synthetic payload failure after trusted cutover')
        with self.assertRaisesRegex(ProvisionError,'Synthetic payload'):
            self.transfer.verify_node(job,data)
        self.transfer.restore_node(job,{})
        self.assertEqual(self.protected(),self.before)
        with self.store.connection() as db:
            self.assertEqual(NativeTrust.snapshot(db,'xray:1'),self.old_pin)
            self.assertEqual(db.execute('SELECT address FROM nodes WHERE id=1').fetchone()[0],'1.1.1.1')
        self.assertEqual(self.recovery.load('xray:1')['vpn']['management_server_certificate'],self.old_pin['certificate'])

    def test_interrupted_transfer_recovers_its_old_pin_from_the_durable_journal(self):
        data=self.prepared();job='a'*32
        self.transfer.register_node(job,data,'new-token'*8)
        NodeTransfer(self.base,self.operations,self.probe,self.life,self.recovery,self.proxies)
        with self.store.connection() as db:
            self.assertEqual(NativeTrust.snapshot(db,'xray:1'),self.old_pin)
            self.assertEqual(db.execute('SELECT state FROM fleet_node_transfers WHERE id=?',(job,)).fetchone()[0],'rolled_back')
        self.assertEqual(self.protected(),self.before)

    def test_newer_authorized_identity_is_not_overwritten_by_a_stale_rollback(self):
        data=self.prepared();job='a'*32
        self.transfer.register_node(job,data,'new-token'*8)
        third,_=certificate(Path(self.tmp.name),'another-reviewed-registration')
        with self.store.connection(write=True) as db:
            expected=NativeTrust.snapshot(db,'xray:1')
            NativeTrust.enroll_verified_transfer(db,'xray:1',third.read_text(),expected)
        with self.assertRaises(ProvisionError):self.transfer.restore_node(job,{})
        self.assertEqual(self.trust.expected('xray:1'),third.read_text())
        with self.store.connection() as db:self.assertEqual(db.execute('SELECT address FROM nodes WHERE id=1').fetchone()[0],'8.8.4.4')
        self.assertEqual(self.protected(),self.before)

    def test_successful_transfer_keeps_new_verified_identity_in_the_encrypted_profile(self):
        data=self.prepared();job='a'*32
        self.transfer.register_node(job,data,'new-token'*8)
        data['_proxy_results']={self.identity:{'passed':True,'checks':[]}}
        self.transfer.accept_node(job,data)
        self.assertEqual(self.trust.expected('xray:1'),data['_management_server_certificate'])
        profile=self.recovery.load('xray:1')
        self.assertEqual(profile['vpn']['management_tls'],data['_profile']['vpn']['management_tls'])
        self.assertEqual(profile['vpn']['management_server_certificate'],data['_management_server_certificate'])
        self.assertEqual(self.protected(),self.before)

    def test_missing_verified_destination_certificate_cannot_publish_a_registration(self):
        data=self.prepared();del data['_management_server_certificate']
        with self.assertRaisesRegex(ProvisionError,'SSH-сертификат'):
            self.transfer.register_node('a'*32,data,'new-token'*8)
        with self.store.connection() as db:
            self.assertEqual(NativeTrust.snapshot(db,'xray:1'),self.old_pin)
            self.assertEqual(db.execute('SELECT count(*) FROM fleet_node_transfers').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT address FROM nodes WHERE id=1').fetchone()[0],'1.1.1.1')
        self.assertEqual(self.protected(),self.before)


if __name__=='__main__':unittest.main()
