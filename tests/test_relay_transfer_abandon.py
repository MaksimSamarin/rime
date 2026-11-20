"""Physical transfer recovery must not revive an explicitly abandoned relay."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from hy2bridge.transfer import NodeTransfer


class AbandonedTransferRelayTests(unittest.TestCase):
    def transfer(self):
        value=NodeTransfer.__new__(NodeTransfer)
        changes=SimpleNamespace(read=Mock(return_value={'phase':'abandoned'}),pending=Mock(return_value=None),
                                retarget=Mock(side_effect=AssertionError('Do not revive an abandoned route')))
        value.proxies=SimpleNamespace(relays=SimpleNamespace(changes=changes))
        value.relay_success_pending=set()
        return value,changes

    def test_physical_transfer_verification_skips_the_abandoned_relay(self):
        value,changes=self.transfer()
        value.recovery=True;value.probe=SimpleNamespace(run_targets=Mock());value.verify_proxies=Mock();value.update=Mock()
        value.verify_node('fixture-job',{'_targets':[],'_registration_id':'fixture-registration'})
        value.probe.run_targets.assert_called_once_with([],'fixture-registration')
        changes.retarget.assert_not_called()

    def test_completed_physical_transfer_does_not_wait_forever_for_abandoned_relay(self):
        value,_=self.transfer();value.recovery=False
        with patch('hy2bridge.provision.Provisioner.update',return_value='recorded') as update:
            value.update('fixture-job','succeeded','Physical transfer checked')
        self.assertEqual(update.call_args.args[1],'succeeded')
        self.assertFalse(value.relay_success_pending)


if __name__=='__main__':unittest.main()
