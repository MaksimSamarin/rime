import unittest
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch,MagicMock

try:
    import grpc
except ImportError:
    grpc=SimpleNamespace(insecure_channel=MagicMock(),secure_channel=MagicMock(),ssl_channel_credentials=MagicMock())
spec=importlib.util.spec_from_file_location('direct_channel_under_test',Path(__file__).resolve().parents[1]/'xray_api/base.py')
module=importlib.util.module_from_spec(spec)
with patch.dict(sys.modules,{'grpc':grpc}):spec.loader.exec_module(module)
XRayBase=module.XRayBase


class DirectChannelTests(unittest.TestCase):
    def test_plain_channel_disables_environment_http_proxy(self):
        with patch.object(grpc,'insecure_channel') as channel:
            XRayBase('127.0.0.1', 62051)
        self.assertIn(('grpc.enable_http_proxy', 0), channel.call_args.kwargs['options'])

    def test_tls_channel_without_name_override_has_direct_options(self):
        with patch.object(grpc,'secure_channel') as channel, patch.object(grpc,'ssl_channel_credentials'):
            XRayBase('node.example', 62051, ssl_cert=b'synthetic-ca')
        self.assertEqual(channel.call_args.kwargs['options'], [('grpc.enable_http_proxy', 0)])

    def test_tls_name_override_preserves_direct_option(self):
        with patch.object(grpc,'secure_channel') as channel, patch.object(grpc,'ssl_channel_credentials'):
            XRayBase('node.example', 62051, ssl_cert=b'synthetic-ca', ssl_target_name='Gozargah')
        self.assertIn(('grpc.enable_http_proxy', 0), channel.call_args.kwargs['options'])
        self.assertIn(('grpc.ssl_target_name_override', 'Gozargah'), channel.call_args.kwargs['options'])
