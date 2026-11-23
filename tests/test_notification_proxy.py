import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec=importlib.util.spec_from_file_location('notification_proxy',Path(__file__).resolve().parents[1]/'deploy/notification-proxy.py')
proxy=importlib.util.module_from_spec(spec);spec.loader.exec_module(proxy)


class NotificationProxyTests(unittest.TestCase):
    def test_telegram_route_does_not_require_the_vpn_provider_api(self):
        with patch.object(proxy.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as curl,patch.object(proxy,'SocksHTTPSConnection') as provider:
            self.assertTrue(proxy.healthy(10810,telegram_only=True))
            provider.assert_not_called()
            self.assertIn('127.0.0.1:10810',curl.call_args.args[0])

    def test_provider_route_retains_its_independent_tls_check(self):
        with patch.object(proxy.subprocess,'run',return_value=SimpleNamespace(returncode=0)),patch.object(proxy,'SocksHTTPSConnection') as provider:
            self.assertTrue(proxy.healthy(10809,telegram_only=False))
            provider.assert_called_once_with('userapi.vdsina.com','127.0.0.1:10809')
            provider.return_value.connect.assert_called_once();provider.return_value.close.assert_called_once()

    def test_dead_telegram_route_is_restarted_without_testing_provider(self):
        with patch.object(proxy.subprocess,'run',return_value=SimpleNamespace(returncode=1)),patch.object(proxy,'SocksHTTPSConnection') as provider:
            self.assertFalse(proxy.healthy(10810,telegram_only=True));provider.assert_not_called()

    def test_dedicated_route_uses_only_the_pinned_relay(self):
        with TemporaryDirectory() as directory:
            path=Path(directory)/'relay.json';path.write_text(json.dumps({'relay':{'ip':'9.9.9.9','alias':'9.9.9.9'}}))
            targets=proxy.load_targets(path)
            command=proxy.ssh_command(targets[0],10810)
            self.assertEqual(command[-1],'root@9.9.9.9')
            self.assertIn('127.0.0.1:10810',command)
            self.assertIn('StrictHostKeyChecking=yes',command)
            self.assertNotIn('1.1.1.1',' '.join(command))
            path.write_text(json.dumps({'relay':{'ip':'127.0.0.1','alias':'bad alias'}}))
            with self.assertRaises(ValueError):proxy.load_targets(path)


if __name__=='__main__':unittest.main()
