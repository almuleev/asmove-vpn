import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs

from app.xui import PanelGroup, PanelSettings

spec = importlib.util.spec_from_file_location('relay', Path(__file__).parents[1]/'deploy/tcp-relay.py')
relay = importlib.util.module_from_spec(spec); spec.loader.exec_module(relay)


class RelayExportTests(unittest.TestCase):
    def test_relay_changes_only_endpoint_and_is_restricted_to_enabled_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            panel = PanelGroup(PanelSettings('http://127.0.0.1:46065/', 4, '1.1.1.1:8080', 'x'*20), directory)
            account = {'id': 'a'*32}
            uid, _ = panel.identity(account['id'])
            original = f'vless://{uid}@1.1.1.1:443?type=tcp&security=reality&pbk=public&sid=ab&sni=example.com&flow=xtls-rprx-vision#old'
            config = {'enabled': True, 'account_ids': [account['id']], 'expires_at': time.time()+300,
                      'public_host': '8.8.8.8', 'port': 8443}
            panel.relay_path.write_text(json.dumps(config))
            result = panel.relay_link(account, [original])
            before, after = urlsplit(original), urlsplit(result)
            self.assertEqual(after.hostname, '8.8.8.8'); self.assertEqual(after.port, 8443)
            self.assertEqual(after.username, before.username)
            self.assertEqual(parse_qs(after.query), parse_qs(before.query))
            self.assertIsNone(panel.relay_link({'id': 'b'*32}, [original]))
            config['expires_at'] = None; panel.relay_path.write_text(json.dumps(config))
            self.assertEqual(panel.relay_link(account, [original]), result)
            self.assertIsNone(panel.relay_link({'id': 'b'*32}, [original]))
            config['expires_at'] = time.time()-1; panel.relay_path.write_text(json.dumps(config))
            self.assertIsNone(panel.relay_link(account, [original]))

    def test_permanent_mode_must_be_explicit_and_expired_or_invalid_config_stays_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'relay.json'
            config = {'enabled': True, 'port': 8443, 'allowed_peers': ['127.0.0.1']}
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError): relay.read_config(path)
            for expiry in (time.time()-1, 'never', float('nan'), True):
                config['expires_at'] = expiry; path.write_text(json.dumps(config))
                with self.assertRaises(ValueError): relay.read_config(path)
            config['expires_at'] = None; path.write_text(json.dumps(config))
            self.assertIsNone(relay.read_config(path)['expires_at'])
            config['enabled'] = False; path.write_text(json.dumps(config))
            with self.assertRaises(ValueError): relay.read_config(path)

    def test_destination_uses_current_node_and_rejects_private_or_russian_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'nodes.json'
            node = {'id': 'EU1', 'ip': '1.1.1.1', 'country': 'nl'}
            path.write_text(json.dumps({'nodes': [node]}))
            self.assertEqual(relay.destination(path, 'EU1'), ('1.1.1.1', 443))
            node['ip'] = '8.8.8.8'; path.write_text(json.dumps({'nodes': [node]}))
            self.assertEqual(relay.destination(path, 'EU1'), ('8.8.8.8', 443))
            node['ip'] = '127.0.0.1'; path.write_text(json.dumps({'nodes': [node]}))
            with self.assertRaises(ValueError): relay.destination(path, 'EU1')


class RelayStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_encrypted_bytes_are_forwarded_intact_and_unlisted_peers_are_rejected(self):
        received = []
        payload = os.urandom(150000)

        async def echo(reader, writer):
            try:
                data = await reader.readexactly(len(payload)); received.append(data)
                writer.write(data); await writer.drain()
            finally:
                writer.close(); await writer.wait_closed()

        backend = await asyncio.start_server(echo, '127.0.0.1', 0)
        target_port = backend.sockets[0].getsockname()[1]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'relay.json'
            with socket.socket() as candidate:
                candidate.bind(('127.0.0.1', 0)); port = candidate.getsockname()[1]
            config = {'enabled': True, 'port': port, 'allowed_peers': ['127.0.0.1'],
                      'target_node': 'EU1', 'expires_at': None}
            path.write_text(json.dumps(config))
            with patch.object(relay, 'destination', return_value=('127.0.0.1', target_port)):
                task = asyncio.create_task(relay.serve(path, path))
                try:
                    for _ in range(30):
                        try: reader, writer = await asyncio.open_connection('127.0.0.1', port); break
                        except OSError: await asyncio.sleep(.05)
                    else: self.fail('Relay did not start')
                    writer.write(payload); await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 5), payload)
                    writer.close(); await writer.wait_closed()
                    config['allowed_peers'] = ['198.51.100.25']; path.write_text(json.dumps(config))
                    reader, writer = await asyncio.open_connection('127.0.0.1', port)
                    self.assertEqual(await asyncio.wait_for(reader.read(), 3), b'')
                    writer.close(); await writer.wait_closed()
                    self.assertEqual(len(received), 1)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        backend.close(); await backend.wait_closed()
