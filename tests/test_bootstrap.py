import base64
from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bootstrap', ROOT/'deploy/bootstrap-vpn.py')
bootstrap = importlib.util.module_from_spec(spec); spec.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def config(self):
        return {'eu_ip': '1.1.1.1', 'eu_service_id': 1, 'eu_host_fingerprint': 'SHA256:'+'A'*43,
                'country': 'nl', 'datacenter_id': 1, 'candidates': []}

    def test_validate_and_check_do_not_execute_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'bootstrap.local.json'; path.write_text(json.dumps(self.config())); path.chmod(0o600)
            with patch.object(sys, 'argv', ['bootstrap-vpn.py', str(path), '--check']), patch.object(
                    bootstrap, 'connect', side_effect=AssertionError('Must not install')), patch.object(
                    bootstrap.subprocess, 'run', side_effect=AssertionError('Must not execute')):
                self.assertEqual(bootstrap.main(), 0)

    def test_invalid_targets_and_replacement_prices_are_rejected_before_ssh(self):
        for change in ({'eu_ip': '127.0.0.1'}, {'eu_service_id': True}, {'eu_host_fingerprint': 'unverified'},
                       {'country': 'ru'}, {'password': 'must-not-be-a-config-key'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                bootstrap.validate({**self.config(), **change})
        candidate = {'plan_id': 1, 'group_id': 1, 'datacenter_id': 2, 'template_id': 1,
                     'ssh_key_id': 1, 'country': 'nl', 'daily_cost': '0.07'}
        self.assertEqual(bootstrap.validate({**self.config(), 'vdsina_token_file': '/root/provider.token',
                                            'candidates': [candidate]})['candidates'], [candidate])
        for price in ('0.50', 'NaN', 'unknown', None):
            with self.subTest(price=price), self.assertRaises(ValueError):
                bootstrap.validate({**self.config(), 'vdsina_token_file': '/root/provider.token',
                                     'candidates': [{**candidate, 'daily_cost': price}]})

    def test_host_fingerprint_is_checked_before_persisting_or_replacing_a_key(self):
        key = base64.b64encode(b'simulated-host-key').decode()
        fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(b'simulated-host-key').digest()).decode().rstrip('=')
        with tempfile.TemporaryDirectory() as directory, patch.object(bootstrap, 'CONTROL', Path(directory)), patch.object(
                bootstrap, 'run', return_value=('1.1.1.1 ssh-ed25519 '+key+'\n').encode()):
            with self.assertRaisesRegex(ValueError, 'fingerprint mismatch'):
                bootstrap.pin_host('1.1.1.1', 1, 'SHA256:'+'A'*43)
            self.assertFalse((Path(directory)/'known_hosts').exists())
            bootstrap.pin_host('1.1.1.1', 1, fingerprint)
            pinned = (Path(directory)/'known_hosts').read_text()
            self.assertIn('asmove-service-1 ssh-ed25519 ', pinned)
            bootstrap.pin_host('1.1.1.1', 1, fingerprint)
            self.assertEqual((Path(directory)/'known_hosts').read_text(), pinned)
            with patch.object(bootstrap, 'run', return_value=('1.1.1.1 ssh-ed25519 '+base64.b64encode(b'other').decode()+'\n').encode()):
                changed = 'SHA256:'+base64.b64encode(hashlib.sha256(b'other').digest()).decode().rstrip('=')
                with self.assertRaisesRegex(ValueError, 'Existing service host key differs'):
                    bootstrap.pin_host('1.1.1.1', 1, changed)
            self.assertEqual((Path(directory)/'known_hosts').read_text(), pinned)

    def test_pages_and_runtime_scripts_exist_in_a_fresh_source_checkout(self):
        for name in bootstrap.SCRIPTS:
            self.assertTrue((ROOT/'deploy'/name).is_file(), name)
        self.assertTrue((ROOT/'launcher/dist/admin/index.html').is_file())
        self.assertFalse((ROOT/'launcher/dist/admin/admin.js').exists())
        self.assertFalse((ROOT/'launcher/dist/launcher.js').exists())

    def test_recovery_refuses_an_empty_or_unrelated_cabinet_before_sync_can_prune_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'accounts.sqlite3'
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript("CREATE TABLE accounts(id TEXT); CREATE TABLE state(access_key_id TEXT);"
                                 "INSERT INTO accounts VALUES('a'),('b'); INSERT INTO state VALUES('original-key');")
            payload = path.read_bytes()
            bootstrap.verify_recovery_identity(payload, {'a', 'b'}, 'original-key')
            for ids, key in [(set(), 'original-key'), ({'a'}, 'original-key'), ({'a', 'b'}, 'new-key')]:
                with self.subTest(ids=ids, key=key), self.assertRaisesRegex(ValueError, 'matching cabinet database'):
                    bootstrap.verify_recovery_identity(payload, ids, key)
