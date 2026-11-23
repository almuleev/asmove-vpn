import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('export_state', Path(__file__).resolve().parents[1]/'deploy/export-state.py')
exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)


class ExportTests(unittest.TestCase):
    def test_bundle_preserves_payload_and_checksums_with_private_modes(self):
        files = {'accounts.sqlite3': b'database-fixture', 'etc-access-site/site.env': b'test-secret-fixture'}
        packed = exporter.pack_state(files, {'version': 1})
        with tarfile.open(fileobj=io.BytesIO(packed), mode='r:gz') as archive:
            manifest = json.load(archive.extractfile('manifest.json'))
            for name, content in files.items():
                self.assertEqual(archive.extractfile(name).read(), content)
                self.assertEqual(archive.getmember(name).mode, 0o600)
                self.assertEqual(manifest['sha256'][name], hashlib.sha256(content).hexdigest())
        for unsafe in ('../site.env', '/etc/site.env', 'C:\\Windows\\test'):
            with self.assertRaises(ValueError): exporter.pack_state({unsafe: b'x'}, {})

    def test_existing_backup_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'existing.age'; path.write_bytes(b'existing-backup')
            with self.assertRaises(FileExistsError): exporter.encrypt_bundle(b'new', 'unused', path)
            self.assertEqual(path.read_bytes(), b'existing-backup')

    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'age binaries required; exercised by Linux CI')
    def test_real_encryption_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); key = directory/'identity.agekey'; output = directory/'backup.age'
            subprocess.run(['age-keygen', '-o', str(key)], check=True, capture_output=True)
            recipient = subprocess.check_output(['age-keygen', '-y', str(key)], text=True).strip()
            packed = exporter.pack_state({'accounts.sqlite3': b'recovery-fixture'}, {'version': 1})
            exporter.encrypt_bundle(packed, recipient, output)
            self.assertNotIn(b'recovery-fixture', output.read_bytes())
            recovered = subprocess.check_output(['age', '-d', '-i', str(key), str(output)])
            self.assertEqual(recovered, packed)
