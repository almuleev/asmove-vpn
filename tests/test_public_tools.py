import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


portal = module('portal_builder', 'deploy/build-portal.py')
provider = module('provider_reader', 'deploy/provider-read.py')


class PublicToolsTests(unittest.TestCase):
    def test_portal_artifact_changes_api_csp_and_admin_and_preserves_no_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'portal.zip'
            portal.build(output, 'https://api.example')
            with ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()), {'.nojekyll', '_headers', 'index.html',
                                                         'admin/index.html', 'cabinet.js', 'site.css'})
                text = archive.read('index.html').decode()
                self.assertIn('connect-src https://api.example;', text)
                self.assertIn('content="https://api.example"', text)
                self.assertIn('url=https://api.example/admin', archive.read('admin/index.html').decode())
                self.assertNotIn('controller.example', text)
            with self.assertRaises(FileExistsError):
                portal.build(output, 'https://api.example')

    def test_portal_rejects_credentials_and_script_injection(self):
        for value in ('http://api.example', 'https://api.example/path', 'https://user:pass@api.example',
                      'https://127.0.0.1', 'https://api.example" onload="test', 'https://api.example#fragment'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                portal.origin(value)

    def test_catalog_uses_get_and_never_exposes_unknown_fields(self):
        api = Mock()
        api.request.return_value = [{'id': 7, 'name': 'key', 'private': 'must-not-be-output', 'data': 'key-material'}]
        self.assertEqual(provider.catalog(api, 'keys'), [{'id': 7, 'name': 'key'}])
        api.request.assert_called_once_with('GET', 'ssh-key')
        api.reset_mock()
        with self.assertRaises(ValueError):
            provider.catalog(api, 'plans', 0)
        api.request.assert_not_called()

    def test_non_usd_api_host_cannot_be_used_for_usd_price_policy(self):
        from app.vdsina import Vdsina
        with self.assertRaises(ValueError):
            Vdsina('userapi.vdsina.ru')
