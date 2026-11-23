import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from app import ntfy, problem_reports
from app.db import connect


class NtfyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.settings = SimpleNamespace(data_dir=Path(temporary.name), origin='https://control.example', panel=None)
        self.account = {'id': 'user', 'login': 'example'}

    def test_bootstrap_skips_history_then_delivers_new_events_even_after_telegram(self):
        problem_reports.enqueue(self.settings, self.account)
        with connect(problem_reports.database(self.settings)) as db, db:
            db.execute('UPDATE reports SET sent=1')
        ntfy.collect(self.settings)
        client = Mock();client.send.return_value = 'receipt'
        self.assertEqual(ntfy.deliver(self.settings, client), (0, True))
        client.send.assert_not_called()
        problem_reports.enqueue(self.settings, {'id': 'second', 'login': 'new-user'})
        with connect(problem_reports.database(self.settings)) as db, db:
            db.execute('UPDATE reports SET sent=2')
        self.assertEqual(ntfy.deliver(self.settings, client), (1, True))
        self.assertIn('new-user', client.send.call_args.args[0])
        self.assertEqual(ntfy.deliver(self.settings, client), (0, True))

    def test_ntfy_failure_preserves_its_queue_and_never_alters_telegram_receipts(self):
        problem_reports.enqueue(self.settings, self.account)
        client = Mock();client.send.side_effect = ntfy.NtfyError('unavailable')
        with patch('app.ntfy.now', return_value=1000) as clock:
            self.assertEqual(ntfy.deliver(self.settings, client), (0, False))
            self.assertEqual(ntfy.state(self.settings)['queued'], 1)
            with connect(problem_reports.database(self.settings)) as db:
                self.assertEqual(db.execute('SELECT sent FROM reports').fetchone()[0], 0)
            client.send.side_effect = None;client.send.return_value = 'retry-receipt'
            self.assertEqual(ntfy.deliver(self.settings, client), (0, True))
            clock.return_value = 1030
            self.assertEqual(ntfy.deliver(self.settings, client), (1, True))
            self.assertEqual(ntfy.state(self.settings)['queued'], 0)

    def test_infrastructure_events_are_mirrored_without_changing_source(self):
        ntfy.collect(self.settings)
        with connect(self.settings.data_dir/'infrastructure.sqlite3', 'rwc') as db, db:
            db.execute('CREATE TABLE notifications(id TEXT,message TEXT,sent INTEGER)')
            db.execute('INSERT INTO notifications VALUES (?,?,?)', ('job:ready', 'Замена готова', 1))
        client = Mock();client.send.return_value = 'server-receipt'
        self.assertEqual(ntfy.deliver(self.settings, client), (1, True))
        self.assertEqual(client.send.call_args.kwargs['click'], 'https://control.example/admin/infrastructure')

    def test_sender_uses_direct_https_and_does_not_log_or_follow_bad_responses(self):
        client = ntfy.Ntfy('https://ntfy.sh/random-secret-topic')
        connection = Mock();response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = json.dumps({'event':'message','topic':'random-secret-topic','id':'accepted'}).encode()
        with patch('app.ntfy.http.client.HTTPSConnection', return_value=connection) as dial:
            self.assertEqual(client.send('Проверка', click='https://control.example/admin'), 'accepted')
            dial.assert_called_once_with('ntfy.sh', 443, timeout=8)
            payload = json.loads(connection.request.call_args.args[2])
            self.assertEqual(payload['message'], 'Проверка')
        response.status = 503
        with patch('app.ntfy.http.client.HTTPSConnection', return_value=connection):
            with self.assertRaisesRegex(ntfy.NtfyError, '^http_503$'):
                client.send('Проверка')

    def test_configuration_rejects_plaintext_and_query_credentials(self):
        for url in ('http://ntfy.sh/topic', 'https://ntfy.sh/topic?token=secret', 'https://user:password@ntfy.sh/topic'):
            with self.assertRaises(ntfy.NtfyError):
                ntfy.Ntfy(url)
