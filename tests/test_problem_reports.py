import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app import events, problem_reports
from app.db import connect


class ProblemReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.settings = SimpleNamespace(data_dir=Path(temporary.name), panel=SimpleNamespace(public_address="203.0.113.1:8080"))
        self.account = {"id": "user-id", "login": "test-user"}

    def test_reports_survive_telegram_failure_and_retry_without_duplicate_clicks(self):
        with patch("app.problem_reports.now", return_value=1000) as clock:
            first = problem_reports.enqueue(self.settings, self.account)
            self.assertTrue(first["accepted"])
            self.assertFalse(problem_reports.enqueue(self.settings, self.account)["accepted"])
            telegram = Mock()
            telegram.send.side_effect = OSError("unavailable")
            with self.assertRaises(OSError):
                problem_reports.deliver(self.settings, telegram)
            with connect(problem_reports.database(self.settings)) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM reports WHERE sent=0").fetchone()[0], 1)
            telegram.send.side_effect = None
            self.assertEqual(problem_reports.deliver(self.settings, telegram), 1)
            message = telegram.send.call_args.args[0]
            self.assertIn("test-user", message)
            self.assertIn("203.0.113.1:8080", message)
            self.assertIn("Это обращение пользователя", message)
            self.assertEqual(problem_reports.deliver(self.settings, telegram), 0)
            clock.return_value = first["next_at"]
            self.assertTrue(problem_reports.enqueue(self.settings, self.account)["accepted"])

    def test_local_reports_are_delivered_without_old_controller(self):
        problem_reports.enqueue(self.settings, self.account)
        self.settings.emergency_controller = None
        telegram = Mock()
        with (patch.object(events.Settings, "from_env", return_value=self.settings),
              patch.object(events, "Telegram", return_value=telegram),
              patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "test-token", "TELEGRAM_CHAT_ID": "test-chat"}, clear=True),
              patch.object(events, "urlopen") as external):
            events.main()
        telegram.send.assert_called_once()
        external.assert_not_called()
