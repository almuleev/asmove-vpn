import tempfile
import ssl
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import Mock, patch

from app.access_term import access_date, noon
from app.db import Store
from app.reminders import ReminderError, SocksHTTPSConnection, notify


DAY = 86400
START = noon(date(2032, 2, 25))


class TelegramProxyTests(unittest.TestCase):
    def test_fragmented_socks_reply_still_requires_valid_telegram_certificate(self):
        socket = Mock()
        socket.recv.side_effect = [b"\x05", b"\x00", b"\x05\x00\x00\x01", b"\0" * 6]
        client = SocksHTTPSConnection("api.telegram.org", "127.0.0.1:10809")
        with patch("app.reminders.socket.create_connection", return_value=socket) as dial, patch.object(
            ssl.SSLContext, "wrap_socket", autospec=True,
            side_effect=ssl.SSLCertVerificationError("wrong certificate"),
        ) as tls:
            with self.assertRaises(ssl.SSLCertVerificationError):
                client.connect()
        dial.assert_called_once_with(("127.0.0.1", 10809), 10)
        context, stream = tls.call_args.args
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(tls.call_args.kwargs, {"server_hostname": "api.telegram.org"})
        self.assertIs(stream, socket)
        self.assertEqual(socket.sendall.call_count, 2)
        socket.close.assert_called_once()

    def test_proxy_must_be_local(self):
        with self.assertRaises(ReminderError):
            SocksHTTPSConnection("api.telegram.org", "1.1.1.1:10809")


class ReminderTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Store(Path(directory.name))
        self.store.initialize(True, "a" * 64)
        self.state = self.store.directory / "reminders.sqlite3"
        self.telegram = Mock()
        clock = patch("app.reminders.now", return_value=START)
        sleep = patch("app.reminders.time.sleep")
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        sleep.start()
        self.addCleanup(sleep.stop)

    def create(self, login, deadline):
        self.store.change(
            "create", login=login, access_index=login, password_hash="unused",
            access_until=deadline, access_day=access_date(deadline).day if deadline is not None else None,
        )
        return self.store.account("login", login)["id"]

    def run_reminders(self):
        return notify(self.store, self.state, self.telegram)

    def test_checks_every_three_days_and_sends_once_per_account_and_deadline(self):
        self.create("first", START + DAY)
        self.create("second", START + 4 * DAY)
        self.create("exactly-five", START + 5 * DAY)
        self.create("already-ended", START)
        self.create("unlimited", None)
        revoked = self.create("revoked", START + DAY)
        self.store.change("revoke", account_id=revoked)

        self.assertEqual(self.run_reminders(), (True, 2))
        messages = [call.args[0] for call in self.telegram.send.call_args_list]
        self.assertIn("Учётная запись: first\n", messages[0])
        self.assertIn("Учётная запись: second\n", messages[1])
        self.assertTrue(all("Сегодня нужно внести платёж" in message for message in messages))
        self.clock.return_value = START + DAY
        self.assertEqual(self.run_reminders(), (False, 0))
        self.clock.return_value = START + 3 * DAY
        self.assertEqual(self.run_reminders(), (True, 1))
        self.assertIn("Учётная запись: exactly-five\n", self.telegram.send.call_args.args[0])
        self.assertEqual(self.run_reminders(), (False, 0))

    def test_retries_pending_messages_and_skips_subscriptions_renewed_in_the_meantime(self):
        self.create("sent", START + DAY)
        renewed = self.create("renewed", START + 2 * DAY)
        self.create("pending", START + 3 * DAY)
        self.telegram.send.side_effect = [None, ReminderError("Telegram HTTP 503")]
        with self.assertRaises(ReminderError):
            self.run_reminders()

        future = START + 40 * DAY
        self.store.change("access", account_id=renewed, access_until=future, access_day=access_date(future).day)
        self.telegram.reset_mock(side_effect=True)
        self.assertEqual(self.run_reminders(), (False, 1))
        self.telegram.send.assert_called_once()
        self.assertIn("Учётная запись: pending\n", self.telegram.send.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
