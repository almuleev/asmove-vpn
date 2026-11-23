import argparse
import http.client
import json
import os
import re
import sqlite3
import socket
import sys
import time
from pathlib import Path

from .access_term import access_date
from .db import Store, connect, now, transaction


CHECK_INTERVAL = 3
REMINDER_WINDOW = 5 * 86400
STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schedule (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_day INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reminders (
    account_id TEXT NOT NULL,
    access_until INTEGER NOT NULL,
    sent_at INTEGER,
    PRIMARY KEY (account_id, access_until)
);
"""


class ReminderError(Exception):
    pass


class SocksHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, proxy):
        super().__init__(host, timeout=10)
        if not re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", proxy):
            raise ReminderError("invalid local Telegram proxy")
        self.proxy_port = int(proxy.rsplit(":", 1)[1])
        if self.proxy_port > 65535:
            raise ReminderError("invalid local Telegram proxy")

    @staticmethod
    def read_exact(connection, length):
        result = bytearray()
        while len(result) < length:
            chunk = connection.recv(length - len(result))
            if not chunk:
                raise OSError("SOCKS connection closed")
            result.extend(chunk)
        return bytes(result)

    def connect(self):
        connection = socket.create_connection(("127.0.0.1", self.proxy_port), self.timeout)
        try:
            connection.sendall(b"\x05\x01\x00")
            if self.read_exact(connection, 2) != b"\x05\x00":
                raise OSError("SOCKS authentication failed")
            host = self.host.encode("idna")
            connection.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + self.port.to_bytes(2, "big"))
            version, reply, reserved, address_type = self.read_exact(connection, 4)
            if (version, reply, reserved) != (5, 0, 0) or address_type not in (1, 3, 4):
                raise OSError("SOCKS connect failed")
            length = {1: 4, 4: 16}.get(address_type)
            if length is None:
                length = self.read_exact(connection, 1)[0]
            self.read_exact(connection, length + 2)
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except OSError:
            connection.close()
            raise


class Telegram:
    def __init__(self, token, chat_id):
        if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", token):
            raise ReminderError("invalid TELEGRAM_BOT_TOKEN")
        if not re.fullmatch(r"[1-9][0-9]{0,15}", chat_id):
            raise ReminderError("invalid private TELEGRAM_CHAT_ID")
        self.token = token
        self.chat_id = int(chat_id)

    def request(self, method, **fields):
        proxy = os.environ.get("TELEGRAM_SOCKS_PROXY")
        connection = SocksHTTPSConnection("api.telegram.org", proxy) if proxy else http.client.HTTPSConnection("api.telegram.org", timeout=10)
        try:
            body = json.dumps({"chat_id": self.chat_id, **fields}, ensure_ascii=False).encode()
            connection.request("POST", f"/bot{self.token}/{method}", body,
                               headers={"Content-Type": "application/json"})
            with connection.getresponse() as response:
                if response.status != 200:
                    raise ReminderError(f"Telegram HTTP {response.status}")
                result = json.loads(response.read(65537))
        except (OSError, ValueError, http.client.HTTPException):
            raise ReminderError("Telegram request failed") from None
        finally:
            connection.close()
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise ReminderError("Telegram rejected the request")
        return result.get("result")

    def check_chat(self):
        chat = self.request("getChat")
        if not isinstance(chat, dict) or chat.get("id") != self.chat_id or chat.get("type") != "private":
            raise ReminderError("Telegram chat is not the configured private chat")

    def send(self, message):
        self.request("sendMessage", text=message)


def reminder_text(login, deadline):
    return (
        "Здравствуйте! Сегодня нужно внести платёж за продление доступа, чтобы ваша ссылка продолжила работать.\n\n"
        f"Учётная запись: {login}\n"
        f"Доступ действует до {access_date(deadline):%d.%m.%Y} в 12:00 МСК."
    )


def enqueue_due(store, state, timestamp):
    today = access_date(timestamp).toordinal()
    schedule = state.execute("SELECT next_day FROM schedule WHERE singleton = 1").fetchone()
    if schedule and today < schedule["next_day"]:
        return False
    with connect(store.data, "ro") as accounts:
        due = accounts.execute(
            "SELECT id, access_until FROM accounts WHERE enabled = 1 AND access_until > ? AND access_until < ?",
            (timestamp, timestamp + REMINDER_WINDOW),
        ).fetchall()
    state.executemany("INSERT OR IGNORE INTO reminders (account_id, access_until) VALUES (?, ?)", due)
    state.execute("DELETE FROM reminders WHERE access_until <= ?", (timestamp,))
    state.execute(
        "INSERT INTO schedule VALUES (1, ?) ON CONFLICT(singleton) DO UPDATE SET next_day = excluded.next_day",
        (today + CHECK_INTERVAL,),
    )
    return True


def notify(store, state_path, telegram):
    with connect(state_path, "rwc") as state:
        state.executescript(STATE_SCHEMA)
        with transaction(state):
            checked = enqueue_due(store, state, now())
        sent = 0
        while True:
            with transaction(state):
                pending = state.execute(
                    "SELECT account_id, access_until FROM reminders WHERE sent_at IS NULL "
                    "ORDER BY access_until, account_id LIMIT 1"
                ).fetchone()
                if pending is None:
                    return checked, sent
                account_id, deadline = pending
                account = store.account("id", account_id)
                if not account or not account["enabled"] or account["access_until"] != deadline or deadline <= now():
                    state.execute("DELETE FROM reminders WHERE account_id = ? AND access_until = ?", pending)
                    continue
                telegram.send(reminder_text(account["login"], deadline))
                state.execute(
                    "UPDATE reminders SET sent_at = ? WHERE account_id = ? AND access_until = ?", (now(), *pending),
                )
            sent += 1
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    if os.environ.get("SITE_ROLE") != "primary":
        return 0
    try:
        telegram = Telegram(os.environ.get("TELEGRAM_BOT_TOKEN", ""), os.environ.get("TELEGRAM_CHAT_ID", ""))
        if args.check_config:
            telegram.check_chat()
            print("Telegram private chat verified")
            return 0
        store = Store(Path(os.environ.get("SITE_DATA_DIR", "/var/lib/access-site/data")))
        checked, sent = notify(store, Path(os.environ["STATE_DIRECTORY"]) / "reminders.sqlite3", telegram)
        print(f"subscriptions_checked={int(checked)} messages_sent={sent}")
    except ReminderError as exc:
        print(f"Subscription reminders failed: {exc}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error, KeyError) as exc:
        print(f"Subscription reminders failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
