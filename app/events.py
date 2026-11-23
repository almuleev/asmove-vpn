import hashlib
import hmac
import json
import logging
import os
from datetime import datetime
from urllib.parse import urlsplit
from uuid import uuid4
from urllib.request import Request, urlopen

from .access_term import MOSCOW
from .db import connect
from .reminders import Telegram
from .settings import Settings
from . import problem_reports


def enqueue(settings, account, result):
    try:
        event_id = uuid4().hex
        with connect(settings.data_dir / "events.sqlite3", "rwc") as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, body TEXT NOT NULL)")
            body = json.dumps({
                "id": event_id,
                "message": (
                    "Запрос запасной ссылки\n"
                    f"Пользователь — {account['login']}\n"
                    f"Время — {datetime.now(MOSCOW):%d.%m.%Y %H:%M} МСК\n"
                    f"Результат — {result}"
                ),
            }, ensure_ascii=False)
            db.execute("INSERT INTO events VALUES (?, ?)", (event_id, body))
    except Exception:
        logging.getLogger("access_site").warning("reserve_event_enqueue_failed")


def main():
    settings = Settings.from_env()
    if os.environ.get("TELEGRAM_BOT_TOKEN"):
        problem_reports.deliver(settings, Telegram(os.environ["TELEGRAM_BOT_TOKEN"], os.environ["TELEGRAM_CHAT_ID"]))
    path = settings.data_dir / "events.sqlite3"
    origin = os.environ.get("SITE_EVENT_CONTROLLER") or settings.emergency_controller
    if not origin:
        return
    event_url = origin + ("?route=event" if urlsplit(origin).hostname == "functions.yandexcloud.net" else "/event")

    def exchange(body):
        signature = hmac.new(settings.access_key, body, hashlib.sha256).hexdigest()
        request = Request(event_url, data=body, headers={
            "Content-Type": "application/json", "X-Reserve-Event-Signature": signature,
        })
        with urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError("Event delivery failed")
            return json.load(response)

    if path.exists():
        with connect(path) as db, db:
            for row in db.execute("SELECT id, body FROM events LIMIT 30").fetchall():
                exchange(row["body"].encode())
                db.execute("DELETE FROM events WHERE id = ?", (row["id"],))
                db.commit()
    if os.environ.get("TELEGRAM_BOT_TOKEN"):
        telegram = Telegram(os.environ["TELEGRAM_BOT_TOKEN"], os.environ["TELEGRAM_CHAT_ID"])
        for event in exchange(b'{"action":"poll"}'):
            telegram.send(event["message"])
            exchange(json.dumps({"action": "ack", "id": event["id"]}).encode())


if __name__ == "__main__":
    main()
