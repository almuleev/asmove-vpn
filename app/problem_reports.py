"""Durable user reports; accepting a report never requires the VPN or Telegram."""
from datetime import datetime
from uuid import uuid4

from .access_term import MOSCOW
from .db import connect, now

COOLDOWN = 300
SCHEMA = """CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY, account_id TEXT NOT NULL, created INTEGER NOT NULL,
    message TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0
)"""


def database(settings):
    return settings.data_dir / "problem-reports.sqlite3"


def status(settings, account):
    if not database(settings).exists():
        return {"next_at": None}
    with connect(database(settings)) as db:
        row = db.execute("SELECT max(created) FROM reports WHERE account_id=?", (account["id"],)).fetchone()
    next_at = row[0] + COOLDOWN if row[0] is not None else 0
    return {"next_at": next_at if next_at > now() else None}


def enqueue(settings, account):
    stamp = now()
    address = settings.panel.public_address if settings.panel else "не указан"
    message = ("Пользователь сообщил о неработающем VPN\n"
               f"Пользователь — {account['login']}\n"
               f"Сервер — {address}\n"
               f"Время — {datetime.fromtimestamp(stamp, MOSCOW):%d.%m.%Y %H:%M} МСК\n"
               "Это обращение пользователя. Проверьте состояние сервера в админке.")
    with connect(database(settings), "rwc") as db, db:
        db.execute(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT max(created) FROM reports WHERE account_id=?", (account["id"],)).fetchone()
        if row[0] is not None and row[0] + COOLDOWN > stamp:
            return {"accepted": False, "next_at": row[0] + COOLDOWN}
        db.execute("INSERT INTO reports(id,account_id,created,message) VALUES (?,?,?,?)",
                   (uuid4().hex, account["id"], stamp, message))
    return {"accepted": True, "next_at": stamp + COOLDOWN}


def deliver(settings, telegram):
    if not database(settings).exists():
        return 0
    sent = 0
    with connect(database(settings)) as db, db:
        for row in db.execute("SELECT id,message FROM reports WHERE sent=0 ORDER BY created,rowid LIMIT 30").fetchall():
            telegram.send(row["message"])
            db.execute("UPDATE reports SET sent=? WHERE id=?", (now(), row["id"]))
            db.commit()
            sent += 1
    return sent
