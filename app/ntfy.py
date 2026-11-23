"""Independent ntfy delivery. Telegram receipts and VPN access are never required."""
import http.client
import json
import os
import re
import sqlite3
from urllib.parse import urlsplit

from .db import connect, now
from .settings import Settings


class NtfyError(Exception):
    pass


class Ntfy:
    def __init__(self, url, token=""):
        parsed = urlsplit(url)
        topic = parsed.path.removeprefix("/")
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or not re.fullmatch(r"[-_A-Za-z0-9]{1,64}", topic)):
            raise NtfyError("invalid_configuration")
        self.host, self.port, self.topic, self.token = parsed.hostname, parsed.port or 443, topic, token

    def send(self, message, *, click=None, priority=3):
        payload = {"topic": self.topic, "title": "VPN Node Guard", "message": message, "priority": priority}
        if click:
            payload["click"] = click
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        # Intentionally direct: TELEGRAM_SOCKS_PROXY and environment HTTP proxies do not apply.
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=8)
        try:
            connection.request("POST", "/", json.dumps(payload, ensure_ascii=False).encode(), headers)
            response = connection.getresponse()
            if response.status != 200:
                raise NtfyError("http_" + str(response.status))
            body = response.read(65537)
            if len(body) > 65536:
                raise NtfyError("response_too_large")
            result = json.loads(body)
            if (not isinstance(result, dict) or result.get("event") != "message"
                    or result.get("topic") != self.topic or not result.get("id")):
                raise NtfyError("invalid_response")
            return result["id"]
        except (OSError, ValueError, http.client.HTTPException):
            raise NtfyError("unavailable") from None
        finally:
            connection.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    source TEXT NOT NULL, id TEXT NOT NULL, message TEXT NOT NULL, click TEXT NOT NULL,
    created INTEGER NOT NULL, sent INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '', receipt TEXT NOT NULL DEFAULT '', PRIMARY KEY(source,id)
);
CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""


def database(settings):
    return settings.data_dir / "ntfy.sqlite3"


def source_messages(settings):
    for filename, table, source, target in (
        ("problem-reports.sqlite3", "reports", "user-report", "/admin"),
        ("infrastructure.sqlite3", "notifications", "infrastructure", "/admin/infrastructure"),
    ):
        path = settings.data_dir / filename
        if not path.exists():
            continue
        with connect(path, "ro") as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone():
                continue
            rows = db.execute("SELECT id,message,sent FROM " + table + " ORDER BY rowid").fetchall()
        for row in rows:
            yield source, row["id"], row["message"], settings.origin + target, bool(row["sent"])


def collect(settings):
    messages = list(source_messages(settings))
    with connect(database(settings), "rwc") as db, db:
        db.executescript(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        initial = not db.execute("SELECT 1 FROM metadata WHERE name='initialized'").fetchone()
        for source, identifier, message, click, delivered in messages:
            # At installation, old Telegram-completed events become baseline records only.
            # After initialization, every new event is queued even if Telegram already sent it.
            db.execute("INSERT OR IGNORE INTO outbox(source,id,message,click,created,sent) VALUES (?,?,?,?,?,?)",
                       (source, identifier, message, click, now(), -1 if initial and delivered else 0))
        db.execute("INSERT OR IGNORE INTO metadata VALUES ('initialized',?)", (now(),))


def deliver(settings, client):
    collect(settings)
    sent = 0
    with connect(database(settings)) as db:
        rows = db.execute("SELECT * FROM outbox WHERE sent=0 AND next_at<=? ORDER BY created,rowid LIMIT 30", (now(),)).fetchall()
        for row in rows:
            try:
                receipt = client.send(row["message"], click=row["click"],
                                      priority=4 if row["source"] == "user-report" else 3)
            except NtfyError as error:
                with db:
                    db.execute("UPDATE outbox SET attempts=attempts+1,next_at=?,error=? WHERE source=? AND id=?",
                               (now() + min(300, 30 * 2 ** min(row["attempts"], 4)), str(error), row["source"], row["id"]))
                return sent, False
            with db:
                db.execute("UPDATE outbox SET sent=?,receipt=?,error='' WHERE source=? AND id=?",
                           (now(), receipt, row["source"], row["id"]))
            sent += 1
    return sent, True


def state(settings):
    if not database(settings).exists():
        return None
    with connect(database(settings), "ro") as db:
        count = db.execute("SELECT count(*) FROM outbox WHERE sent=0").fetchone()[0]
        success = db.execute("SELECT max(sent) FROM outbox WHERE sent>0").fetchone()[0]
    return {"queued": count, "last_success": success}


def main():
    os.umask(0o077)
    settings = Settings.from_env()
    if settings.role != "primary" or not os.environ.get("NTFY_URL"):
        return 0
    try:
        sent, ok = deliver(settings, Ntfy(os.environ["NTFY_URL"], os.environ.get("NTFY_TOKEN", "")))
        print(f"ntfy_sent={sent} delivery_ok={int(ok)}")
        return 0 if ok else 1
    except (NtfyError, OSError, sqlite3.Error):
        print("ntfy delivery unavailable; messages remain queued")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
