from uuid import uuid4

from .db import account_comment, connect, now, transaction
from .xui import PanelError


PATH = "/internal/reserve"
TTL = 24 * 3600
LEGACY_TTL = 12 * 3600  # Requests without a stored deadline were issued before per-request expiry.
COOLDOWN = 24 * 3600
RETENTION = 3 * 86400


class ReserveLinks:
    def __init__(self, store, panel):
        self.store = store
        self.path = store.directory / "reserve.sqlite3"
        self.panel = panel

    def initialize(self):
        with connect(self.path, "rwc") as connection, connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                    client_id TEXT PRIMARY KEY NOT NULL,
                    account_id TEXT NOT NULL,
                    requested_at INTEGER NOT NULL,
                    config TEXT
                );
                CREATE INDEX IF NOT EXISTS requests_account ON requests (account_id, requested_at);
                CREATE TABLE IF NOT EXISTS request_deadlines (
                    client_id TEXT PRIMARY KEY NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS request_deadline_delete AFTER DELETE ON requests
                BEGIN
                    DELETE FROM request_deadlines WHERE client_id = OLD.client_id;
                END;
            """)

    @staticmethod
    def latest(connection, account_id):
        return connection.execute(
            "SELECT * FROM requests LEFT JOIN request_deadlines USING (client_id) "
            "WHERE account_id = ? ORDER BY requested_at DESC LIMIT 1", (account_id,)
        ).fetchone()

    @staticmethod
    def save_deadline(connection, client_id, expires_at):
        connection.execute(
            "INSERT INTO request_deadlines VALUES (?, ?) "
            "ON CONFLICT(client_id) DO UPDATE SET expires_at = excluded.expires_at", (client_id, expires_at),
        )

    @staticmethod
    def describe(row, timestamp, access_until):
        if not row or row["config"] is None:
            return {"next_at": 0, "link": None}
        requested_at = row["requested_at"]
        expires_at = row["expires_at"] or requested_at + LEGACY_TTL
        if access_until is not None:
            expires_at = min(expires_at, access_until)
        link = None
        if expires_at > timestamp:
            link = {"config": row["config"], "expires_at": expires_at}
        next_at = requested_at + COOLDOWN
        return {"next_at": next_at if next_at > timestamp else 0, "link": link}

    def status(self, account):
        with connect(self.path, "ro") as connection:
            return self.describe(self.latest(connection, account["id"]), now(), account["access_until"])

    def issue(self, account):
        access_until = account["access_until"]
        with connect(self.path) as connection:
            # Commit the identifier before calling 3x-ui so even an interrupted request can be retried or cleaned up.
            with transaction(connection):
                timestamp = now()
                row = self.latest(connection, account["id"])
                if row and row["config"] is not None and row["requested_at"] + COOLDOWN > timestamp:
                    return self.describe(row, timestamp, access_until)
                if (row is None or row["config"] is not None
                        or (row["expires_at"] or row["requested_at"] + LEGACY_TTL) <= timestamp):
                    expires_at = min(timestamp + TTL, access_until) if access_until is not None else timestamp + TTL
                    if expires_at <= timestamp:
                        raise PanelError("reserve_expired")
                    client_id = uuid4().hex
                    connection.execute("INSERT INTO requests VALUES (?, ?, ?, NULL)", (client_id, account["id"], timestamp))
                    self.save_deadline(connection, client_id, expires_at)
            with transaction(connection):
                row = self.latest(connection, account["id"])
                if row["config"] is None:
                    expires_at = row["expires_at"] or row["requested_at"] + LEGACY_TTL
                    timestamp = now()
                    if expires_at <= timestamp or (access_until is not None and access_until <= timestamp):
                        raise PanelError("reserve_expired")
                    if access_until is not None and expires_at > access_until:
                        expires_at = access_until
                        self.panel.set_expiry(row["client_id"], expires_at, enabled=True)
                        self.save_deadline(connection, row["client_id"], expires_at)
                    platform = account["platform"]
                    config = self.panel.issue(
                        row["client_id"], expires_at, comment=account_comment(account["login"], platform),
                        platform=platform, reserve=True,
                    )
                    connection.execute("UPDATE requests SET config = ? WHERE client_id = ?",
                                       (config, row["client_id"]))
                    row = self.latest(connection, account["id"])
                return self.describe(row, now(), access_until)

    def cleanup(self):
        with connect(self.path) as connection:
            timestamp = now()
            failed = False
            active = connection.execute(
                "SELECT client_id, account_id, COALESCE(expires_at, requested_at + ?) AS deadline "
                "FROM requests LEFT JOIN request_deadlines USING (client_id) "
                "WHERE config != '' AND COALESCE(expires_at, requested_at + ?) > ?",
                (LEGACY_TTL, LEGACY_TTL, timestamp),
            ).fetchall()
            for client_id, account_id, deadline in active:
                account = self.store.account("id", account_id)
                access_until = account["access_until"] if account else None
                if access_until is None or access_until >= deadline:
                    continue
                try:
                    self.panel.set_expiry(client_id, access_until, enabled=access_until > timestamp)
                except PanelError:
                    failed = True
                    continue
                with connection:
                    self.save_deadline(connection, client_id, access_until)
            with connection:
                connection.execute(
                    "UPDATE requests SET config = '' WHERE config != '' AND client_id IN ("
                    "SELECT client_id FROM requests LEFT JOIN request_deadlines USING (client_id) "
                    "WHERE COALESCE(expires_at, requested_at + ?) <= ?)", (LEGACY_TTL, timestamp),
                )
            due = connection.execute(
                "SELECT client_id FROM requests LEFT JOIN request_deadlines USING (client_id) "
                "WHERE COALESCE(expires_at, requested_at + ?) <= ?",
                (LEGACY_TTL, timestamp - RETENTION),
            ).fetchall()
            for (client_id,) in due:
                try:
                    self.panel.remove(client_id)
                except PanelError:
                    failed = True
                    continue
                with connection:
                    connection.execute("DELETE FROM requests WHERE client_id = ?", (client_id,))
            if failed:
                raise PanelError("reserve_cleanup")
