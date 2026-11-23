import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .access_term import MAX_ACCESS_UNTIL


SCHEMA_VERSION = 1
PLATFORMS = {"any": "Любая", "ios": "iOS", "android": "Android", "windows": "Windows"}
DEFAULT_PLATFORM = "any"
PLATFORM_COLUMN = "platform TEXT NOT NULL DEFAULT 'any' CHECK (platform IN ('any', 'ios', 'android', 'windows'))"
RESERVE_ENABLED_COLUMN = "reserve_enabled INTEGER NOT NULL DEFAULT 1 CHECK (reserve_enabled IN (0, 1))"
ACCESS_UNTIL_COLUMN = f"access_until INTEGER CHECK (access_until BETWEEN 1 AND {MAX_ACCESS_UNTIL})"
ACCESS_DAY_COLUMN = "access_day INTEGER CHECK (access_day BETWEEN 1 AND 31)"
LEGACY_ACCOUNT_FIELDS = "id, login, access_index, password_hash, enabled, auth_version, config, config_at"
ACCOUNT_FIELDS = f"{LEGACY_ACCOUNT_FIELDS}, platform, reserve_enabled, access_until, access_day"
AUDIT_FIELDS = "revision, happened_at, action, login, change_id"
AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    revision INTEGER PRIMARY KEY,
    happened_at INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('create', 'config', 'password', 'revoke', 'enable', 'delete', 'reserve', 'access')),
    login TEXT NOT NULL,
    change_id TEXT NOT NULL
)
"""
DATA_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    origin_id TEXT NOT NULL,
    change_id TEXT NOT NULL,
    access_key_id TEXT NOT NULL
);
INSERT OR IGNORE INTO state VALUES (1, 0, '', '', '');
CREATE TABLE IF NOT EXISTS issued_codes (
    access_index TEXT PRIMARY KEY NOT NULL
);
CREATE TABLE IF NOT EXISTS password_vault (
    access_index TEXT PRIMARY KEY NOT NULL,
    ciphertext TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY NOT NULL,
    login TEXT UNIQUE NOT NULL,
    access_index TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    auth_version TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '',
    config_at INTEGER,
    {PLATFORM_COLUMN},
    {RESERVE_ENABLED_COLUMN},
    {ACCESS_UNTIL_COLUMN},
    {ACCESS_DAY_COLUMN}
);
{AUDIT_SCHEMA};
"""
LOCAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    auth_version TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
    bucket TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_status (
    direction TEXT PRIMARY KEY,
    last_success INTEGER,
    revision INTEGER,
    last_attempt INTEGER NOT NULL,
    error TEXT
);
"""


def now():
    return int(time.time())


def account_comment(login, platform):
    return f"{login} · {PLATFORMS[platform]}"


@contextmanager
def connect(path: Path, mode="rw"):
    connection = sqlite3.connect(f"{path.as_uri()}?mode={mode}", uri=True, timeout=5)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        yield connection
    finally:
        connection.close()


@contextmanager
def transaction(connection):
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        yield connection


class Store:
    def __init__(self, directory):
        self.directory = directory.resolve()
        self.data = self.directory / "accounts.sqlite3"
        self.local = self.directory / "local.sqlite3"

    def initialize(self, primary, access_key_id):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        for path, schema in ((self.data, DATA_SCHEMA), (self.local, LOCAL_SCHEMA)):
            with connect(path, "rwc") as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, SCHEMA_VERSION):
                    raise ValueError("Unsupported schema version")
                connection.execute("PRAGMA journal_mode = WAL")
                with connection:
                    connection.executescript(schema)
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                if path == self.data:
                    with transaction(connection):
                        columns = {column["name"] for column in connection.execute("PRAGMA table_info(accounts)")}
                        if "platform" not in columns:
                            connection.execute(f"ALTER TABLE accounts ADD COLUMN {PLATFORM_COLUMN}")
                        if "reserve_enabled" not in columns:
                            connection.execute(f"ALTER TABLE accounts ADD COLUMN {RESERVE_ENABLED_COLUMN}")
                        if "access_until" not in columns:
                            connection.execute(f"ALTER TABLE accounts ADD COLUMN {ACCESS_UNTIL_COLUMN}")
                        if "access_day" not in columns:
                            connection.execute(f"ALTER TABLE accounts ADD COLUMN {ACCESS_DAY_COLUMN}")
                        audit_schema = connection.execute("SELECT sql FROM sqlite_schema WHERE name = 'audit'").fetchone()[0]
                        if "'access'" not in audit_schema:
                            connection.execute("ALTER TABLE audit RENAME TO audit_legacy")
                            connection.execute(AUDIT_SCHEMA)
                            connection.execute(f"INSERT INTO audit ({AUDIT_FIELDS}) SELECT {AUDIT_FIELDS} FROM audit_legacy")
                            connection.execute("DROP TABLE audit_legacy")
                        connection.execute(
                            "UPDATE state SET access_key_id = ? WHERE access_key_id = ''", (access_key_id,)
                        )
                        current_key = connection.execute("SELECT access_key_id FROM state").fetchone()[0]
                        if current_key != access_key_id:
                            raise ValueError("Access key does not match database")
                        if primary:
                            origin_id = uuid4().hex
                            connection.execute(
                                "UPDATE state SET origin_id = ?, change_id = ? WHERE change_id = ''",
                                (origin_id, origin_id),
                            )

    def account(self, column, value):
        query = {
            "login": "SELECT * FROM accounts WHERE login = ?",
            "id": "SELECT * FROM accounts WHERE id = ?",
            "access_index": "SELECT * FROM accounts WHERE access_index = ?",
        }[column]
        with connect(self.data, "ro") as connection:
            return connection.execute(query, (value,)).fetchone()

    def overview(self):
        with connect(self.data, "ro") as connection, connection:
            connection.execute("BEGIN")
            users = connection.execute(
                "SELECT id, login, enabled, config_at, config, platform, reserve_enabled, access_until "
                "FROM accounts ORDER BY login"
            ).fetchall()
            audit = connection.execute("SELECT * FROM audit ORDER BY revision DESC LIMIT 50").fetchall()
            revision = connection.execute("SELECT revision FROM state").fetchone()[0]
        return users, audit, revision

    def change(self, action, *, account_id=None, login=None, access_index=None, password_hash=None, config=None,
               platform=DEFAULT_PLATFORM, reserve_enabled=False, access_until=None, access_day=None):
        with connect(self.data) as connection, transaction(connection):
            timestamp = now()
            if action in {"create", "password"}:
                if not connection.execute(
                    "INSERT OR IGNORE INTO issued_codes VALUES (?)", (access_index,)
                ).rowcount:
                    raise CodeAlreadyIssued
            if action == "create":
                connection.execute(
                    f"INSERT INTO accounts ({ACCOUNT_FIELDS}) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
                    (account_id or uuid4().hex, login, access_index, password_hash, uuid4().hex,
                     config or "", timestamp if config else None, platform, reserve_enabled, access_until, access_day),
                )
            else:
                account = connection.execute(
                    "SELECT login, reserve_enabled FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()
                if account is None:
                    raise LookupError
                if action == "reserve" and account["reserve_enabled"] == reserve_enabled:
                    return
                login = account["login"]
                query, args = {
                    "config": ("UPDATE accounts SET config = ?, config_at = ? WHERE id = ?", (config, timestamp)),
                    "reserve": ("UPDATE accounts SET reserve_enabled = ? WHERE id = ?", (reserve_enabled,)),
                    "access": ("UPDATE accounts SET access_until = ?, access_day = ? WHERE id = ?", (access_until, access_day)),
                    "password": (
                        "UPDATE accounts SET access_index = ?, password_hash = ?, auth_version = ? WHERE id = ?",
                        (access_index, password_hash, uuid4().hex),
                    ),
                    "revoke": ("UPDATE accounts SET enabled = 0, auth_version = ? WHERE id = ?", (uuid4().hex,)),
                    "enable": ("UPDATE accounts SET enabled = 1, auth_version = ? WHERE id = ?", (uuid4().hex,)),
                    "delete": ("DELETE FROM accounts WHERE id = ?", ()),
                }[action]
                connection.execute(query, (*args, account_id))
            connection.execute("UPDATE state SET revision = revision + 1, change_id = ?", (uuid4().hex,))
            connection.execute(
                "INSERT INTO audit SELECT revision, ?, ?, ?, change_id FROM state", (timestamp, action, login)
            )

    def sync_status(self, direction):
        with connect(self.local, "ro") as connection:
            return connection.execute("SELECT * FROM sync_status WHERE direction = ?", (direction,)).fetchone()

    def record_sync(self, direction, revision=None, error=None):
        with connect(self.local) as connection, transaction(connection):
            timestamp = now()
            connection.execute(
                """INSERT INTO sync_status VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(direction) DO UPDATE SET
                       last_success = COALESCE(excluded.last_success, sync_status.last_success),
                       revision = COALESCE(excluded.revision, sync_status.revision),
                       last_attempt = excluded.last_attempt,
                       error = excluded.error""",
                (direction, timestamp if error is None else None, revision, timestamp, error),
            )


class CodeAlreadyIssued(Exception):
    pass
