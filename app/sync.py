import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from .access_term import MAX_ACCESS_UNTIL
from .db import ACCOUNT_FIELDS, AUDIT_FIELDS, DEFAULT_PLATFORM, LEGACY_ACCOUNT_FIELDS, PLATFORMS, SCHEMA_VERSION
from .db import connect, now, transaction


MAX_SNAPSHOT = 32 * 1024 * 1024


class SyncError(Exception):
    pass


def sync_health(store, role, revision, stale_after):
    status = store.sync_status("sent" if role == "primary" else "received")
    last_success = status["last_success"] if status else None
    synced_revision = status["revision"] if status else None
    stale = last_success is None or now() - last_success > stale_after
    pending = (synced_revision if synced_revision is not None else 0) < revision
    return status, stale, pending


def snapshot(store, target):
    with target.open("xb"), connect(store.data, "ro") as source, connect(target) as destination:
        source.backup(destination)
        destination.execute("PRAGMA journal_mode = DELETE")
    return inspect(target)[0]


def inspect(path):
    if not 0 < path.stat().st_size <= MAX_SNAPSHOT:
        raise SyncError("snapshot_size")
    with connect(path, "ro") as connection, connection:
        connection.execute("BEGIN")
        if (
            connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
            or connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
            or connection.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok"
        ):
            raise SyncError("snapshot_invalid")
        state = connection.execute("SELECT singleton, revision, origin_id, change_id, access_key_id FROM state").fetchall()
        if len(state) != 1:
            raise SyncError("snapshot_invalid")
        singleton, revision, origin_id, change_id, key_id = state[0]
        if (
            singleton != 1 or not isinstance(revision, int) or revision < 0
            or not isinstance(origin_id, str) or not re.fullmatch(r"[a-f0-9]{32}", origin_id)
            or not isinstance(change_id, str) or not re.fullmatch(r"[a-f0-9]{32}", change_id)
            or not isinstance(key_id, str) or not re.fullmatch(r"[a-f0-9]{64}", key_id)
        ):
            raise SyncError("snapshot_invalid")
        columns = {column["name"] for column in connection.execute("PRAGMA table_info(accounts)")}
        platform = "platform" if "platform" in columns else f"'{DEFAULT_PLATFORM}' AS platform"
        has_reserve_enabled = "reserve_enabled" in columns
        reserve_enabled = "reserve_enabled" if has_reserve_enabled else "1 AS reserve_enabled"
        has_access_term = {"access_until", "access_day"} <= columns
        access_term = "access_until, access_day" if has_access_term else "NULL AS access_until, NULL AS access_day"
        accounts = connection.execute(
            f"SELECT {LEGACY_ACCOUNT_FIELDS}, {platform}, {reserve_enabled}, {access_term} FROM accounts"
        ).fetchall()
        codes = connection.execute("SELECT access_index FROM issued_codes").fetchall()
        indexes = {row["access_index"] for row in codes}
        if any(account["access_index"] not in indexes or account["platform"] not in PLATFORMS
               or account["reserve_enabled"] not in (0, 1) for account in accounts):
            raise SyncError("snapshot_invalid")
        for account in accounts:
            until, day = account["access_until"], account["access_day"]
            if until is None and day is None:
                continue
            if type(until) is not int or not 1 <= until <= MAX_ACCESS_UNTIL or type(day) is not int or not 1 <= day <= 31:
                raise SyncError("snapshot_invalid")
        audit = connection.execute(f"SELECT {AUDIT_FIELDS} FROM audit ORDER BY revision").fetchall()
        if len(audit) != revision or any(row["revision"] != i for i, row in enumerate(audit, 1)):
            raise SyncError("snapshot_invalid")
        if change_id != (audit[-1]["change_id"] if revision else origin_id):
            raise SyncError("snapshot_invalid")
    return revision, origin_id, change_id, key_id, accounts, codes, audit, has_reserve_enabled, has_access_term


def apply_snapshot(store, path, *, restore=False):
    revision, origin_id, change_id, key_id, accounts, codes, audit, has_reserve_enabled, has_access_term = inspect(path)
    with connect(store.data) as connection, transaction(connection):
        old_revision, old_origin, old_change_id, old_key_id = connection.execute(
            "SELECT revision, origin_id, change_id, access_key_id FROM state"
        ).fetchone()
        if old_key_id != key_id:
            raise SyncError("access_key_mismatch")
        if not restore and old_change_id:
            if revision < old_revision or origin_id != old_origin:
                raise SyncError("snapshot_conflict")
            ancestor = audit[old_revision - 1]["change_id"] if old_revision else origin_id
            if ancestor != old_change_id:
                raise SyncError("snapshot_conflict")
            if revision == old_revision:
                if has_reserve_enabled:
                    # During an upgrade, an older replica may have accepted this revision without the flag.
                    connection.executemany(
                        "UPDATE accounts SET reserve_enabled = ? WHERE id = ? AND reserve_enabled != ?",
                        ((row["reserve_enabled"], row["id"], row["reserve_enabled"]) for row in accounts),
                    )
                if has_access_term:
                    connection.executemany(
                        "UPDATE accounts SET access_until = ?1, access_day = ?2 WHERE id = ?3 "
                        "AND (access_until IS NOT ?1 OR access_day IS NOT ?2)",
                        ((row["access_until"], row["access_day"], row["id"]) for row in accounts),
                    )
                return revision
        connection.execute("DELETE FROM accounts")
        connection.execute("DELETE FROM audit")
        connection.execute("DELETE FROM issued_codes")
        connection.executemany("INSERT INTO issued_codes VALUES (?)", codes)
        connection.executemany(
            f"INSERT INTO accounts ({ACCOUNT_FIELDS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", accounts
        )
        connection.executemany(f"INSERT INTO audit ({AUDIT_FIELDS}) VALUES (?, ?, ?, ?, ?)", audit)
        connection.execute("UPDATE state SET revision = ?, origin_id = ?, change_id = ?", (revision, origin_id, change_id))
    if restore:
        with connect(store.local) as connection, transaction(connection):
            for table in ("sessions", "attempts", "sync_status"):
                connection.execute(f"DELETE FROM {table}")
    return revision


def receive(store, stream):
    try:
        with tempfile.TemporaryDirectory(dir=store.directory) as temporary:
            incoming = Path(temporary) / "incoming.sqlite3"
            remaining = MAX_SNAPSHOT
            with incoming.open("xb") as file:
                while chunk := stream.read(65536):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise SyncError("snapshot_size")
                    file.write(chunk)
            revision = apply_snapshot(store, incoming)
    except (OSError, sqlite3.Error, SyncError) as exc:
        reason = str(exc) if isinstance(exc, SyncError) else "receive_error"
        store.record_sync("received", error=reason)
        raise SyncError(reason) from None
    store.record_sync("received", revision=revision)
    return revision


def accept_reply(revision, reply):
    lines = reply.splitlines()
    if not 1 <= len(lines) <= 2 or lines[0] != f"OK {revision}".encode():
        raise SyncError("ssh_or_receiver")
    # Older replicas may include the former shared link during a rolling update.
    if len(lines) == 2 and (not lines[1].startswith(b"RESERVE ") or len(lines[1]) > 10000):
        raise SyncError("ssh_or_receiver")


def send(store):
    try:
        host = os.environ.get("SYNC_HOST", "")
        port = os.environ.get("SYNC_PORT", "22")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]*", host) or not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
            raise SyncError("peer_settings")
        ssh_dir = store.directory.parent / "sender"
        command = [
            "/usr/bin/ssh", "-F", "/dev/null", "-T", "-p", port,
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={ssh_dir / 'known_hosts'}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2", "-i", str(ssh_dir / "id_ed25519"),
            f"access-site-recv@{host}", "receive",
        ]
        with tempfile.TemporaryDirectory(dir=store.directory) as temporary:
            outgoing = Path(temporary) / "outgoing.sqlite3"
            revision = snapshot(store, outgoing)
            with outgoing.open("rb") as stream:
                result = subprocess.run(command, stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        timeout=45, check=False)
        if result.returncode != 0:
            raise SyncError("ssh_or_receiver")
        accept_reply(revision, result.stdout)
    except (OSError, sqlite3.Error, subprocess.TimeoutExpired, SyncError) as exc:
        reason = str(exc) if isinstance(exc, SyncError) else "send_error"
        store.record_sync("sent", error=reason)
        raise SyncError(reason) from None
    store.record_sync("sent", revision=revision)
    return revision


def backup(store):
    backups = store.directory / "backups"
    backups.mkdir(mode=0o700, exist_ok=True)
    name = f"access-{time.time_ns()}.sqlite3"
    with tempfile.TemporaryDirectory(dir=backups) as temporary:
        target = Path(temporary) / name
        revision = snapshot(store, target)
        with target.open("r+b") as file:
            os.fsync(file.fileno())
        target.replace(backups / name)
    cutoff = time.time() - 14 * 86400
    for old in backups.glob("access-*.sqlite3"):
        if old.is_file() and old.stat().st_mtime < cutoff:
            old.unlink(missing_ok=True)
    return revision


def restore(store, source):
    with tempfile.TemporaryDirectory(dir=store.directory) as temporary:
        copy = Path(temporary) / "restore.sqlite3"
        if not 0 < source.stat().st_size <= MAX_SNAPSHOT:
            raise SyncError("snapshot_size")
        shutil.copyfile(source, copy)
        return apply_snapshot(store, copy, restore=True)
