import hashlib
import hmac
import re
import secrets
import threading

from argon2 import PasswordHasher, Type, exceptions

from .access_term import expired
from .db import connect, now, transaction


HASHER = PasswordHasher(time_cost=3, memory_cost=32768, parallelism=1, type=Type.ID)
HASH_SLOTS = threading.BoundedSemaphore(2)
SESSION_COOKIE = "__Host-access-session"
LOGIN_COOKIE = "__Host-access-login"
LOGIN_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{2,31}")
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
ACCESS_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ACCESS_PATTERN = re.compile(f"[{ACCESS_ALPHABET}]{{6}}")
WINDOW = 300


def token():
    return secrets.token_urlsafe(32)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def make_password():
    password = secrets.token_urlsafe(24)
    with HASH_SLOTS:
        return password, HASHER.hash(password)


def verify(encoded, password):
    try:
        return HASHER.verify(encoded, password)
    except (exceptions.VerificationError, exceptions.InvalidHashError):
        return False


def access_index(key, password):
    return hmac.digest(key, f"lookup:{password}".encode(), "sha256").hex()


def access_secret(key, password):
    return hmac.digest(key, f"verify:{password}".encode(), "sha256")


def make_user_password(key):
    password = "".join(secrets.choice(ACCESS_ALPHABET) for _ in range(6))
    with HASH_SLOTS:
        encoded = HASHER.hash(access_secret(key, password))
    return password, access_index(key, password), encoded


class Auth:
    def __init__(self, settings, store):
        self.settings = settings
        self.store = store
        self.admin_version = digest(settings.admin_hash)
        self.dummy_hash = HASHER.hash(token())

    def sign(self, context, value):
        return hmac.digest(self.settings.secret, f"{context}:{value}".encode(), "sha256").hex()

    def allow_attempt(self, kind, ip):
        keys = [
            (self.sign("rate-ip", f"{kind}:{ip}"), 30, WINDOW),
            (self.sign("rate-all", kind), 12 if kind == "admin" else 40, WINDOW if kind == "admin" else 60),
        ]
        timestamp = now()
        with connect(self.store.local) as connection, transaction(connection):
            connection.execute("DELETE FROM attempts WHERE expires_at <= ?", (timestamp,))
            for key, limit, _ in keys:
                row = connection.execute("SELECT count FROM attempts WHERE bucket = ?", (key,)).fetchone()
                if row is not None and row["count"] >= limit:
                    return False
            connection.executemany(
                "INSERT INTO attempts VALUES (?, ?, 1) ON CONFLICT(bucket) DO UPDATE SET count = count + 1",
                ((key, timestamp + window) for key, _, window in keys),
            )
        return True

    def create_session(self, subject, version, ttl, old_token):
        session = token()
        timestamp = now()
        with connect(self.store.local) as connection, transaction(connection):
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (timestamp,))
            if TOKEN_PATTERN.fullmatch(old_token):
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (digest(old_token),))
            connection.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?)", (digest(session), subject, version, timestamp + ttl)
            )
        return session

    def get_session(self, session):
        if not TOKEN_PATTERN.fullmatch(session):
            return None, None
        with connect(self.store.local, "ro") as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?", (digest(session), now())
            ).fetchone()
        if row is None:
            return None, None
        if row["subject"] == "admin":
            if hmac.compare_digest(row["auth_version"], self.admin_version):
                return "admin", None
            return None, None
        account = self.store.account("id", row["subject"])
        if (account and account["enabled"] and not expired(account, now())
                and row["auth_version"] == account["auth_version"]):
            return "user", account
        return None, None

    def remove_session(self, session):
        with connect(self.store.local) as connection, connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (digest(session),))
