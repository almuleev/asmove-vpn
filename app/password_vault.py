"""Recoverable user codes, encrypted separately from authentication hashes."""
import base64
import hmac
from cryptography.fernet import Fernet, InvalidToken
from .auth import access_index
from .db import connect


def cipher(key):
    return Fernet(base64.urlsafe_b64encode(hmac.digest(key, b'user-code-vault-v1', 'sha256')))


def remember(store, key, code):
    index = access_index(key, code)
    encrypted = cipher(key).encrypt(code.encode()).decode()
    with connect(store.data) as db, db:
        db.execute('INSERT OR REPLACE INTO password_vault VALUES (?, ?)', (index, encrypted))


def retrieve(store, key, account):
    with connect(store.data, 'ro') as db:
        row = db.execute('SELECT ciphertext FROM password_vault WHERE access_index = ?',
                         (account['access_index'],)).fetchone()
    if row is None:
        return None
    try:
        code = cipher(key).decrypt(row[0].encode()).decode()
    except (InvalidToken, UnicodeError):
        return None
    return code if hmac.compare_digest(access_index(key, code), account['access_index']) else None
