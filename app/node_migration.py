"""Synchronize managed clients and atomically move cabinet links to a VPN node."""

from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from .db import account_comment, connect, now, transaction, DEFAULT_PLATFORM
from .xui import PanelError


def prepare_links(panel, accounts):
    links = {}
    active_ids = set()
    for account in accounts:
        client_id, email = panel.identity(account["id"])
        active_ids.add(email)
        deadline = (account["access_until"] or 0) * 1000
        enabled = bool(account["enabled"] and (not deadline or deadline > now() * 1000))
        record = panel.find_client(email)
        if record is None:
            panel.request("clients/add", {"client": {
                "id": client_id, "email": email, "flow": panel.settings.flow,
                "enable": enabled, "expiryTime": deadline, "totalGB": 0,
                "limitIp": int(account["platform"] != DEFAULT_PLATFORM), "reset": 0,
                "comment": account_comment(account["login"], account["platform"]),
            }, "inboundIds": panel.inbound_ids})
        else:
            panel.check_identity(record, client_id, email)
            panel.set_expiry(account["id"], account["access_until"] or 0, enabled=enabled)
        record = panel.request("clients/get/" + email)
        client = panel.check_identity(record, client_id, email)
        if (client.get("enable") is not enabled or client.get("expiryTime") != deadline
                or client.get("limitIp", 0) != int(account["platform"] != DEFAULT_PLATFORM)):
            raise PanelError("migration_client_mismatch")
        result = panel.request("clients/links/" + email)
        if not isinstance(result, list):
            raise PanelError("migration_links")
        for link in result:
            parsed = urlsplit(link)
            if panel.link_matches(parsed, client_id) and len(link.encode()) <= 8000:
                links[account["id"]] = panel.stable_link(link, "Connection")
                break
        if account["id"] not in links:
            raise PanelError("migration_link_missing")
    # Only our UUID-based clients may be removed, and only on this inbound.
    for record in panel.request("clients/list") or []:
        email = record.get("email", "")
        if email.startswith("access-site-") and email not in active_ids:
            identity = email.removeprefix("access-site-")
            try:
                client_id, _ = panel.identity(identity)
            except ValueError:
                continue
            detail = panel.request("clients/get/" + email)
            panel.check_identity(detail, client_id, email)
            panel.remove(identity)
    return links


def publish_links(store, revision, links):
    """Compare revision and replace every link in one transaction, preserving credentials."""
    with connect(store.data) as db, transaction(db):
        if db.execute("SELECT revision FROM state").fetchone()[0] != revision:
            raise ValueError("Account data changed; synchronize clients again")
        accounts = db.execute("SELECT id,login,config FROM accounts").fetchall()
        if set(links) != {row["id"] for row in accounts}:
            raise ValueError("Every account needs a prepared link")
        for row in accounts:
            if row["config"] == links[row["id"]]:
                continue
            change = uuid4().hex
            db.execute("UPDATE accounts SET config=?,config_at=? WHERE id=?", (links[row["id"]], now(), row["id"]))
            db.execute("UPDATE state SET revision=revision+1,change_id=?", (change,))
            db.execute("INSERT INTO audit SELECT revision,?,'config',?,change_id FROM state", (now(), row["login"]))


def synchronize_retiring_panel(panel, accounts):
    """Keep old imported links subject to revocations and expiry during migration."""
    current = {panel.identity(row["id"])[1]: row for row in accounts}
    for client in panel.request("clients/list") or []:
        email = client.get("email", "")
        if not email.startswith("access-site-"):
            continue
        account_id = email.removeprefix("access-site-")
        try:
            panel.identity(account_id)
        except ValueError:
            continue
        account = current.get(email)
        if not account or not account["enabled"]:
            panel.remove(account_id)
        else:
            deadline = account["access_until"] or 0
            panel.set_expiry(account_id, deadline, enabled=not deadline or deadline > now())
