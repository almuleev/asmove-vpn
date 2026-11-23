import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

from .auth import make_password
from .db import Store, connect
from .reserve import ReserveLinks
from .settings import Settings
from .sync import SyncError, backup, receive, restore, send, sync_health
from .xui import Panel, PanelError, PanelGroup
from .infrastructure import Infrastructure, InfrastructureError, Worker, load_config


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("credentials", "init", "status", "send", "receive", "backup", "check-panel", "sync-retiring-panel", "sync-secondary-panels", "prune-reserve", "infrastructure-tick", "infrastructure-check"):
        commands.add_parser(command)
    commands.add_parser("restore").add_argument("snapshot", type=Path)
    args = parser.parse_args()
    if args.command == "credentials":
        password, encoded = make_password()
        print(f"SITE_SECRET='{os.urandom(32).hex()}'\nSITE_ADMIN_HASH='{encoded}'")
        print(f"Пароль администратора (сохраните сейчас): {password}", file=sys.stderr)
        return 0

    settings = Settings.from_env()
    if args.command.startswith("infrastructure-"):
        if not settings.infrastructure_config or settings.role != "primary":
            print("Infrastructure is not configured on this primary", file=sys.stderr)
            return 1
        try:
            load_config(settings.infrastructure_config)
            if args.command == "infrastructure-tick":
                worker = Worker(Infrastructure(settings.data_dir, settings.infrastructure_config))
                worker.tick()
                if os.environ.get("TELEGRAM_BOT_TOKEN"):
                    from .reminders import Telegram
                    worker.notify(Telegram(os.environ["TELEGRAM_BOT_TOKEN"], os.environ["TELEGRAM_CHAT_ID"]), settings.origin)
            print("Infrastructure configuration verified" if args.command.endswith("check") else "Infrastructure checks completed")
            return 0
        except (OSError, ValueError, KeyError, InfrastructureError, sqlite3.Error):
            print("Infrastructure operation failed. Check configuration and the worker state.", file=sys.stderr)
            return 1
    store = Store(settings.data_dir)
    reserve = ReserveLinks(store, Panel(settings.panel)) if settings.reserve_export and settings.panel else None
    try:
        if args.command == "init":
            store.initialize(settings.role == "primary", settings.access_key_id)
            if reserve:
                reserve.initialize()
        elif args.command == "receive" and settings.role == "replica":
            revision = receive(store, sys.stdin.buffer)
            print(f"OK {revision}", flush=True)
        elif args.command == "prune-reserve":
            if reserve:
                reserve.cleanup()
        elif args.command == "send" and settings.role == "primary":
            if settings.replication_enabled:
                print(f"sent revision={send(store)}")
            else:
                print('Replica synchronization is disabled')
        elif args.command == "backup":
            print(f"backup revision={backup(store)}")
        elif args.command == "restore":
            print(f"restored revision={restore(store, args.snapshot)}")
        elif args.command == "check-panel":
            if not settings.panel:
                raise PanelError("panel_not_configured")
            Panel(settings.panel).inbound()
            print("3x-ui connection and inbound verified")
        elif args.command == "sync-retiring-panel":
            if settings.role != "primary" or not settings.panel:
                raise PanelError("primary_panel_required")
            from .node_migration import synchronize_retiring_panel
            synchronize_retiring_panel(Panel(settings.panel), store.overview()[0])
            print("Legacy VPN revocations and expiry synchronized")
        elif args.command == "sync-secondary-panels":
            if settings.role != "primary" or not settings.panel:
                raise PanelError("primary_panel_required")
            from .node_migration import prepare_links
            for secondary in PanelGroup(settings.panel, settings.data_dir).secondaries():
                prepare_links(secondary, store.overview()[0])
            print("Secondary VPN clients synchronized")
        elif args.command == "status":
            with connect(store.data, "ro") as connection:
                state = connection.execute("SELECT revision, change_id FROM state").fetchone()
            status, stale, pending = sync_health(store, settings.role, state["revision"], settings.stale_after)
            print(json.dumps({
                "role": settings.role, "ready": bool(state["change_id"]), "revision": state["revision"],
                "sync_stale": stale, "sync_pending": pending, "sync": dict(status) if status else {},
            }))
        else:
            raise SyncError("wrong_role")
    except (SyncError, PanelError, sqlite3.Error, OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, (SyncError, PanelError)) else type(exc).__name__
        print(f"{args.command} failed: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
