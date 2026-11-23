import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .xui import PanelSettings


@dataclass(frozen=True)
class Settings:
    role: str
    origin: str
    data_dir: Path
    secret: bytes
    access_key: bytes
    admin_hash: str
    stale_after: int = 300
    panel: PanelSettings | None = None
    reserve_export: bool = False
    launcher_origin: str | None = None
    admin_relay_key: str | None = None
    admin_primary_origin: str | None = None
    admin_peer_ip: str | None = None
    reserve_origin: str | None = None
    emergency_until: int | None = None
    emergency_controller: str | None = None
    portal_origin: str | None = None
    infrastructure_config: Path | None = None
    replication_enabled: bool = True

    @property
    def access_key_id(self):
        return hashlib.sha256(self.access_key).hexdigest()

    @classmethod
    def from_env(cls):
        try:
            role = os.environ["SITE_ROLE"]
            replication = os.environ.get('SITE_REPLICATION_ENABLED', '0')
            if replication not in ('0', '1'):
                raise ValueError
            origin = os.environ["SITE_ORIGIN"]
            data_dir = Path(os.environ["SITE_DATA_DIR"])
            secret = bytes.fromhex(os.environ["SITE_SECRET"])
            access_key = bytes.fromhex(os.environ["SITE_ACCESS_KEY"])
            admin_hash = os.environ["SITE_ADMIN_HASH"]
            launcher_origin = os.environ.get("SITE_LAUNCHER_ORIGIN") or None
            portal_origin = os.environ.get("SITE_PORTAL_ORIGIN") or None
            relay_key = os.environ.get("SITE_ADMIN_RELAY_KEY") or None
            primary_origin = os.environ.get("SITE_ADMIN_PRIMARY_ORIGIN") or None
            reserve_origin = os.environ.get("SITE_RESERVE_ORIGIN") or None
            emergency_controller = os.environ.get("SITE_EMERGENCY_CONTROLLER") or None
            emergency_until = int(os.environ["SITE_EMERGENCY_UNTIL"]) if "SITE_EMERGENCY_UNTIL" in os.environ else None
            reserve_export = os.environ.get("SITE_RESERVE_EXPORT") == "1"
            panel = PanelSettings.from_env()
            if emergency_until is not None and (
                emergency_until <= 0 or role != "replica" or not reserve_export or not panel
                or primary_origin or reserve_origin
            ):
                raise ValueError
            peer_ip = os.environ.get("SITE_ADMIN_PEER_IP") or None
            if peer_ip:
                peer_ip = str(ipaddress.ip_address(peer_ip))
            if relay_key and not re.fullmatch(r"[0-9a-f]{64}", relay_key):
                raise ValueError
            if primary_origin and (
                not relay_key or not re.fullmatch(r"https://[a-z0-9.-]+(?::[0-9]+)?", primary_origin)
                or primary_origin == origin
            ):
                raise ValueError
            if reserve_origin and (
                not relay_key or not re.fullmatch(r"https://[a-z0-9.-]+(?::[0-9]+)?", reserve_origin)
                or reserve_origin == origin
            ):
                raise ValueError
            if emergency_controller and (role != "primary" or reserve_origin or reserve_export or not re.fullmatch(
                r"https://(?:[a-z0-9.-]+|functions\.yandexcloud\.net/[a-z0-9]{20})", emergency_controller
            )):
                raise ValueError
            if launcher_origin:
                launcher = urlsplit(launcher_origin)
                if (
                    launcher_origin != f"https://{launcher.netloc}"
                    or not re.fullmatch(r"[a-z0-9.-]+(?::[0-9]+)?", launcher.netloc)
                ):
                    raise ValueError
            if portal_origin and not re.fullmatch(r"https://[a-z0-9.-]+", portal_origin):
                raise ValueError
            parsed = urlsplit(origin)
            if (
                role not in {"primary", "replica"}
                or parsed.scheme != "https"
                or not re.fullmatch(r"[a-z0-9.-]+(?::[0-9]+)?", parsed.netloc)
                or origin != f"https://{parsed.netloc}"
                or not data_dir.is_absolute()
                or len(secret) != 32
                or len(access_key) != 32
                or not admin_hash.startswith("$argon2id$")
            ):
                raise ValueError
        except (KeyError, ValueError):
            raise SystemExit("Invalid or missing SITE_* environment settings") from None
        infrastructure = os.environ.get("SITE_INFRASTRUCTURE_CONFIG")
        if infrastructure and (role != "primary" or not Path(infrastructure).is_absolute()):
            raise SystemExit("Infrastructure requires a primary server and an absolute config path")
        return cls(role, origin, data_dir, secret, access_key, admin_hash,
                   panel=panel, reserve_export=reserve_export,
                   launcher_origin=launcher_origin, admin_relay_key=relay_key,
                   admin_primary_origin=primary_origin, admin_peer_ip=peer_ip, reserve_origin=reserve_origin,
                   emergency_until=emergency_until, emergency_controller=emergency_controller,
                   portal_origin=portal_origin,
                   infrastructure_config=Path(infrastructure) if infrastructure else None,
                   replication_enabled=replication == '1')
