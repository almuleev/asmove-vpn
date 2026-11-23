import hashlib
import hmac
import http.client
import json
import ipaddress
import math
import os
from pathlib import Path
import re
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID

from .db import DEFAULT_PLATFORM, now


MAX_RESPONSE = 4 * 1024 * 1024


class PanelError(Exception):
    pass


class LocalPanelHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, loopback, port, server_name, context):
        super().__init__(server_name, port, timeout=4, context=context)
        self.loopback = loopback
        self.context = context

    def connect(self):
        connection = socket.create_connection((self.loopback, self.port), self.timeout)
        try:
            self.sock = self.context.wrap_socket(connection, server_hostname=self.host)
        except OSError:
            connection.close()
            raise


@dataclass(frozen=True)
class PanelSettings:
    url: str
    inbound: int
    public_address: str
    token: str = field(repr=False)
    tls_pin: str = ""
    flow: str = ""
    tls_verify_public_address: bool = False
    companion_inbounds: tuple[int, ...] = ()

    @classmethod
    def from_env(cls):
        url = os.environ.get("SITE_XUI_URL", "")
        if not url:
            return None
        try:
            inbound = int(os.environ["SITE_XUI_INBOUND"])
            public_address = os.environ["SITE_XUI_ADDRESS"]
            token = os.environ["SITE_XUI_TOKEN"]
            pin = os.environ.get("SITE_XUI_TLS_SHA256", "").lower().replace(":", "")
            flow = os.environ.get("SITE_XUI_FLOW", "")
            verify_public = os.environ.get("SITE_XUI_TLS_VERIFY_PUBLIC_ADDRESS", "0")
            companions = os.environ.get("SITE_XUI_COMPANION_INBOUNDS", "")
            if companions and not re.fullmatch(r"[1-9][0-9]*(?:,[1-9][0-9]*)?", companions):
                raise ValueError
            companion_inbounds = tuple(int(value) for value in companions.split(",") if value)
            address = urlsplit(url)
            public = urlsplit(f"https://{public_address}")
            if (
                address.scheme not in {"http", "https"}
                or address.hostname not in {"127.0.0.1", "::1"}
                or address.username is not None or address.password is not None
                or address.query or address.fragment or not address.port
                or not re.fullmatch(r"(?:/[A-Za-z0-9_.~-]+)*/?", address.path)
                or inbound <= 0
                or not re.fullmatch(r"[!-~]{16,512}", token)
                or (pin and (address.scheme != "https" or not re.fullmatch(r"[a-f0-9]{64}", pin)))
                or verify_public not in {"0", "1"}
                or (verify_public == "1" and (address.scheme != "https" or pin))
                or not re.fullmatch(r"[a-z0-9.-]+:[1-9][0-9]{0,4}", public_address)
                or not public.port
                or not re.fullmatch(r"[a-z0-9-]{0,64}", flow)
                or inbound in companion_inbounds or len(set(companion_inbounds)) != len(companion_inbounds)
            ):
                raise ValueError
        except (KeyError, ValueError):
            raise SystemExit("Invalid 3x-ui settings in SITE_XUI_*") from None
        return cls(url, inbound, public_address, token, pin, flow, verify_public == "1", companion_inbounds)


class Panel:
    def __init__(self, settings):
        self.settings = settings
        self.address = urlsplit(settings.url)
        self.public = urlsplit(f"https://{settings.public_address}")

    @property
    def inbound_ids(self):
        return [self.settings.inbound, *self.settings.companion_inbounds]

    def request(self, path, payload=None):
        address = self.address
        if address.scheme == "https":
            # With a configured pin, verify the exact certificate before sending credentials.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) if self.settings.tls_pin else ssl.create_default_context()
            if self.settings.tls_pin:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            if self.settings.tls_verify_public_address:
                conn = LocalPanelHTTPSConnection(address.hostname, address.port, self.public.hostname, context)
            else:
                conn = http.client.HTTPSConnection(address.hostname, address.port, timeout=4, context=context)
        else:
            conn = http.client.HTTPConnection(address.hostname, address.port, timeout=4)
        headers = {
            "Authorization": f"Bearer {self.settings.token}",
            "Accept": "application/json",
            "Host": self.settings.public_address,
        }
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode()
        try:
            conn.connect()
            if self.settings.tls_pin:
                digest = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
                if not hmac.compare_digest(digest, self.settings.tls_pin):
                    raise PanelError("panel_tls")
            conn.request("GET" if payload is None else "POST", address.path.rstrip("/") + "/panel/api/" + path,
                         body=body, headers=headers)
            response = conn.getresponse()
            data = response.read(MAX_RESPONSE + 1)
            if response.status != 200 or len(data) > MAX_RESPONSE:
                raise PanelError(f"panel_http_{response.status}")
            result = json.loads(data)
            if not isinstance(result, dict) or result.get("success") is not True:
                raise PanelError("panel_rejected")
            return result.get("obj")
        except (OSError, http.client.HTTPException, ValueError, TypeError):
            raise PanelError("panel_unavailable") from None
        finally:
            conn.close()

    def inbound(self):
        result = self.request(f"inbounds/get/{self.settings.inbound}")
        if (
            not isinstance(result, dict) or result.get("id") != self.settings.inbound
            or result.get("protocol") != "vless" or result.get("enable") is not True
        ):
            raise PanelError("panel_inbound")
        return result

    @staticmethod
    def identity(account_id):
        return str(UUID(hex=account_id)), f"access-site-{account_id}"

    def link_matches(self, parsed, client_id):
        return (
            parsed.scheme == "vless" and parsed.username == client_id and parsed.password is None
            and parsed.hostname == self.public.hostname and parsed.port == self.public.port
        )

    def stable_link(self, link, label):
        """Use the approved Reality target instead of a random export SNI."""
        parsed = urlsplit(link)
        query = parse_qs(parsed.query)
        if query.get('type') == ['grpc'] and query.get('security') == ['reality']:
            stream = self.inbound().get('streamSettings', {})
            if isinstance(stream, str):
                stream = json.loads(stream or '{}')
            reality = stream.get('realitySettings', {})
            target = reality.get('target') or reality.get('dest')
            preferred = urlsplit('//'+target).hostname if isinstance(target, str) else None
            if preferred and preferred in reality.get('serverNames', []):
                fields = [(key,value) for key,value in parse_qsl(parsed.query, keep_blank_values=True)
                          if key not in ('sni', 'alpn')]
                fields.extend([('sni', preferred), ('alpn', 'h2')])
                parsed = parsed._replace(query=urlencode(fields))
        if query.get('type') == ['xhttp'] and query.get('security') == ['tls']:
            stream = self.inbound().get('streamSettings', {})
            if isinstance(stream, str):
                stream = json.loads(stream or '{}')
            transport = stream.get('xhttpSettings', {})
            fields = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
                      if key not in ('sni', 'fp', 'alpn', 'path', 'mode', 'host', 'flow', 'allowInsecure', 'insecure')]
            fields.extend([('sni', self.public.hostname), ('fp', 'ios'), ('alpn', 'h2'),
                           ('path', transport.get('path', '/')), ('mode', 'auto')])
            parsed = parsed._replace(query=urlencode(fields))
        return urlunsplit(parsed._replace(fragment=label))

    def manages(self, account):
        client_id, _ = self.identity(account["id"])
        try:
            return self.link_matches(urlsplit(account["config"]), client_id)
        except ValueError:
            return False

    def find_client(self, email):
        try:
            return self.request(f"clients/get/{email}")
        except PanelError as exc:
            if str(exc) != "panel_rejected":
                raise
            clients = self.request("clients/list") or []
            if not isinstance(clients, list) or any(entry.get("email") == email for entry in clients):
                raise exc
            return None

    def check_identity(self, record, client_id, email):
        if (
            not isinstance(record, dict) or not isinstance(record.get("client"), dict)
            or record["client"].get("uuid") != client_id or record["client"].get("email") != email
            or not isinstance(record.get("inboundIds"), list)
            or len(record["inboundIds"]) != len(self.inbound_ids)
            or set(record["inboundIds"]) != set(self.inbound_ids)
        ):
            raise PanelError("panel_identity")
        return record["client"]

    def issue(self, account_id, expires_at=0, *, comment="", platform=DEFAULT_PLATFORM, reserve=False):
        client_id, email = self.identity(account_id)
        deadline = expires_at * 1000
        limit_ip = int(platform != DEFAULT_PLATFORM)
        record = self.find_client(email)
        if record is None:
            self.inbound()
            client = {
                "id": client_id, "email": email, "flow": self.settings.flow, "enable": True,
                "expiryTime": deadline, "totalGB": 0, "limitIp": limit_ip, "reset": 0,
            }
            if comment:
                client["comment"] = comment
            self.request("clients/add", {"client": client, "inboundIds": self.inbound_ids})
            record = self.request(f"clients/get/{email}")
        client = self.check_identity(record, client_id, email)
        if client.get("enable") is not True or client.get("expiryTime") != deadline:
            raise PanelError("panel_expiry")
        if client.get("limitIp", 0) != limit_ip:
            raise PanelError("panel_ip_limit")
        if deadline:
            self.check_expiry(email, deadline, True)
        links = self.request(f"clients/links/{email}")
        if not isinstance(links, list):
            raise PanelError("panel_link")
        for link in links:
            try:
                parsed = urlsplit(link)
                if self.link_matches(parsed, client_id) and len(link.encode()) <= 8000:
                    label = "Backup" if reserve else "Connection"
                    return self.stable_link(link, label)
            except (ValueError, TypeError, AttributeError):
                continue
        raise PanelError("panel_link")

    def check_expiry(self, email, deadline, enabled):
        traffic = self.request(f"clients/traffic/{email}")
        if not isinstance(traffic, dict) or traffic.get("enable") is not enabled or traffic.get("expiryTime") != deadline:
            raise PanelError("panel_expiry")

    def set_expiry(self, account_id, expires_at, *, enabled):
        client_id, email = self.identity(account_id)
        record = self.find_client(email)
        if record is None:
            return False
        client = self.check_identity(record, client_id, email)
        deadline = expires_at * 1000
        if client.get("expiryTime") != deadline or client.get("enable") is not enabled:
            # The panel's read API uses uuid, while the write API takes the VLESS credential as id.
            payload = {**client, "id": client_id, "expiryTime": deadline, "enable": enabled}
            # The read API's WireGuard address string is unused by VLESS and invalid
            # in the update API. Updates fan out to every attached inbound in 3x-ui.
            payload.pop("allowedIPs", None)
            self.request(f"clients/update/{email}", payload)
        self.check_expiry(email, deadline, enabled)
        return True

    def remove(self, account_id):
        client_id, email = self.identity(account_id)
        record = self.find_client(email)
        if record is not None:
            self.check_identity(record, client_id, email)
            self.request(f"clients/del/{email}", {})
            if self.find_client(email) is not None:
                raise PanelError("panel_remove")


class PanelGroup(Panel):
    """Issue and revoke on both managed nodes while keeping one primary link."""

    def __init__(self, settings, directory):
        super().__init__(settings)
        self.secondary_path = Path(directory) / "secondary-panels.json"
        self.relay_path = Path(directory) / "tcp-relay.json"

    def relay_link(self, account, links):
        """Change only the endpoint of a validated native TCP/Reality profile."""
        if not self.relay_path.exists():
            return None
        try:
            relay = json.loads(self.relay_path.read_text())
            expiry = relay.get('expires_at', 0)
            if (not relay.get('enabled') or account['id'] not in relay.get('account_ids', [])
                    or (expiry is not None and (type(expiry) not in (int, float)
                        or not math.isfinite(expiry) or expiry <= now()))):
                return None
            host = str(ipaddress.IPv4Address(relay['public_host']))
            if not ipaddress.ip_address(host).is_global or type(relay['port']) is not int or not 1 <= relay['port'] <= 65535:
                return None
            client_id, _ = self.identity(account['id'])
            for link in links:
                parsed = urlsplit(link); query = parse_qs(parsed.query)
                if (parsed.scheme == 'vless' and parsed.username == client_id and parsed.password is None
                        and parsed.hostname == self.public.hostname and parsed.port == 443
                        and query.get('security') == ['reality'] and query.get('type', ['tcp'])[0] in ('tcp', 'raw')):
                    return urlunsplit(parsed._replace(netloc=f'{client_id}@{host}:{relay["port"]}', fragment='Connection-Relay'))
        except (OSError, ValueError, TypeError, KeyError):
            return None
        return None

    def secondaries(self):
        if not self.secondary_path.exists():
            return []
        try:
            values = json.loads(self.secondary_path.read_text())
            if not isinstance(values, dict) or len(values) > 1:
                raise ValueError
            result = []
            for value in values.values():
                settings = PanelSettings(**value)
                address = urlsplit(settings.url)
                if address.scheme not in {"http", "https"} or address.hostname != "127.0.0.1" or not address.port:
                    raise ValueError
                result.append(Panel(settings))
            return result
        except (OSError, ValueError, TypeError):
            raise PanelError("secondary_configuration") from None

    def issue(self, account_id, expires_at=0, **kwargs):
        link = super().issue(account_id, expires_at, **kwargs)
        for panel in self.secondaries():
            panel.issue(account_id, expires_at, **kwargs)
        return link

    def set_expiry(self, account_id, expires_at, *, enabled):
        result = super().set_expiry(account_id, expires_at, enabled=enabled)
        for panel in self.secondaries():
            if not panel.set_expiry(account_id, expires_at, enabled=enabled) and enabled and result:
                raise PanelError("secondary_client_missing")
        return result

    def remove(self, account_id):
        error = None
        for panel in [Panel(self.settings), *self.secondaries()]:
            try:
                panel.remove(account_id)
            except PanelError as exc:
                error = exc
        if error:
            raise error

    def additional_links(self, account):
        links = []
        client_id, email = self.identity(account["id"])
        if self.settings.companion_inbounds:
            try:
                self.check_identity(self.request("clients/get/" + email), client_id, email)
                for link in self.request("clients/links/" + email) or []:
                    parsed = urlsplit(link)
                    if (parsed.scheme == "vless" and parsed.username == client_id and parsed.password is None
                            and parsed.hostname == self.public.hostname and parsed.port != self.public.port
                            and len(link.encode()) <= 8000):
                        transport = parse_qs(parsed.query).get('type', ['tcp'])[0]
                        label = {'tcp': 'Connection-TCP', 'raw': 'Connection-TCP',
                                 'grpc': 'Connection-gRPC', 'xhttp': 'Connection-XHTTP'}.get(transport, 'Connection-Extra')
                        links.append(urlunsplit(parsed._replace(fragment=label)))
            except (PanelError, ValueError, TypeError, AttributeError):
                pass
        relay = self.relay_link(account, links)
        if relay:
            links.append(relay)
        try:
            panels = self.secondaries()
        except PanelError:
            return links
        for panel in panels:
            try:
                for link in panel.request("clients/links/" + email) or []:
                    if panel.link_matches(urlsplit(link), client_id) and len(link.encode()) <= 8000:
                        links.append(panel.stable_link(link, "Backup"))
                        break
            except (PanelError, ValueError, TypeError, AttributeError):
                continue
        return links
