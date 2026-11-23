import http.client
import ipaddress
import json
import socket
import ssl
from pathlib import Path
from urllib.parse import urlencode, urlsplit


PATH = "/internal/admin/accounts"
MAX_REPLY = 1024 * 1024
CONTROLLER_ADDRESSES = Path("/run/access-site-reserve-network/controller-addresses")


class RelayError(Exception):
    pass


class ControllerConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, *, timeout):
        self.tls_context = ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self.tls_context)

    def connect(self):
        try:
            addresses = CONTROLLER_ADDRESSES.read_text(encoding="ascii").split()
        except FileNotFoundError:
            return super().connect()
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                continue
            try:
                sock = socket.create_connection((str(ip), self.port), self.timeout)
            except OSError:
                continue
            try:
                self.sock = self.tls_context.wrap_socket(sock, server_hostname=self.host)
                return
            except BaseException:
                sock.close()
                raise
        raise OSError("No reachable reserve controller address")


def request(settings, form=None):
    return exchange(settings.admin_primary_origin, settings.admin_relay_key, PATH, form, timeout=12)


def exchange(origin, key, path, form=None, *, timeout):
    target = urlsplit(origin)
    connection_class = http.client.HTTPSConnection
    if target.hostname == "functions.yandexcloud.net" and target.path and path == "/status":
        path = target.path + "?route=status"
        connection_class = ControllerConnection
    elif path == "/status" and target.hostname and target.hostname.endswith(".apigw.yandexcloud.net"):
        connection_class = ControllerConnection
    connection = connection_class(target.hostname, target.port, timeout=timeout)
    headers = {"Authorization": f"Bearer {key}"} if key is not None else {}
    body = None
    if form is not None:
        body = urlencode(form).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        connection.request("GET" if form is None else "POST", path, body=body, headers=headers)
        with connection.getresponse() as response:
            if response.status != 200:
                raise RelayError
            payload = response.read(MAX_REPLY + 1)
        if len(payload) > MAX_REPLY:
            raise RelayError
        return json.loads(payload)
    except (OSError, http.client.HTTPException, ValueError):
        raise RelayError from None
    finally:
        connection.close()
