"""Shared settings and protocol for the CLI and desktop installer."""

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
from urllib.parse import urlsplit


DEFAULT_TARGET = "www.mozilla.org"
REMOTE_COMMAND = (
    'if [ "$(id -u)" = 0 ]; then exec python3 -; '
    'else exec sudo -n python3 -; fi'
)


def host(value):
    value = value.removeprefix("[").removesuffix("]")
    if "%" in value:
        raise ValueError("Введите IP-адрес или имя сервера без идентификатора интерфейса.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise ValueError("Введите IP-адрес или имя сервера.")
    return value


def port(value):
    if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535:
        raise ValueError("Номер порта должен быть от 1 до 65535.")
    return int(value)


@dataclass(frozen=True)
class Setup:
    ssh_host: str
    ssh_user: str
    ssh_port: int
    identity: Path | None
    address: str
    listen_port: int
    target: str

    @classmethod
    def from_input(cls, ssh_host, ssh_user, ssh_port, key, address, listen_port, target):
        ssh_host = host(ssh_host.strip())
        ssh_user = ssh_user.strip()
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]*", ssh_user):
            raise ValueError("Некорректное имя пользователя SSH.")
        ssh_port = port(ssh_port.strip())
        identity = None
        if key.strip():
            identity = Path(key.strip().strip('"')).expanduser().resolve()
            if not identity.is_file():
                raise ValueError("Файл SSH-ключа не найден.")
        address = host(address.strip() or ssh_host)
        listen_port = port(listen_port.strip())
        target = host(target.strip())
        if "." not in target or target == address:
            raise ValueError("Укажите отдельный домен REALITY.")
        try:
            ipaddress.ip_address(target)
        except ValueError:
            pass
        else:
            raise ValueError(f"Для REALITY нужен домен, например {DEFAULT_TARGET}.")
        return cls(ssh_host, ssh_user, ssh_port, identity, address, listen_port, target)

    def payload(self):
        request = json.dumps({"address": self.address, "port": self.listen_port, "target": self.target})
        source = Path(__file__).with_name("install-3x-ui-remote.py").read_text(encoding="utf-8")
        return f"REQUEST = {request!r}\n{source}".encode("utf-8")

    def ssh_args(self):
        args = [
            "ssh", "-o", "StrictHostKeyChecking=ask", "-o", "ForwardAgent=no", "-o", "BatchMode=no",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3", "-p", str(self.ssh_port), "-l", self.ssh_user,
        ]
        if self.identity:
            args += ["-i", str(self.identity), "-o", "IdentitiesOnly=yes"]
        return args

    def tunnel_command(self, panel_port):
        forward = f"127.0.0.1:{panel_port}:127.0.0.1:{panel_port}"
        args = [*self.ssh_args(), "-N", "-L", forward, "-o", "ExitOnForwardFailure=yes", self.ssh_host]
        if os.name == "nt":
            return "ssh " + " ".join("'" + arg.replace("'", "''") + "'" for arg in args[1:])
        return shlex.join(args)

    def tcp_status(self):
        try:
            with socket.create_connection((self.address, self.listen_port), timeout=5):
                return f"TCP-порт {self.listen_port} доступен с этого компьютера."
        except OSError:
            return (
                f"С этого компьютера TCP-порт {self.listen_port} недоступен. "
                "Проверьте правила сети у провайдера и публичный адрес."
            )

    def response(self, data):
        result = json.loads(data)
        if not isinstance(result, dict) or not all(
            isinstance(result.get(field), str) and result[field].isascii() and result[field].isprintable()
            for field in ("link", "panel_path", "username", "password")
        ):
            raise ValueError("Сервер вернул неполные данные установки.")
        link = urlsplit(result["link"])
        panel_port = result.get("panel_port")
        if (
            link.scheme != "vless" or link.hostname != self.address or link.port != self.listen_port
            or type(panel_port) is not int or not 1 <= panel_port <= 65535
            or not re.fullmatch(r"/[a-f0-9]{24}/", result["panel_path"])
        ):
            raise ValueError("Сервер вернул некорректную ссылку или адрес панели.")
        return result
