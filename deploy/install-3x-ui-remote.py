"""Server-side installer. The SSH launcher supplies REQUEST before this script."""

from contextlib import closing
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import parse_qs, urlsplit, urlunsplit
from urllib.request import urlopen
from uuid import uuid4


VERSION = "v3.11.0"
ASSETS = {
    "x86_64": ("amd64", "0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916"),
    "aarch64": ("arm64", "f50b4c30fd919d018f2f4c3d8db53a4ca027503d581328727770afb116a79d90"),
}
INSTALL_DIR = Path("/usr/local/x-ui")
DB_DIR = Path("/etc/x-ui")
UNIT = Path("/etc/systemd/system/x-ui.service")
MANAGER = Path("/usr/bin/x-ui")
STATE = Path("/var/lib/access-site-3x-ui.json")
LOCK = Path("/run/lock/access-site-3x-ui.lock")
FLOW = "xtls-rprx-vision"
REMARK = "VLESS REALITY (Access Site)"


class SetupError(Exception):
    pass


def progress(message):
    print(message, file=sys.stderr, flush=True)


def run(*args, capture=False, quiet=False):
    result = subprocess.run(
        args, cwd=INSTALL_DIR if INSTALL_DIR.is_dir() else "/", text=True, check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else sys.stderr,
        stderr=subprocess.DEVNULL if quiet else sys.stderr, timeout=90,
    )
    return result.stdout


def xui(*args):
    try:
        return run(str(INSTALL_DIR / "x-ui"), *args, capture=True, quiet=True)
    except subprocess.CalledProcessError as error:
        raise SetupError("Команда настройки 3x-ui завершилась с ошибкой.") from error


def listeners(port, *, processes=False):
    return run("ss", "-Hltnp" if processes else "-Hltn", "sport", "=", f":{port}", capture=True)


def save_state(state):
    with tempfile.NamedTemporaryFile("w", dir=STATE.parent, delete=False) as file:
        temporary = Path(file.name)
    try:
        temporary.write_text(json.dumps(state), encoding="utf-8")
        temporary.replace(STATE)
    finally:
        temporary.unlink(missing_ok=True)


def new_state(port, target):
    if any(os.path.lexists(path) for path in (INSTALL_DIR, DB_DIR, UNIT, MANAGER, "/etc/default/x-ui")):
        raise SetupError("На сервере уже есть установка x-ui. Для мастера нужен VPS без установленной панели.")
    units = run("systemctl", "list-unit-files", "--type=service", "--no-legend", capture=True)
    if re.search(r"^x-ui\.service\s", units, re.MULTILINE):
        raise SetupError("На сервере уже зарегистрирована служба x-ui.")
    if listeners(port):
        raise SetupError(f"Порт {port}/tcp занят. Выберите другой порт VLESS.")
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    try:
        with socket.create_connection((target, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls:
                if tls.selected_alpn_protocol() != "h2":
                    raise SetupError(f"Домен {target} не согласовал HTTP/2. Выберите другой домен REALITY.")
    except OSError as error:
        raise SetupError(f"VPS не смог установить TLS 1.3 с {target}: {error}") from error
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            panel_port = sock.getsockname()[1]
        if panel_port != port and not listeners(panel_port):
            break
    state = {
        "port": port, "target": target, "panel_port": panel_port,
        "panel_path": f"/{secrets.token_hex(12)}/", "username": "admin",
        "password": secrets.token_urlsafe(24), "client_id": str(uuid4()), "configured": False,
    }
    save_state(state)
    return state


def install_release(arch, expected):
    if not INSTALL_DIR.exists():
        progress(f"Загружается 3x-ui {VERSION} ({arch}).")
        asset = f"x-ui-linux-{arch}.tar.gz"
        url = f"https://github.com/MHSanaei/3x-ui/releases/download/{VERSION}/{asset}"
        with tempfile.TemporaryDirectory(prefix=".x-ui-", dir=INSTALL_DIR.parent) as directory:
            stage = Path(directory)
            archive = stage / asset
            with urlopen(url, timeout=60) as response, archive.open("wb") as file:
                shutil.copyfileobj(response, file)
            with archive.open("rb") as file:
                digest = hashlib.file_digest(file, "sha256").hexdigest()
            if digest != expected:
                raise SetupError("Контрольная сумма архива 3x-ui не совпала.")
            with tarfile.open(archive) as files:
                files.extractall(stage, filter="data")
            (stage / "x-ui").replace(INSTALL_DIR)
    for source, destination, mode in (
        ("x-ui.sh", MANAGER, 0o755), ("x-ui.service.debian", UNIT, 0o644),
    ):
        if destination.exists():
            continue
        with tempfile.TemporaryDirectory(prefix=".x-ui-", dir=destination.parent) as directory:
            staged = Path(directory) / destination.name
            shutil.copyfile(INSTALL_DIR / source, staged)
            staged.chmod(mode)
            staged.replace(destination)


def configure_panel(state):
    if state["configured"]:
        return
    DB_DIR.mkdir(mode=0o700, exist_ok=True)
    xui(
        "setting", "-listenIP", "127.0.0.1", "-port", str(state["panel_port"]),
        "-webBasePath", state["panel_path"], "-username", state["username"],
        "-password", state["password"],
    )
    # 3x-ui 3.11 starts a separate subscription server by default. Set its
    # defaults in the initialized SQLite database before the first startup.
    with closing(sqlite3.connect(DB_DIR / "x-ui.db")) as database, database:
        for key, value in {"subEnable": "false", "subListen": "127.0.0.1"}.items():
            database.execute("DELETE FROM settings WHERE key = ?", (key,))
            database.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))
    state["configured"] = True
    save_state(state)


class Panel:
    def __init__(self, state, address):
        self.port = state["panel_port"]
        self.path = state["panel_path"] + "panel/api/"
        endpoint = f"[{address}]" if ":" in address else address
        self.host = f"{endpoint}:{state['port']}"
        output = xui("setting", "-getApiToken", "-tokenName", "access-site-installer")
        match = re.search(r"(?m)^apiToken: (\S+)", output)
        if not match:
            raise SetupError("3x-ui не выдала токен настройки.")
        self.token = match[1]

    def request(self, endpoint, payload=None):
        headers = {"Authorization": f"Bearer {self.token}", "Host": self.host}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload)
        with closing(http.client.HTTPConnection("127.0.0.1", self.port, timeout=6)) as client:
            client.request("GET" if body is None else "POST", self.path + endpoint, body, headers)
            response = client.getresponse()
            if response.status != 200:
                raise SetupError(f"API 3x-ui ({endpoint}) вернуло HTTP {response.status}.")
            result = json.loads(response.read())
        if result.get("success") is not True:
            raise SetupError(f"API 3x-ui отклонило операцию {endpoint}.")
        return result.get("obj")


def wait_for(check, message):
    for _ in range(30):
        try:
            if check():
                return
        except (OSError, http.client.HTTPException, SetupError):
            pass
        time.sleep(1)
    raise SetupError(message)


def inbound_payload(state, keys):
    client = {
        "id": state["client_id"], "email": "access-site-vless", "enable": True,
        "flow": FLOW, "subId": secrets.token_hex(8),
    }
    reality = {
        "show": False, "xver": 0, "target": f"{state['target']}:443",
        "serverNames": [state["target"]], "privateKey": keys["privateKey"],
        "shortIds": [secrets.token_hex(8)],
        "settings": {"publicKey": keys["publicKey"], "fingerprint": "chrome", "spiderX": "/"},
    }
    return {
        "remark": REMARK, "port": state["port"], "protocol": "vless", "enable": True,
        "settings": json.dumps({"clients": [client], "decryption": "none", "encryption": "none"}),
        "streamSettings": json.dumps({"network": "tcp", "security": "reality", "realitySettings": reality}),
        "sniffing": json.dumps({"enabled": False, "destOverride": []}),
    }


def setup_inbound(panel, state):
    port = state["port"]
    wait_for(lambda: panel.request("server/status"), "Панель 3x-ui не отвечает на локальном порту.")
    inbounds = panel.request("inbounds/list") or []
    own = next((item for item in inbounds if item.get("remark") == REMARK), None)
    if own is None:
        if listeners(port):
            raise SetupError(f"Порт {port}/tcp занят.")
        keys = panel.request("server/getNewX25519Cert")
        panel.request("inbounds/add", inbound_payload(state, keys))
        run("systemctl", "restart", "x-ui")
    elif own["port"] != port or own["protocol"] != "vless" or not own["enable"]:
        raise SetupError("Ранее созданный inbound изменён. Проверьте его в панели.")
    elif "xray" not in listeners(port, processes=True):
        run("systemctl", "restart", "x-ui")

    wait_for(
        lambda: "xray" in listeners(port, processes=True)
        and panel.request("server/status").get("xray", {}).get("state") == "running",
        f"Xray не запустил VLESS на порту {port}/tcp. Проверьте journalctl -u x-ui.",
    )
    for link in panel.request("clients/links/access-site-vless") or []:
        parsed = urlsplit(link)
        params = parse_qs(parsed.query)
        if (
            parsed.scheme == "vless" and parsed.username == state["client_id"]
            and parsed.password is None and parsed.port == port
            and params.get("security") == ["reality"] and params.get("flow") == [FLOW]
            and params.get("sni") == [state["target"]] and params.get("pbk") and params.get("sid")
        ):
            return urlunsplit(parsed._replace(netloc=f"{state['client_id']}@{panel.host}"))
    raise SetupError("Панель не вернула ожидаемую ссылку VLESS + REALITY.")


def allow_ufw(port):
    ufw = shutil.which("ufw")
    if ufw and run(ufw, "status", capture=True).splitlines()[:1] == ["Status: active"]:
        run(ufw, "allow", f"{port}/tcp")


def main(request):
    os.umask(0o077)
    os.environ["LC_ALL"] = "C"
    release = platform.freedesktop_os_release()
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise SetupError("Требуется Ubuntu 24.04.")
    if platform.machine() not in ASSETS:
        raise SetupError("Поддерживаются VPS с архитектурой amd64 или arm64.")
    address, port, target = request["address"], request["port"], request["target"]
    with LOCK.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SetupError("На сервере уже запущен мастер установки.") from error
        state = json.loads(STATE.read_text()) if STATE.exists() else new_state(port, target)
        if (port, target) != (state["port"], state["target"]):
            raise SetupError(
                f"Для повторного запуска укажите прежние порт {state['port']} и домен {state['target']}."
            )
        install_release(*ASSETS[platform.machine()])
        configure_panel(state)
        progress("Запускаются панель и Xray.")
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", "x-ui")
        panel = Panel(state, address)
        link = setup_inbound(panel, state)
        allow_ufw(port)
        print(json.dumps({
            "link": link, "panel_port": state["panel_port"], "panel_path": state["panel_path"],
            "username": state["username"], "password": state["password"],
        }))


if __name__ == "__main__":
    try:
        main(json.loads(REQUEST))
    except subprocess.CalledProcessError as error:
        progress(f"Команда {error.cmd[0]} завершилась с кодом {error.returncode}.")
        sys.exit(1)
    except subprocess.TimeoutExpired as error:
        progress(f"Истекло время ожидания команды {error.cmd[0]}.")
        sys.exit(1)
    except (SetupError, OSError, ValueError, sqlite3.Error, tarfile.TarError) as error:
        progress(f"Ошибка на VPS: {error}")
        sys.exit(1)
