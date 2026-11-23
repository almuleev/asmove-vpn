"""Keep a pinned SSH SOCKS route; Telegram can use an independent relay."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/opt/access-site/current")
from app.reminders import SocksHTTPSConnection, ReminderError

CONTROL = Path("/var/lib/access-site/control")
child = None


def stop(*_):
    if child and child.poll() is None:
        child.terminate()
    raise SystemExit(0)


def load_targets(path):
    targets = json.loads(Path(path).read_text())
    if not isinstance(targets, dict) or not 1 <= len(targets) <= 4:
        raise ValueError("Invalid notification targets")
    for target in targets.values():
        ip = str(ipaddress.IPv4Address(target["ip"]))
        if not ipaddress.ip_address(ip).is_global or not re.fullmatch(r"[A-Za-z0-9.-]{1,80}", target["alias"]):
            raise ValueError("Invalid notification endpoint")
    return list(targets.values())


def ssh_command(target, port):
    return ["/usr/bin/ssh", "-NT", "-i", str(CONTROL / "id_ed25519"),
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(CONTROL / "known_hosts"), "-o", "HostKeyAlias=" + target["alias"],
        "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=2", "-D", "127.0.0.1:" + str(port), "root@" + target["ip"]]


def healthy(port, *, telegram_only):
    result = subprocess.run(["/usr/bin/curl", "--silent", "--fail", "--output", "/dev/null",
        "--max-time", "8", "--connect-timeout", "4", "--noproxy", "", "--socks5-hostname",
        "127.0.0.1:" + str(port), "https://api.telegram.org/"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        return False
    if telegram_only:
        return True
    provider = SocksHTTPSConnection("userapi.vdsina.com", "127.0.0.1:" + str(port))
    try:
        # TLS only: anonymous API requests can trigger auth limits.
        provider.connect()
        return True
    except (OSError, ReminderError):
        return False
    finally:
        provider.close()


def serve(path, port, *, telegram_only):
    global child
    while True:
        try:
            for target in load_targets(path):
                child = subprocess.Popen(ssh_command(target, port),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for _ in range(12):
                    if child.poll() is not None:
                        break
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(1)
                while child.poll() is None:
                    if not healthy(port, telegram_only=telegram_only):
                        child.terminate()
                        break
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        pass
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
                child = None
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(3)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--targets', type=Path, default=CONTROL / 'notification-targets.json')
    parser.add_argument('--port', type=int, default=10809)
    parser.add_argument('--telegram-only', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Invalid SOCKS port')
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    serve(args.targets, args.port, telegram_only=args.telegram_only)


if __name__ == '__main__':
    main()
