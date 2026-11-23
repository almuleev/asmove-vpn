"""Run on an independent observer with its own Xray and private client configs.

Usage: python3 vpn-probe.py /etc/asmove-probe.json
Input is the worker's JSON node. Only public node addresses are accepted.
"""

import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit
import tempfile
import time


def check(config, node):
    settings = json.loads(Path(config).read_text(encoding="utf-8"))
    ipaddress.ip_address(node["ip"])
    if not ipaddress.ip_address(node["ip"]).is_global or type(node["port"]) is not int or not 1 <= node["port"] <= 65535:
        raise ValueError("Invalid public endpoint")
    curl = settings["curl"]
    targets = settings.get("check_urls", [settings.get("check_url")])
    if not isinstance(targets, list) or not 1 <= len(targets) <= 2:
        raise ValueError("Expected one or two HTTPS check URLs")
    hosts = set()
    for target in targets:
        parsed = urlsplit(target)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.fragment):
            raise ValueError("Expected HTTPS target without credentials")
        hosts.add(parsed.hostname)
    if len(hosts) != len(targets) or not Path(curl).is_absolute():
        raise ValueError("Use different destination hosts and an absolute curl path")
    options = [curl, "--silent", "--show-error", "--fail", "--max-time", "5", "--output", "/dev/null"]
    # A failure of any direct control makes this cycle inconclusive.
    if any(subprocess.run([*options, "--noproxy", "*", target], capture_output=True, timeout=7).returncode
           for target in targets):
        return {"observer_ok": False, "vpn_ok": False, "targets_total": len(targets)}
    template_path = None
    if settings.get("replacement_directory"):
        # A replacement has its own REALITY keys and probe identity.
        candidate = Path(settings["replacement_directory"]) / (node["id"] + "-" + node["ip"] + ".json")
        if candidate.is_file():
            template_path = candidate
    if template_path is None:
        template_path = Path(settings["nodes"][node["id"]])
    template = json.loads(template_path.read_text(encoding="utf-8"))
    with socket.socket() as port:
        port.bind(("127.0.0.1", 0))
        local_port = port.getsockname()[1]
    template["inbounds"] = [{"listen": "127.0.0.1", "port": local_port,
                             "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}]
    outbound = template["outbounds"][0]
    if outbound["protocol"] != "vless":
        raise ValueError("Expected a VLESS client template")
    outbound["settings"]["vnext"][0].update(address=node["ip"], port=node["port"])
    template["outbounds"] = [outbound]
    template["routing"] = {"rules": []}
    if not Path(settings["xray"]).is_absolute():
        raise ValueError("Expected an absolute Xray executable path")
    with tempfile.TemporaryDirectory(prefix="asmove-probe-") as directory:
        path = Path(directory) / "client.json"
        path.write_text(json.dumps(template), encoding="utf-8")
        path.chmod(0o600)
        with subprocess.Popen([settings["xray"], "run", "-config", str(path)], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL) as xray:
            try:
                listening = False
                for _ in range(20):
                    if xray.poll() is not None:
                        return {"observer_ok": False, "vpn_ok": False}
                    try:
                        with socket.create_connection(("127.0.0.1", local_port), timeout=0.1):
                            listening = True
                            break
                    except OSError:
                        time.sleep(0.05)
                if not listening:
                    return {"observer_ok": False, "vpn_ok": False}
                # One successful destination proves traffic still passes. Replacing
                # a VPS because one website is down would be a false positive.
                working = any(subprocess.run([*options, "--noproxy", "", "--proxy",
                              f"socks5h://127.0.0.1:{local_port}", target],
                              capture_output=True, timeout=7).returncode == 0 for target in targets)
                return {"observer_ok": True, "vpn_ok": working, "targets_total": len(targets)}
            finally:
                xray.terminate()
                try:
                    xray.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    xray.kill()
                    xray.wait()


if __name__ == "__main__":
    try:
        request = json.loads(sys.stdin.read(65537))
        print(json.dumps(check(sys.argv[1], request["node"])))
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        print(json.dumps({"observer_ok": False, "vpn_ok": False}))
