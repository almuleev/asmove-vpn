"""Root-owned runner for provisioning and publishing approved VDSina orders.

Only existing paid jobs in the controller database are processed. This runner
never orders or deletes a VPS. Installation is idempotent on the remote VPS.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

sys.path.insert(0, str(Path.cwd()))
from app.db import Store, connect
from app.infrastructure import load_config
from app.node_migration import prepare_links, publish_links
from app.settings import Settings
from app.sync import snapshot, restore
from app.vdsina import Vdsina
from app.xui import Panel, PanelSettings, PanelError
from xui_setup import Setup

CONTROL = Path("/var/lib/access-site/control")
PRIVATE = Path("/var/lib/asmove-lifecycle")
PUBLIC = Path("/var/lib/asmove-lifecycle-results")
PROBES = Path("/var/lib/asmove-lifecycle-probes")
TRANSPORT_POLICY = Path("/etc/access-site/vpn-transport-policy.json")
ENV = Path("/etc/access-site/site.env")
UNIT = Path("/etc/systemd/system/access-site-eu-panel.service")


def save(path, value, *, public=False):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as file:
        file.write(json.dumps(value) if isinstance(value, dict) else value)
        file.flush()
        os.fsync(file.fileno())
    temporary.chmod(0o640 if public else 0o600)
    if public:
        import pwd
        user = pwd.getpwnam("access-site")
        os.chown(temporary, 0, user.pw_gid)
    os.replace(temporary, path)


def run(argv, *, data=None, timeout=30):
    return subprocess.run(argv, input=data, capture_output=True, check=True, timeout=timeout).stdout


def client_template(link):
    parsed = urlsplit(link)
    params = parse_qs(parsed.query)
    tls_xhttp = params.get('type') == ['xhttp'] and params.get('security') == ['tls']
    if (parsed.scheme != "vless" or not (tls_xhttp or (params.get("security") == ["reality"]
            and params.get("type") in (["tcp"], ["grpc"])))):
        raise ValueError("Expected VLESS REALITY or XHTTP/TLS")
    if any(params.get(key, ['0'])[0].lower() not in ('0', 'false', '') for key in ('allowInsecure', 'insecure')):
        raise ValueError('Certificate verification must stay enabled')
    UUID(parsed.username)
    config = {"log": {"loglevel": "error"}, "outbounds": [{"protocol": "vless", "settings": {"vnext": [{
        "address": parsed.hostname, "port": parsed.port, "users": [{"id": parsed.username,
        "encryption": "none", "flow": params.get("flow", [""])[0]}]}]}, "streamSettings": {
        "network": params["type"][0], "security": "reality", "realitySettings": {"serverName": params["sni"][0],
        "fingerprint": params.get("fp", ["chrome"])[0], "publicKey": params.get("pbk", [""])[0],
        "shortId": params.get("sid", [""])[0], "spiderX": params.get("spx", ["/"])[0]}}}]}
    if tls_xhttp:
        stream = config['outbounds'][0]['streamSettings']
        stream.pop('realitySettings')
        stream.update(security='tls', tlsSettings={'serverName': params['sni'][0],
                      'fingerprint': params.get('fp', ['ios'])[0], 'alpn': ['h2'], 'allowInsecure': False},
                      xhttpSettings={'path': params.get('path', ['/'])[0], 'mode': 'auto'})
        config['outbounds'][0]['settings']['vnext'][0]['users'][0]['flow'] = ''
    if params["type"] == ["grpc"]:
        config["outbounds"][0]["streamSettings"]["grpcSettings"] = {
            "serviceName": params.get("serviceName", [""])[0],
            "authority": params.get("authority", [""])[0],
            "multiMode": params.get("mode", [""])[0] == "multi",
        }
    return config


def ensure_transport_certificate(job, ip):
    if not TRANSPORT_POLICY.exists():
        return
    policy = json.loads(TRANSPORT_POLICY.read_text())
    if policy.get('network') != 'xhttp' or policy.get('security') != 'tls':
        return
    import base64
    request = {'source': base64.b64encode(Path(__file__).with_name('vpn-tls.py').read_bytes()).decode(), 'ip': ip}
    program = """import base64,json,subprocess,sys
from pathlib import Path
r=json.load(sys.stdin)
p=Path('/usr/local/lib/asmove/vpn-tls.py');p.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
p.write_bytes(base64.b64decode(r['source'],validate=True));p.chmod(0o700)
result=subprocess.run(['/usr/bin/python3',str(p),'--install','--ip',r['ip']],capture_output=True,timeout=350)
if result.returncode:raise RuntimeError('VPN certificate setup failed: '+result.stderr.decode()[-1000:])
print(result.stdout.decode())
"""
    run([*ssh_args(ip, job['service_id']), 'root@'+ip, 'python3 -c '+shlex.quote(program)],
        data=json.dumps(request).encode(), timeout=370)


def notification_target(node_id, ip, service_id):
    path = CONTROL / "notification-targets.json"
    if not path.exists():
        return
    values = json.loads(path.read_text())
    values[node_id] = {"ip": ip, "alias": "asmove-service-" + str(service_id)}
    save(path, values, public=True)


def ssh_args(ip, service_id):
    if not ipaddress.ip_address(ip).is_global or not isinstance(service_id, int) or service_id <= 0:
        raise ValueError("Invalid provider server")
    # TOFU is confined to an API-confirmed order and a unique service identity.
    # A previously pinned key for the same service is never overwritten.
    return ["ssh", "-T", "-i", str(CONTROL / "id_ed25519"), "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o",
            "UserKnownHostsFile=" + str(CONTROL / "known_hosts"), "-o", "HostKeyAlias=asmove-service-" + str(service_id),
            "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"]


@contextmanager
def panel_connection(details, service_id):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    args = ssh_args(details["ip"], service_id)
    args += ["-N", "-o", "ExitOnForwardFailure=yes", "-L",
             f"127.0.0.1:{port}:127.0.0.1:{details['panel_port']}", "root@" + details["ip"]]
    with subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as tunnel:
        try:
            for _ in range(80):
                if tunnel.poll() is not None:
                    raise ValueError("Panel SSH tunnel failed")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise ValueError("Panel SSH tunnel timeout")
            scheme = details.get("scheme", "http")
            settings = PanelSettings(f"{scheme}://127.0.0.1:{port}" + details["panel_path"], details["inbound"],
                                     details["ip"] + ":" + str(details.get("vpn_port", 443)), details["token"], flow="xtls-rprx-vision",
                                     tls_verify_public_address=scheme == "https",
                                     companion_inbounds=tuple(details.get("companion_inbounds", ())))
            yield Panel(settings)
        finally:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=3)
            except subprocess.TimeoutExpired:
                tunnel.kill(); tunnel.wait()


def configure_transport(panel, details):
    """Preserve the administrator's working transport on a replacement VPS."""
    if not TRANSPORT_POLICY.exists():
        return panel, details
    policy = json.loads(TRANSPORT_POLICY.read_text())
    port = policy["port"]
    network = policy.get('network')
    if network not in ('grpc', 'xhttp') or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid VPN transport policy")
    if details.get("vpn_port") == port and details.get("companion_inbounds"):
        return panel, details
    base = panel.inbound()
    if base["port"] == port:
        raise ValueError("Transport policy must use a separate port")
    remark = "access-site-"+network
    inbounds = panel.request("inbounds/list") or []
    target = next((row for row in inbounds if row.get("remark") == remark), None)
    if target is None:
        if any(row["port"] == port for row in inbounds):
            raise ValueError("VPN transport port already belongs to another inbound")
        stream = (json.loads(base["streamSettings"]) if isinstance(base["streamSettings"], str)
                  else deepcopy(base["streamSettings"]))
        if network == 'grpc':
            stream.update(network="grpc", grpcSettings=policy["grpcSettings"])
            stream["realitySettings"].update(target=policy["target"], serverNames=policy["serverNames"])
        else:
            if policy.get('security') != 'tls':
                raise ValueError('XHTTP requires TLS')
            stream = {'network': 'xhttp', 'security': 'tls', 'xhttpSettings': policy['xhttpSettings'],
                      'tlsSettings': {'minVersion': '1.2', 'maxVersion': '1.3', 'alpn': ['h2', 'http/1.1'],
                       'certificates': [{'certificateFile': '/etc/asmove-vpn-tls/fullchain.pem',
                                         'keyFile': '/etc/asmove-vpn-tls/privkey.pem', 'oneTimeLoading': False}],
                       'settings': {'serverName': details['ip'], 'fingerprint': 'ios', 'allowInsecure': False}}}
        panel.request("inbounds/add", {"remark": remark, "port": port, "protocol": "vless", "enable": True,
            "settings": json.dumps({"clients": [], "decryption": "none", "encryption": "none"}),
            "streamSettings": json.dumps(stream), "sniffing": (base.get("sniffing", "{}")
                if isinstance(base.get("sniffing", "{}"), str) else json.dumps(base["sniffing"]))})
        target = next(row for row in panel.request("inbounds/list") if row.get("remark") == remark)
    if target["port"] != port or target["protocol"] != "vless" or not target["enable"]:
        raise ValueError("Replacement transport inbound changed")
    target_stream = (json.loads(target["streamSettings"]) if isinstance(target["streamSettings"], str)
                     else target["streamSettings"])
    if target_stream.get("network") != network:
        raise ValueError("Replacement transport protocol changed")
    uid = urlsplit(details["link"]).username
    probe = next(row for row in panel.request("clients/list") if row.get("uuid") == uid)
    panel.request("clients/" + probe["email"] + "/attach", {"inboundIds": [target["id"]]})
    primary = Panel(replace(panel.settings, inbound=target["id"],
                            public_address=details["ip"] + ":" + str(port),
                            companion_inbounds=(base["id"],)))
    link = next(link for link in panel.request("clients/links/" + probe["email"])
                if primary.link_matches(urlsplit(link), uid))
    link = primary.stable_link(link, "Connection")
    return primary, {**details, "inbound": target["id"], "vpn_port": port,
                     "companion_inbounds": [base["id"]], "link": link}


def bootstrap_node(job, ip, directory):
    state_file = directory / "node.json"
    if state_file.is_file():
        details = json.loads(state_file.read_text())
        if details["ip"] != ip:
            raise ValueError("Provider address changed")
    else:
        setup = Setup.from_input(ip, "root", "22", "", ip, "443", "www.mozilla.org")
        output = run([*ssh_args(ip, job["service_id"]), "root@" + ip, "python3 -"], data=setup.payload(), timeout=900)
        result = setup.response(output)
        remote = b'''import json,re,sqlite3,subprocess
s=json.load(open('/var/lib/access-site-3x-ui.json'))
t=subprocess.check_output(['/usr/local/x-ui/x-ui','setting','-getApiToken','-tokenName','access-site-installer'],text=True)
token=re.search(r'(?m)^apiToken: (\\S+)',t)[1]
db=sqlite3.connect('/etc/x-ui/x-ui.db')
inbound=db.execute("SELECT id FROM inbounds WHERE protocol='vless' AND port=443 AND enable=1").fetchone()[0]
print(json.dumps({'token':token,'inbound':inbound}))
'''
        credentials = json.loads(run([*ssh_args(ip, job["service_id"]), "root@" + ip, "python3 -"], data=remote))
        details = {**result, **credentials, "ip": ip, "scheme": "http"}
        save(state_file, details)
    return details


def provision(job, ip, directory):
    state_file = directory / "node.json"
    details = bootstrap_node(job, ip, directory)
    ensure_transport_certificate(job, ip)
    store = Store(Settings.from_env().data_dir)
    with panel_connection(details, job["service_id"]) as panel:
        panel, details = configure_transport(panel, details)
        save(state_file, details)
        panel.inbound()
        users, _, _ = store.overview()
        prepare_links(panel, users)
    if details.get("vpn_port", 443) != 443:
        firewall = ("import shutil,subprocess\np=shutil.which('ufw')\n"
                    "if p and subprocess.check_output([p,'status'],text=True).startswith('Status: active'):\n"
                    f" subprocess.run([p,'allow','{details['vpn_port']}/tcp'],check=True)\n")
        run([*ssh_args(ip, job["service_id"]), "root@" + ip, "python3 -"], data=firewall.encode())
    node = json.loads(job["spec"])["old"]["id"]
    replacement = PROBES / (node + "-" + ip + ".json")
    save(replacement, client_template(details["link"]), public=True)
    import vpn_recovery
    from types import SimpleNamespace
    vpn_recovery.install_backup_endpoint(SimpleNamespace(ssh_args=ssh_args, run=run), ip, job["service_id"])
    return {"ready": True, "port": details.get("vpn_port", 443)}


def unit_for(details, service_id, local_port=46065):
    args = ssh_args(details["ip"], service_id)
    args[args.index("StrictHostKeyChecking=accept-new")] = "StrictHostKeyChecking=yes"
    args += ["-N", "-o", "ExitOnForwardFailure=yes", "-L",
             f"127.0.0.1:{local_port}:127.0.0.1:{details['panel_port']}", "root@" + details["ip"]]
    return ("[Unit]\nDescription=ASMove VPN VPN panel SSH connection\nAfter=network-online.target\n"
            "Wants=network-online.target\n[Service]\nUser=root\nExecStart=" + shlex.join(args) +
            "\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\n"
            "PrivateTmp=true\nCapabilityBoundingSet=\n[Install]\nWantedBy=multi-user.target\n")


def environment(raw):
    values = {}
    for line in raw.splitlines():
        if line.strip() and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            items = shlex.split(value)
            values[key] = items[0] if items else ""
    return values


def publish(job, details, directory):
    # The web process is stopped before the authoritative snapshot, preventing a
    # revoke/create from racing with provisioning. Database writes are atomic.
    store = Store(Settings.from_env().data_dir)
    original = ENV.read_text()
    old_unit = UNIT.read_text()
    old_notifications = (store.directory / "probes/notifications.json").read_text()
    backup = directory / ("before-publication-" + str(time.time_ns()) + ".sqlite3")
    timers = [name for name in ("access-site-sync.timer", "asmove-snapshot-upload.timer",
              "access-site-reminders.timer", "access-site-events.timer")
              if subprocess.run(["systemctl", "is-active", "--quiet", name]).returncode == 0]
    manifest = {"committed": False, "backup": str(backup), "env": original, "unit": old_unit,
                "notifications": old_notifications, "timers": timers}
    save(directory / "publication.json", manifest)
    maintenance = store.directory / "vpn-publication-maintenance"
    save(maintenance, "Publishing an approved VPN replacement\n")
    try:
        if timers:
            run(["systemctl", "stop", *timers])
            run(["systemctl", "stop", *[timer.removesuffix("timer") + "service" for timer in timers]], timeout=90)
        run(["systemctl", "stop", "access-site.service"])
        snapshot(store, backup)
        save(directory / "before-publication.env", original)
        save(directory / "before-publication.unit", old_unit)
        with panel_connection(details, job["service_id"]) as panel:
            users, _, revision = store.overview()
            links = prepare_links(panel, users)
        values = environment(original)
        scheme = details.get("scheme", "http")
        values.update(SITE_XUI_URL=scheme + "://127.0.0.1:46065" + details["panel_path"],
                      SITE_XUI_INBOUND=str(details["inbound"]), SITE_XUI_ADDRESS=details["ip"] + ":" + str(details.get("vpn_port", 443)),
                      SITE_XUI_TOKEN=details["token"], SITE_XUI_FLOW="xtls-rprx-vision")
        values.pop("SITE_XUI_COMPANION_INBOUNDS", None)
        if details.get("companion_inbounds"):
            values["SITE_XUI_COMPANION_INBOUNDS"] = ",".join(map(str, details["companion_inbounds"]))
        values.pop("SITE_XUI_TLS_SHA256", None)
        values.pop("SITE_XUI_TLS_VERIFY_PUBLIC_ADDRESS", None)
        if scheme == "https":
            values["SITE_XUI_TLS_VERIFY_PUBLIC_ADDRESS"] = "1"
        save(UNIT, unit_for(details, job["service_id"])); UNIT.chmod(0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "restart", "access-site-eu-panel.service"])
        for attempt in range(12):
            try:
                Panel(PanelSettings(values["SITE_XUI_URL"], details["inbound"], values["SITE_XUI_ADDRESS"],
                                    details["token"], flow="xtls-rprx-vision", tls_verify_public_address=scheme == "https",
                                    companion_inbounds=tuple(details.get("companion_inbounds", ())))).inbound()
                break
            except PanelError:
                if attempt == 11:
                    raise
                time.sleep(1)
        publish_links(store, revision, links)
        save(ENV, "".join(key + "=" + shlex.quote(value) + "\n" for key, value in values.items()))
        notifications = client_template(details["link"])
        notifications["inbounds"] = [{"listen": "127.0.0.1", "port": 10809, "protocol": "socks",
                                       "settings": {"auth": "noauth", "udp": False}}]
        save(store.directory / "probes/notifications.json", notifications, public=True)
        if (CONTROL/'notification-targets.json').exists():
            run(["systemctl", "restart", "access-site-notification-proxy.service"])
        run(["systemctl", "start", "access-site.service"])
        origin = Settings.from_env().origin
        address = urlsplit(origin)
        run(["curl", "--fail", "--silent", "--retry", "5", "--retry-delay", "1", "--retry-connrefused",
             "--max-time", "8", "--noproxy", "*", "--resolve",
             f"{address.hostname}:{address.port or 443}:127.0.0.1", origin + "/health"], timeout=60)
        manifest["committed"] = True
        save(directory / "publication.json", manifest)
    finally:
        recover_directory(directory, store)
    background = ['asmove-snapshot-upload.service']
    if getattr(Settings.from_env(), 'replication_enabled', True):
        background.append('access-site-sync.service')
    background = [unit for unit in background if subprocess.run(
        ['systemctl', 'show', unit, '--property=LoadState', '--value'], capture_output=True, text=True).stdout.strip() == 'loaded']
    if background:
        run(["systemctl", "start", "--no-block", *background])
    notification_target(job.get("node", "EU1"), details["ip"], job["service_id"])
    return {"published": True}


def recover_directory(directory, store):
    path = directory / "publication.json"
    if not path.exists():
        return
    manifest = json.loads(path.read_text())
    if not manifest["committed"]:
        run(["systemctl", "stop", "access-site.service"])
        backup = Path(manifest["backup"]) if manifest.get("backup") else None
        if backup and backup.parent != directory:
            raise ValueError("Unexpected recovery snapshot")
        if backup and backup.exists():
            restore(store, backup)
            user = __import__("pwd").getpwnam("access-site")
            for file in (store.data, store.local):
                os.chown(file, user.pw_uid, user.pw_gid)
        save(ENV, manifest["env"])
        unit = Path(manifest.get("unit_path", str(UNIT)))
        if manifest["unit"] is None:
            run(["systemctl", "stop", unit.name])
            unit.unlink(missing_ok=True)
        else:
            save(unit, manifest["unit"]); unit.chmod(0o644)
        for filename, contents in manifest.get("extra_files", {}).items():
            path_to_restore = Path(filename)
            if contents is None:
                path_to_restore.unlink(missing_ok=True)
            else:
                save(path_to_restore, contents, public=True)
        save(store.directory / "probes/notifications.json", manifest["notifications"], public=True)
        run(["systemctl", "daemon-reload"])
        if manifest["unit"] is not None:
            run(["systemctl", "restart", unit.name])
        if (CONTROL/'notification-targets.json').exists():
            run(["systemctl", "restart", "access-site-notification-proxy.service"])
    run(["systemctl", "start", "access-site.service"])
    (store.directory / "vpn-publication-maintenance").unlink(missing_ok=True)
    if manifest["timers"]:
        run(["systemctl", "start", *manifest["timers"]])
    path.unlink()


def publish_secondary(job, details, directory):
    store = Store(Settings.from_env().data_dir)
    secondary_path = store.directory / "secondary-panels.json"
    infrastructure_path = Settings.from_env().infrastructure_config
    unit = UNIT.with_name("access-site-eu2-panel.service")
    original_secondary = secondary_path.read_text() if secondary_path.exists() else None
    original_config = infrastructure_path.read_text()
    original_unit = unit.read_text() if unit.exists() else None
    manifest = {"committed": False, "backup": None, "env": ENV.read_text(), "unit": original_unit,
                "unit_path": str(unit), "notifications": (store.directory / "probes/notifications.json").read_text(),
                "timers": [], "extra_files": {str(secondary_path): original_secondary, str(infrastructure_path): original_config}}
    save(directory / "publication.json", manifest)
    save(store.directory / "vpn-publication-maintenance", "Publishing the secondary VPN node\n")
    try:
        run(["systemctl", "stop", "access-site.service"])
        with panel_connection(details, job["service_id"]) as panel:
            prepare_links(panel, store.overview()[0])
        save(unit, unit_for(details, job["service_id"], 46066)); unit.chmod(0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", unit.name])
        run(["systemctl", "restart", unit.name])
        values = json.loads(original_secondary) if original_secondary else {}
        spec = json.loads(job["spec"])
        node_id = spec["old"]["id"]
        scheme = details.get("scheme", "http")
        values[node_id] = {"url": scheme + "://127.0.0.1:46066" + details["panel_path"], "inbound": details["inbound"],
                           "public_address": details["ip"] + ":" + str(details.get("vpn_port", 443)), "token": details["token"],
                           "flow": "xtls-rprx-vision", "tls_verify_public_address": scheme == "https",
                           "companion_inbounds": details.get("companion_inbounds", [])}
        save(secondary_path, values, public=True)
        from app.xui import PanelGroup
        for attempt in range(12):
            try:
                PanelGroup(Settings.from_env().panel, store.directory).secondaries()[0].inbound()
                break
            except PanelError:
                if attempt == 11:
                    raise
                time.sleep(1)
        run(["systemctl", "start", "access-site.service"])
        origin = Settings.from_env().origin; address = urlsplit(origin)
        run(["curl", "--fail", "--silent", "--retry", "5", "--retry-delay", "1", "--retry-connrefused",
             "--max-time", "8", "--noproxy", "*", "--resolve",
             f"{address.hostname}:{address.port or 443}:127.0.0.1", origin + "/health"], timeout=60)
        if spec.get("addition"):
            config = json.loads(original_config)
            existing = next((row for row in config["nodes"] if row["id"] == node_id), None)
            if existing and existing["service_id"] != job["service_id"]:
                raise ValueError("Additional node identity changed")
            if not existing:
                config["nodes"].append({"id": node_id, "ip": details["ip"], "port": details.get("vpn_port", 443),
                    "service_id": job["service_id"], "country": spec["candidate"]["country"],
                    "datacenter_id": spec["candidate"]["datacenter_id"], "native_daily_cost": str(spec["candidate"]["daily_cost"])})
                config["baseline_daily"] += spec["daily_rub"]
            config["additions"] = [row for row in config.get("additions", []) if row["id"] != node_id]
            save(infrastructure_path, config, public=True)
        run(["systemctl", "enable", "--now", "access-site-secondary-clients.timer"])
        manifest["committed"] = True
        save(directory / "publication.json", manifest)
    finally:
        recover_directory(directory, store)
    notification_target(job["node"], details["ip"], job["service_id"])
    return {"published": True}


def main():
    import fcntl
    import pwd
    os.umask(0o077)
    settings = Settings.from_env()
    if "--recover" in sys.argv:
        if PRIVATE.exists():
            for directory in PRIVATE.iterdir():
                if directory.is_dir():
                    recover_directory(directory, Store(settings.data_dir))
        return
    config = load_config(settings.infrastructure_config)
    if config["mode"] != "live":
        return
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    user = pwd.getpwnam("access-site")
    for directory in (PUBLIC, PROBES):
        directory.mkdir(mode=0o750, exist_ok=True)
        os.chown(directory, 0, user.pw_gid)
    with (PRIVATE / "runner.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for directory in PRIVATE.iterdir():
            if directory.is_dir():
                recover_directory(directory, Store(settings.data_dir))
        with connect(settings.data_dir / "infrastructure.sqlite3") as db:
            jobs = [dict(row) for row in db.execute("SELECT * FROM jobs WHERE status IN ('provisioning','verifying','publishing')")]
        for job in jobs:
            if not re.fullmatch(r"[a-f0-9]{32}", job["id"]) or not job["reserved"]:
                continue
            spec = json.loads(job["spec"])
            if spec.get("delete_first"):
                continue
            if spec["mode"] != "live":
                continue
            directory = PRIVATE / job["id"]
            directory.mkdir(mode=0o700, exist_ok=True)
            result_path = PUBLIC / (job["id"] + "-" + job["status"] + ".json")
            if result_path.exists():
                continue
            try:
                server = Vdsina(config.get("api_host", "userapi.vdsina.com")).server(job["service_id"])
                if server.get("name") != "asmove-" + job["id"] or server.get("status") != "active":
                    continue
                ip = Vdsina.address(server)
                if job["ip"] and job["ip"] != ip:
                    raise ValueError("Provider address changed")
                if job["status"] == "provisioning":
                    result = provision(job, ip, directory)
                else:
                    details = json.loads((directory / "node.json").read_text())
                    if details["ip"] != ip:
                        raise ValueError("Provisioned address changed")
                    if job["status"] == "verifying":
                        with panel_connection(details, job["service_id"]) as panel:
                            panel.inbound()
                            prepare_links(panel, Store(settings.data_dir).overview()[0])
                        result = {"ready": True}
                    else:
                        secondaries = settings.data_dir / "secondary-panels.json"
                        known = json.loads(secondaries.read_text()) if secondaries.exists() else {}
                        if spec.get("addition") or job["node"] in known:
                            result = publish_secondary(job, details, directory)
                        else:
                            result = publish(job, details, directory)
                save(result_path, result, public=True)
            except Exception as error:
                # Private logs contain no remote stdout, tokens, or user links.
                save(directory / "last-error.json", {"stage": job["status"], "error": type(error).__name__, "at": int(time.time())})
                print("Lifecycle step will retry: " + job["status"], file=sys.stderr)


if __name__ == "__main__":
    main()
