"""Connect a clean EU VPS to an initialized RU controller; never rent/delete a VPS."""
import argparse
import base64
from contextlib import closing
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
CURRENT = Path('/opt/access-site/current')
CONTROL = Path('/var/lib/access-site/control')
PRIVATE = Path('/var/lib/nodeguard-bootstrap')
SCRIPTS = ('vpn-lifecycle.py', 'delete-first.py', 'vpn_recovery.py', 'lifecycle-result.py',
           'xui_setup.py', 'install-3x-ui-remote.py', 'vpn-probe.py',
           'notification-proxy.py', 'tcp-relay.py', 'vpn-tls.py', 'export-state.py')


def validate(value):
    allowed = {'eu_ip', 'eu_service_id', 'eu_host_fingerprint', 'country', 'datacenter_id',
               'vdsina_token_file', 'candidates', 'telegram_env_file', 'ntfy_env_file', 'recovery_archive_file'}
    if set(value)-allowed:
        raise ValueError('Unknown configuration keys: '+', '.join(sorted(set(value)-allowed)))
    address = ipaddress.IPv4Address(value['eu_ip'])
    if not address.is_global:
        raise ValueError('eu_ip must be a public IPv4 address')
    for name in ('eu_service_id', 'datacenter_id'):
        if type(value[name]) is not int or value[name] <= 0:
            raise ValueError(name+' must be a positive integer')
    if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', value['eu_host_fingerprint']):
        raise ValueError('Obtain the SHA256 host fingerprint from the EU provider console')
    if not re.fullmatch(r'[a-z]{2}', value.get('country', 'nl')) or value.get('country') == 'ru':
        raise ValueError('EU VPN country must be outside Russia')
    candidates = value.get('candidates', [])
    if type(candidates) is not list or bool(candidates) != bool(value.get('vdsina_token_file')):
        raise ValueError('Configure both candidates and vdsina_token_file, or neither')
    from decimal import Decimal
    for row in candidates:
        for key in ('plan_id', 'group_id', 'datacenter_id', 'template_id', 'ssh_key_id'):
            if type(row.get(key)) is not int or row[key] <= 0:
                raise ValueError('Each candidate needs positive '+key)
        from decimal import InvalidOperation
        try:
            correct_price = Decimal(str(row.get('daily_cost'))) == Decimal('0.07')
        except InvalidOperation:
            correct_price = False
        if (not correct_price or not re.fullmatch(r'[a-z]{2}', row.get('country', '')) or row.get('country') == 'ru'):
            raise ValueError('Replacement candidates must cost exactly USD 0.07/day abroad')
    return value


def private_text(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 65536:
        raise ValueError('Expected a regular private file of at most 64 KiB')
    if os.name == 'posix' and (p.stat().st_uid != os.geteuid() or stat.S_IMODE(p.stat().st_mode) & 0o077):
        raise ValueError('Private input must belong to the running user with mode 0600 or 0400 (root for installation)')
    return p.read_text(encoding='utf-8').strip()


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=kwargs.pop('timeout', 60), **kwargs).stdout


def write(path, content, public=False):
    p = Path(path); p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix='.'+p.name+'-', dir=p.parent)
    temporary = Path(name)
    with os.fdopen(descriptor, 'wb') as file:
        file.write(content.encode() if isinstance(content, str) else content)
        file.flush(); os.fsync(file.fileno())
    temporary.chmod(0o640 if public else 0o600)
    if public:
        import grp
        os.chown(temporary, 0, grp.getgrnam('access-site').gr_gid)
    os.replace(temporary, p)


def pin_host(ip, service, expected):
    scanned = run(['ssh-keyscan', '-T', '8', '-t', 'ed25519', ip]).decode()
    lines = [line for line in scanned.splitlines() if line and not line.startswith('#')]
    if len(lines) != 1:
        raise ValueError('Expected one ED25519 host key')
    fields = lines[0].split()
    if len(fields) != 3 or fields[1] != 'ssh-ed25519':
        raise ValueError('Invalid SSH host key response')
    fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(fields[2], validate=True)).digest()).decode().rstrip('=')
    if fingerprint != expected:
        raise ValueError('SSH host key fingerprint mismatch; connection was not trusted')
    alias = 'nodeguard-service-'+str(service)
    path = CONTROL/'known_hosts'; old = path.read_text() if path.exists() else ''
    retained = [line for line in old.splitlines() if not line.startswith(alias+' ')]
    previous = [line for line in old.splitlines() if line.startswith(alias+' ')]
    pinned = alias+' '+fields[1]+' '+fields[2]
    if previous and previous != [pinned]:
        raise ValueError('Existing service host key differs; inspect it manually')
    write(path, '\n'.join([*retained, pinned])+'\n')


def verify_recovery_identity(database_bytes, current_ids, expected_key_id):
    """Never prune restored panel clients against an empty/unrelated cabinet."""
    import sqlite3
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary)/'accounts.sqlite3'; database.write_bytes(database_bytes); database.chmod(0o600)
        with closing(sqlite3.connect(database)) as db:
            archived_ids = {row[0] for row in db.execute('SELECT id FROM accounts')}
            key_id = db.execute('SELECT access_key_id FROM state').fetchone()[0]
    if archived_ids != set(current_ids) or key_id != expected_key_id:
        raise ValueError('Restore the matching cabinet database and original SITE_ACCESS_KEY before restoring x-ui')


def connect(config):
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Run connect as root on the RU controller')
    if not CURRENT.is_dir() or not (CONTROL/'id_ed25519').is_file():
        raise ValueError('Run bootstrap-host.sh on a clean RU controller first')
    sys.path[:0] = [str(CURRENT), str(ROOT/'deploy')]
    spec = importlib.util.spec_from_file_location('lifecycle', ROOT/'deploy/vpn-lifecycle.py')
    lc = importlib.util.module_from_spec(spec); spec.loader.exec_module(lc)
    env = lc.environment(Path('/etc/access-site/site.env').read_text())
    os.environ.update(env)
    from app.settings import Settings
    from app.db import Store
    from app.infrastructure import load_config
    from app.vdsina import Vdsina
    settings = Settings.from_env()
    ip, service = config['eu_ip'], config['eu_service_id']
    if ip == urlsplit(settings.origin).hostname:
        raise ValueError('RU controller and EU VPN must be different servers')
    directory = PRIVATE/ip; directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    identity = {'controller': settings.origin, 'eu_ip': ip, 'service_id': service}
    state_path = directory/'bootstrap.json'
    if env.get('SITE_XUI_URL') and not state_path.exists():
        raise ValueError('Controller already manages a VPN. Use update/replacement, not clean bootstrap')
    if state_path.exists():
        state = json.loads(state_path.read_text())
        if state['identity'] != identity:
            raise ValueError('Bootstrap target changed; inspect the existing private state')
    else:
        state = {'identity': identity, 'job_id': uuid4().hex}
        write(state_path, json.dumps(state))
    if (directory/'complete.json').exists():
        return {'ready': True, 'already_configured': True, 'ip': ip}
    # Validate secret files before changing either server.
    token = private_text(config['vdsina_token_file']) if config.get('vdsina_token_file') else None
    if token and (any(c.isspace() for c in token) or not 16 <= len(token) <= 512):
        raise ValueError('Invalid provider token file')
    optional = {}
    for label, allowed in [('telegram', {'TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID'}), ('ntfy', {'NTFY_URL', 'NTFY_TOKEN'})]:
        if config.get(label+'_env_file'):
            values = lc.environment(private_text(config[label+'_env_file']))
            if any('REPLACE_' in value for value in values.values()):
                raise ValueError('Fill private '+label+' settings before installation')
            if set(values)-allowed:
                raise ValueError('Unsupported keys in '+label+' environment file')
            if label == 'ntfy':
                from app.ntfy import Ntfy
                Ntfy(values.get('NTFY_URL', ''), values.get('NTFY_TOKEN', ''))
            else:
                from app.reminders import Telegram
                Telegram(values.get('TELEGRAM_BOT_TOKEN', ''), values.get('TELEGRAM_CHAT_ID', ''))
            optional[label] = values
    pin_host(ip, service, config['eu_host_fingerprint'])
    import grp
    group = grp.getgrnam('access-site').gr_gid
    for path in (lc.PROBES, lc.PUBLIC, settings.data_dir/'probes'):
        path.mkdir(parents=True, exist_ok=True); path.chmod(0o750); os.chown(path, 0, group)
    script_dir = Path('/opt/nodeguard-control/deploy'); script_dir.mkdir(parents=True, mode=0o755, exist_ok=True)
    script_dir.parent.chmod(0o755); script_dir.chmod(0o755)
    for name in SCRIPTS:
        shutil.copyfile(ROOT/'deploy'/name, script_dir/name); (script_dir/name).chmod(0o644)
    # A fixed path and persisted owner marker make retries safe without accepting arbitrary panels.
    marker = settings.origin+' '+state['job_id']
    remote = ("set -eu\n. /etc/os-release\n[ \"$ID\" = ubuntu ] && [ \"$VERSION_ID\" = 24.04 ]\n"
              "[ \"$(uname -m)\" = x86_64 ]\n"
              "if [ -e /etc/x-ui/x-ui.db ]; then [ -f /var/lib/nodeguard-bootstrap-owner ] && "
              "[ \"$(cat /var/lib/nodeguard-bootstrap-owner)\" = "+shlex.quote(marker)+" ]; fi\n"
              "printf '%s\\n' "+shlex.quote(marker)+" > /var/lib/nodeguard-bootstrap-owner\n"
              "chmod 600 /var/lib/nodeguard-bootstrap-owner\n"
              "export DEBIAN_FRONTEND=noninteractive\napt-get update\n"
              "apt-get install -y --no-install-recommends python3 ca-certificates curl openssl iproute2 tar gzip xz-utils\n")
    lc.run([*lc.ssh_args(ip, service), 'root@'+ip, 'sh -s'], data=remote.encode(), timeout=600)
    policy = {'network': 'xhttp', 'security': 'tls', 'port': 2053,
              'xhttpSettings': {'path': '/connect-'+os.urandom(12).hex(), 'mode': 'auto'}}
    if not lc.TRANSPORT_POLICY.exists():
        write(lc.TRANSPORT_POLICY, json.dumps(policy))
    provider = bool(token)
    node = {'id': 'EU1', 'ip': ip, 'port': 2053, 'service_id': service,
            'country': config.get('country', 'nl'), 'datacenter_id': config['datacenter_id'], 'native_daily_cost': '0.07'}
    observer_path = settings.data_dir/'probes/observer.json'
    template_path = settings.data_dir/'probes/EU1.json'
    infrastructure = {
        'mode': 'live' if provider else 'simulate', 'currency': 'USD', 'rub_per_unit': '100.00',
        'rate_valid_until': 0, 'baseline_daily': 0, 'fixed_monthly': 0, 'external_server_count': 1,
        'allow_overlap': False, 'max_servers': 3, 'required_ru_probes': 1, 'failures': 3,
        'nodes': [node], 'candidates': config.get('candidates', []),
        'delete_first': {'enabled': provider, 'auto_propose': provider, 'daily_cost': '0.07'},
        'probes': [{'id': 'RU1', 'region': 'ru', 'network': 'ru-controller',
                    'command': [str(CURRENT/'venv/bin/python'), str(script_dir/'vpn-probe.py'), str(observer_path)]}],
        **{key+'_command': [str(CURRENT/'venv/bin/python'), str(script_dir/'lifecycle-result.py'), stage]
           for key, stage in [('provision', 'provisioning'), ('verify', 'verifying'), ('publish', 'publishing')]}}
    config_path = Path('/var/lib/access-site/infrastructure.json')
    if config_path.exists() and not (directory/'configured.json').exists():
        raise ValueError('Existing infrastructure configuration was not created by this bootstrap')
    write(config_path, json.dumps(infrastructure, indent=2), public=True)
    write(directory/'configured.json', json.dumps(identity))
    load_config(config_path)
    env['SITE_INFRASTRUCTURE_CONFIG'] = str(config_path)
    write('/etc/access-site/site.env', ''.join(k+'='+shlex.quote(v)+'\n' for k,v in env.items()))
    os.environ.update(env)
    if token:
        write('/etc/access-site/infrastructure.env', 'VDSINA_API_TOKEN='+shlex.quote(token)+'\n')
        os.environ['VDSINA_API_TOKEN'] = token
    job = {'id': state['job_id'], 'service_id': service, 'node': 'EU1', 'spec': json.dumps({'old': node})}
    if config.get('recovery_archive_file'):
        import vpn_recovery
        archive = Path(config['recovery_archive_file'])
        if (archive.is_symlink() or not archive.is_file() or archive.stat().st_uid != 0
                or stat.S_IMODE(archive.stat().st_mode) & 0o077 or archive.stat().st_size > vpn_recovery.MAX_ARCHIVE):
            raise ValueError('Recovery archive must be a private root-owned regular file')
        data = archive.read_bytes(); manifest, archived_files = vpn_recovery.validate_archive(data)
        verify_recovery_identity(archived_files['accounts.sqlite3'],
            {row['id'] for row in Store(settings.data_dir).overview()[0]}, settings.access_key_id)
        job['spec'] = json.dumps({'old': manifest['node']})
        vpn_recovery.restore_panel(lc, job, ip, directory, data)
    lc.provision(job, ip, directory)
    details = json.loads((directory/'node.json').read_text())
    binaries = Path('/opt/nodeguard-control/bin'); binaries.mkdir(mode=0o755, parents=True, exist_ok=True); binaries.chmod(0o755)
    scp = ['scp', *lc.ssh_args(ip, service)[2:], 'root@'+ip+':/usr/local/x-ui/bin/xray-linux-amd64', str(binaries/'xray.new')]
    run(scp, timeout=180)
    expected = lc.run([*lc.ssh_args(ip, service), 'root@'+ip, 'sha256sum /usr/local/x-ui/bin/xray-linux-amd64']).decode().split()[0]
    if hashlib.sha256((binaries/'xray.new').read_bytes()).hexdigest() != expected:
        raise ValueError('Observer Xray transfer checksum mismatch')
    (binaries/'xray.new').chmod(0o755); os.replace(binaries/'xray.new', binaries/'xray')
    observer = {'xray': str(binaries/'xray'), 'curl': '/usr/bin/curl',
                'check_url': 'https://www.gstatic.com/generate_204', 'nodes': {'EU1': str(template_path)},
                'replacement_directory': str(lc.PROBES)}
    write(observer_path, json.dumps(observer), public=True)
    write(template_path, json.dumps(lc.client_template(details['link'])), public=True)
    write(settings.data_dir/'probes/notifications.json', json.dumps(lc.client_template(details['link'])), public=True)
    from app.infrastructure import Worker, Infrastructure
    report = Worker(Infrastructure(settings.data_dir, config_path)).probe(node)
    if not any(p['region']=='ru' and p['observer_ok'] and p['vpn_ok'] for p in report['probes']):
        raise ValueError('End-to-end VPN check failed; user links were not published')
    write(lc.UNIT, lc.unit_for(details, service)); lc.UNIT.chmod(0o644)
    run(['systemctl', 'daemon-reload']); run(['systemctl', 'enable', '--now', lc.UNIT.name])
    lc.publish(job, details, directory)
    for label, values in optional.items():
        if label == 'telegram':
            values['TELEGRAM_SOCKS_PROXY'] = '127.0.0.1:10809'
        write('/etc/access-site/'+label+'.env', ''.join(k+'='+shlex.quote(v)+'\n' for k,v in values.items()))
    if 'ntfy' in optional:
        write(settings.data_dir/'ntfy-connection.json', json.dumps({'url': optional['ntfy']['NTFY_URL']}), public=True)
        run(['systemctl', 'enable', '--now', 'access-site-ntfy.timer'])
    if 'telegram' in optional:
        write(CONTROL/'notification-targets.json', json.dumps({'EU1': {'ip': ip, 'alias': 'nodeguard-service-'+str(service)}}))
        shutil.copyfile(ROOT/'deploy/systemd/access-site-notification-proxy.service', '/etc/systemd/system/access-site-notification-proxy.service')
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', 'access-site-notification-proxy.service', 'access-site-events.timer', 'access-site-reminders.timer'])
    from app.infrastructure import Worker, Infrastructure
    report = Worker(Infrastructure(settings.data_dir, config_path)).probe(node)
    if not any(p['region']=='ru' and p['observer_ok'] and p['vpn_ok'] for p in report['probes']):
        raise ValueError('End-to-end VPN check from the RU controller failed')
    run(['systemctl', 'enable', '--now', 'access-site-infrastructure.timer'])
    if provider:
        run(['systemctl', 'enable', '--now', 'access-site-delete-first.timer'])
    result = {'ready': True, 'ip': ip, 'port': 2053, 'vpn_verified': True,
              'replacement_requires_admin': True, 'replacement_enabled': provider,
              'accounts': len(Store(settings.data_dir).overview()[0])}
    write(directory/'complete.json', json.dumps(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('--check', action='store_true', help='Validate configuration; no SSH, installation or ordering')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        value = validate(json.loads(private_text(args.config)))
        if args.check:
            print(json.dumps({'valid': True, 'changes': False})); return 0
        if os.name != 'posix' or os.geteuid() != 0:
            raise ValueError('Run installation as root on the RU controller')
        import fcntl
        PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (PRIVATE/'bootstrap.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(connect(value)))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Do not expose captured SSH stdout/stderr: installer results contain panel credentials.
        print('Bootstrap stopped: '+(str(error) if isinstance(error, (ValueError, KeyError)) else type(error).__name__)
              +'. Inspect the private bootstrap state; do not reset a running server.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
