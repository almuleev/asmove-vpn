"""Issue/renew the EU VPN's IP certificate, independently of the panel certificate."""
import argparse
import fcntl
import functools
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.request

STATE = Path('/var/lib/asmove-vpn-tls')
CERT = Path('/etc/asmove-vpn-tls')
PROGRAM = '/usr/local/lib/asmove/vpn-tls.py'
VERSION = '3.1.7'
SOURCE_SHA256 = '35bf6b947478666be137f938f77c5089954f120798220e6fff390949c5ea5692'


def run(args, timeout=30):
    return subprocess.run(args, check=True, capture_output=True, timeout=timeout).stdout


def valid_certificate(chain, key, ip, seconds=259200):
    try:
        run(['openssl', 'x509', '-in', str(chain), '-noout', '-checkend', str(seconds)])
        run(['openssl', 'verify', '-purpose', 'sslserver', '-verify_ip', ip,
             '-untrusted', str(chain), str(chain)])
        public = run(['openssl', 'x509', '-in', str(chain), '-pubkey', '-noout'])
        private_public = run(['openssl', 'pkey', '-in', str(key), '-pubout'])
        return public == private_public
    except (OSError, subprocess.SubprocessError):
        return False


def install(ip):
    (CERT/'ip').write_text(ip+'\n'); (CERT/'ip').chmod(0o600)
    unit = ('[Unit]\nDescription=Renew VPN IP certificate\nAfter=network-online.target\n'
            '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+PROGRAM+' --renew\n'
            'TimeoutStartSec=6min\nUMask=0077\nNoNewPrivileges=yes\nProtectHome=yes\n'
            'PrivateTmp=yes\nProtectSystem=strict\n'
            'ReadWritePaths='+str(STATE)+' '+str(CERT)+'\n')
    timer = ('[Unit]\nDescription=Check VPN certificate twice daily\n[Timer]\n'
             'OnCalendar=*-*-* 00,12:15:00\nRandomizedDelaySec=20min\nPersistent=true\n'
             'OnBootSec=5min\n[Install]\nWantedBy=timers.target\n')
    Path('/etc/systemd/system/asmove-vpn-tls.service').write_text(unit)
    Path('/etc/systemd/system/asmove-vpn-tls.timer').write_text(timer)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'asmove-vpn-tls.timer'])


class Challenge(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if not self.path.startswith('/.well-known/acme-challenge/') or '..' in self.path:
            return self.send_error(404)
        return super().do_GET()

    def list_directory(self, path):
        return self.send_error(404)


def ensure(ip, force=False):
    address = ipaddress.IPv4Address(ip)
    if not address.is_global:
        raise ValueError('Expected a public IPv4 address')
    local = json.loads(run(['ip', '-j', '-4', 'address', 'show']))
    if ip not in {a['local'] for link in local for a in link.get('addr_info', [])}:
        raise ValueError('Certificate IP must belong to this VPS')
    chain, key = CERT/'fullchain.pem', CERT/'privkey.pem'
    if not force and valid_certificate(chain, key, ip):
        return {'ready': True, 'changed': False, 'ip': ip}
    source = STATE/'acme.sh'
    if not source.exists() or hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA256:
        url = f'https://raw.githubusercontent.com/acmesh-official/acme.sh/{VERSION}/acme.sh'
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read(1024*1024)
        if hashlib.sha256(content).hexdigest() != SOURCE_SHA256:
            raise ValueError('ACME source checksum mismatch')
        source.write_bytes(content); source.chmod(0o700)
    webroot = STATE/'webroot'; webroot.mkdir(mode=0o700, exist_ok=True)
    handler = functools.partial(Challenge, directory=str(webroot))
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 80), handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    try:
        args = ['sh', str(source), '--issue', '--server', 'letsencrypt', '-d', ip,
                '--webroot', str(webroot), '--certificate-profile', 'shortlived', '--days', '3',
                '--keylength', 'ec-256', '--home', str(STATE/'acme'),
                '--config-home', str(STATE/'acme'), '--cert-home', str(STATE/'certs')]
        if force:
            args.append('--force')
        result = subprocess.run(args, capture_output=True, timeout=270)
        log = STATE/'last-issue.log'; log.write_bytes(result.stdout+result.stderr); log.chmod(0o600)
        issued = STATE/'certs'/f'{ip}_ecc'/'fullchain.cer'
        issued_key = issued.with_name(f'{ip}.key')
        if not valid_certificate(issued, issued_key, ip):
            raise RuntimeError('Certificate issuance/validation failed; see private last-issue.log')
        # Both files are validated before replacing either. Xray reloads only after both replacements.
        for origin, target in ((issued_key, key), (issued, chain)):
            temporary = target.with_suffix('.new'); temporary.write_bytes(origin.read_bytes())
            temporary.chmod(0o600); os.replace(temporary, target)
        metadata = {'ip': ip, 'renewed_at': time.time(), 'sha256': hashlib.sha256(chain.read_bytes()).hexdigest()}
        path = CERT/'state.json'; path.write_text(json.dumps(metadata)); path.chmod(0o600)
        run(['systemctl', 'try-restart', 'x-ui.service'], timeout=40)
        return {'ready': True, 'changed': True, 'ip': ip}
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--renew', action='store_true')
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    CERT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE/'renew.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ip = args.ip or (CERT/'ip').read_text().strip()
        result = ensure(ip, args.force)
        if args.install:
            install(ip)
        print(json.dumps(result))


if __name__ == '__main__':
    main()
