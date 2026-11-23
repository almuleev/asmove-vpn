#!/usr/bin/env bash
# Initial installation ONLY; update an existing controller with deploy/update.sh.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
source "$root/deploy/lib.sh"
require_root
if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo 'Usage: bootstrap-host.sh PUBLIC_IP_OR_HOST [PORTAL_ORIGIN] [ORIGINAL_ACCESS_KEY_FILE]' >&2
    exit 2
fi
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && $(dpkg --print-architecture) == amd64 ]] || {
    echo 'This bootstrap requires Ubuntu 24.04 amd64.' >&2; exit 1;
}
[[ -d /run/systemd/system ]] || { echo 'A real systemd host is required.' >&2; exit 1; }
[[ ! -e /etc/access-site/site.env && ! -e /opt/access-site/current ]] || {
    echo 'Existing installation detected. Use update.sh; bootstrap will not overwrite it.' >&2; exit 1;
}
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 python3-venv python3-pip ca-certificates \
    curl openssl nginx openssh-client iproute2 util-linux tar gzip xz-utils age
authority=$1 portal=${2:-}
parse_https_authority "$authority"
python3 - "$portal" <<'PY'
import re,sys
if sys.argv[1] and not re.fullmatch(r'https://[a-z0-9.-]+', sys.argv[1]):
    raise SystemExit('PORTAL_ORIGIN must be an HTTPS origin without a path')
PY
python3 -m venv /opt/access-site-certbot
/opt/access-site-certbot/bin/pip --disable-pip-version-check install certbot==5.4.0
/opt/access-site-certbot/bin/pip check
systemctl enable --now nginx
bash "$root/deploy/install.sh" primary "$authority" ${3:+"$3"}
python3 - "$portal" <<'PY'
import shlex,sys
from pathlib import Path
p=Path('/etc/access-site/site.env')
with p.open('a') as f:
    f.write("SITE_REPLICATION_ENABLED='0'\nSITE_PORTAL_ORIGIN="+shlex.quote(sys.argv[1])+"\n")
PY
bash "$root/deploy/https.sh"
systemctl enable --now "access-site-cert-renew@${https_host}.timer"
install -d -m 0700 /var/lib/access-site/control /var/lib/asmove-delete-first
if [[ ! -f /var/lib/access-site/control/id_ed25519 ]]; then
    ssh-keygen -q -t ed25519 -N '' -C asmove-control -f /var/lib/access-site/control/id_ed25519
fi
if [[ ! -f /var/lib/asmove-delete-first/backup_ed25519 ]]; then
    ssh-keygen -q -t ed25519 -N '' -C asmove-backup -f /var/lib/asmove-delete-first/backup_ed25519
fi
systemctl restart access-site.service
check_service "$authority" '{"status":"ok"}'
echo "Controller ready: https://$authority/admin"
echo 'Admin password: /etc/access-site/initial-admin.txt (root only)'
echo 'Add /var/lib/access-site/control/id_ed25519.pub to the EU VPS root authorized_keys.'
echo 'Then fill deploy/bootstrap.example.json privately and run deploy/bootstrap-vpn.py.'
