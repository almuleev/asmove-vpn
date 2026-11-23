#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
source "$root/deploy/lib.sh"
require_root
if [[ ( ( $# -ne 2 && $# -ne 3 ) || ${1:-} != primary ) && ( $# -ne 3 || ${1:-} != replica ) ]]; then
    echo 'Usage: install.sh primary HTTPS_HOST[:PORT] [ACCESS_KEY_FILE] | install.sh replica HTTPS_HOST[:PORT] ACCESS_KEY_FILE' >&2
    exit 2
fi
role=$1 authority=$2
parse_https_authority "$authority"
source /etc/os-release
[[ $ID == ubuntu ]] || { echo 'Ubuntu required.' >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ required"'
command -v curl >/dev/null
if [[ $role == primary && $# == 2 ]]; then
    access_key=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
else
    [[ -f $3 && ! -L $3 && $(stat -c '%u:%a' -- "$3") =~ ^0:(400|600)$ ]]
    access_key=$(cat -- "$3")
    [[ $access_key =~ ^[a-f0-9]{64}$ ]] || { echo 'Invalid access key file.' >&2; exit 1; }
fi
exec 9>/run/lock/access-site-deploy.lock
flock -n 9
for path in /opt/access-site/current /etc/access-site /var/lib/access-site \
    /etc/systemd/system/access-site* /usr/local/sbin/access-site; do
    if [[ -e $path || -L $path ]]; then
        echo "Existing path: $path. Inspect it before installation." >&2
        exit 1
    fi
done
if [[ -n $(ss -H -ltn 'sport = :8016') ]] || getent passwd access-site >/dev/null; then
    echo 'Local port 8016 or user access-site is already in use.' >&2
    exit 1
fi

install -d -m 0755 /opt/access-site/releases
build_release "$root"
umask 077
useradd --system --user-group --home-dir /var/lib/access-site --shell /usr/sbin/nologin access-site
install -d -m 0755 /var/lib/access-site
install -d -m 0700 -o access-site -g access-site /var/lib/access-site/{data,sender}
install -d -m 0700 /etc/access-site
printf "SITE_ROLE='%s'\nSITE_ORIGIN='https://%s'\nSITE_DATA_DIR='/var/lib/access-site/data'\n" \
    "$role" "$authority" > /etc/access-site/site.env
printf "SITE_ACCESS_KEY='%s'\n" "$access_key" >> /etc/access-site/site.env
unset access_key
(
    cd "$release"
    venv/bin/python -m app.cli credentials >> /etc/access-site/site.env 2> /etc/access-site/initial-admin.txt
)
activate_release "$release"
install -m 0755 "$root/deploy/access-site" /usr/local/sbin/access-site
/usr/local/sbin/access-site init
install -m 0644 "$root/deploy/systemd/"* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now access-site.service access-site-backup.timer
expected='{"status":"ok"}'
if [[ $role == replica ]]; then
    expected='{"status":"unavailable"}'
fi
check_service "$authority" "$expected"
echo 'Read the initial admin password in your private VPS console: cat /etc/access-site/initial-admin.txt'
