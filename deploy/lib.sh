#!/usr/bin/env bash

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo 'Run this script as root.' >&2
        exit 1
    fi
}

valid_host() {
    python3 - "$1" <<'PY'
import ipaddress
import re
import sys

host = sys.argv[1]
try:
    address = ipaddress.ip_address(host)
except ValueError:
    labels = host.split(".")
    valid = len(host) <= 253 and len(labels) >= 2 and not labels[-1].isdigit()
    valid = valid and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels)
else:
    valid = address.version == 4 and address.is_global
if not valid:
    raise SystemExit("Expected a lowercase DNS name or a public IPv4 address")
PY
}

parse_https_authority() {
    https_host=${1%%:*}
    https_port=443
    if [[ $1 == *:* ]]; then
        https_port=${1##*:}
        if [[ ! $https_port =~ ^[1-9][0-9]{0,4}$ ]] || (( https_port > 65535 || https_port == 443 || https_port == 80 || https_port == 8016 )); then
            echo 'Expected a free HTTPS port other than 80, 443 or 8016. Omit the port for HTTPS on 443.' >&2
            return 1
        fi
    fi
    valid_host "$https_host"
    [[ $1 == "$https_host" || $1 == "$https_host:$https_port" ]]
}

load_site() {
    # Only root can write these files.
    set -a
    source /etc/access-site/site.env
    set +a
}

build_release() {
    local root=$1
    umask 022
    release=$(mktemp -d /opt/access-site/releases/release-XXXXXXXX)
    chmod 0755 "$release"
    cp -r "$root/app" "$release/"
    find "$release/app" -type d -name __pycache__ -prune -exec rm -rf -- {} +
    python3 -m venv "$release/venv"
    local constraints=()
    if [[ -f $root/requirements-constraints.txt ]]; then
        constraints=(-c "$root/requirements-constraints.txt")
    fi
    "$release/venv/bin/python" -m pip --disable-pip-version-check install -r "$root/requirements.txt" "${constraints[@]}"
    "$release/venv/bin/python" -m pip check
    (
        cd "$release"
        venv/bin/python -c 'from app.main import create_app; from app.cli import main'
    )
}

activate_release() {
    local link
    link=$(mktemp -d /opt/access-site/switch-XXXXXXXX)
    ln -s "$1" "$link/current"
    mv -Tf "$link/current" /opt/access-site/current
    rmdir "$link"
}

check_service() {
    local host=$1 expected=$2 response
    for _ in {1..20}; do
        if systemctl is-active --quiet access-site.service &&
            response=$(curl -sS --max-time 2 -H "Host: $host" -H 'X-Forwarded-Proto: https' http://127.0.0.1:8016/health 2>/dev/null) &&
            [[ $response == "$expected" ]]; then
            return 0
        fi
        sleep 1
    done
    echo 'Local health check did not pass. See journalctl -u access-site.service.' >&2
    return 1
}
