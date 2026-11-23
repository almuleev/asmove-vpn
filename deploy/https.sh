#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
source "$root/deploy/lib.sh"
require_root
if [[ $# -gt 1 || ( $# -eq 1 && -n $1 && $1 != *@* ) ]]; then
    echo 'Usage: https.sh [CERTIFICATE_EMAIL]' >&2
    exit 2
fi
contact=(--register-unsafely-without-email)
if [[ -n ${1:-} ]]; then
    contact=(--email "$1")
fi
load_site
authority=${SITE_ORIGIN#https://}
parse_https_authority "$authority"
host=$https_host
port=$https_port
certbot=certbot
if [[ -n ${ACCESS_SITE_CERTBOT:-} ]]; then
    certbot=$ACCESS_SITE_CERTBOT
elif [[ -x /snap/bin/certbot ]]; then
    certbot=/snap/bin/certbot
elif [[ -x /opt/access-site-certbot/bin/certbot ]]; then
    certbot=/opt/access-site-certbot/bin/certbot
fi
command -v "$certbot" >/dev/null
systemctl is-active --quiet nginx
nginx -t
exec 9>/run/lock/access-site-deploy.lock
flock -n 9

webroot=/var/www/access-site-acme
conf=/etc/nginx/sites-available/access-site.conf
enabled=/etc/nginx/sites-enabled/access-site.conf
hook=/etc/letsencrypt/renewal-hooks/deploy/40-access-site-nginx
if [[ -e $enabled || -L $enabled || -e $conf || -L $conf || -e $hook || -L $hook ]]; then
    echo 'Access site Nginx or Certbot paths already exist. Inspect them before continuing.' >&2
    exit 1
fi
umask 077
temporary=$(mktemp -d)
installed=0
cleanup() {
    local status=$?
    if (( status != 0 && installed != 0 )); then
        rm -f -- "$enabled" "$conf" "$hook"
        nginx -t && systemctl reload nginx || true
    fi
    rm -f -- "$temporary/nginx.conf" "$temporary/site.conf"
    rmdir "$temporary"
}
trap cleanup EXIT
nginx -T > "$temporary/nginx.conf" 2>/dev/null
if python3 - "$host" "$temporary/nginx.conf" <<'PY'
import re
import sys
from pathlib import Path

text = re.sub(r"#.*", "", Path(sys.argv[2]).read_text())
existing = any(sys.argv[1] in line.split() for line in re.findall(r"\bserver_name\s+([^;]+);", text))
raise SystemExit(0 if existing else 1)
PY
then
    echo 'An existing Nginx site already declares this host.' >&2
    exit 1
fi

listen_https="listen $port ssl;"
ipv6_http=''
ipv6_https=''
certificate_name="access-site-$host"
identifier=(-d "$host")
if [[ $host =~ ^[0-9.]+$ ]]; then
    if [[ -n $(ss -H -ltn "sport = :$port") ]]; then
        printf 'Port %s already has a listener. Select a free HTTPS port for the IP certificate.\n' "$port" >&2
        exit 1
    fi
    "$certbot" --version | python3 -c 'import re, sys; m = re.search(r"(\d+)\.(\d+)", sys.stdin.read()); sys.exit(0 if m and tuple(map(int, m.groups())) >= (5, 4) else "Certbot 5.4+ required for IPv4")'
    listen_https="listen $port ssl default_server;"
    identifier=(--preferred-profile shortlived --ip-address "$host")
elif grep -q . /proc/net/if_inet6 2>/dev/null; then
    ipv6_http='listen [::]:80;'
    ipv6_https="listen [::]:$port ssl;"
fi

install -d -m 0755 "$webroot"

cat > "$temporary/site.conf" <<EOF
server {
    listen 80;
    $ipv6_http
    server_name $host;
    access_log off;
    error_log /dev/null crit;

    location ^~ /.well-known/acme-challenge/ {
        root $webroot;
        try_files \$uri =404;
    }
    location / {
        return 308 https://$authority/;
    }
}
EOF
installed=1
install -m 0644 "$temporary/site.conf" "$conf"
ln -s "$conf" "$enabled"
nginx -t
systemctl reload nginx

"$certbot" certonly --webroot -w "$webroot" --cert-name "$certificate_name" \
    --non-interactive --agree-tos "${contact[@]}" --keep-until-expiring "${identifier[@]}"
chain="/etc/letsencrypt/live/$certificate_name/fullchain.pem"
[[ -s $chain ]]
cat >> "$temporary/site.conf" <<EOF

server {
    $listen_https
    $ipv6_https
    server_name $host;
    ssl_certificate $chain;
    ssl_certificate_key /etc/letsencrypt/live/$certificate_name/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    access_log off;
    error_log /dev/null crit;
    client_max_body_size 32k;
    client_body_buffer_size 32k;
    client_body_timeout 10s;

    location / {
        proxy_pass http://127.0.0.1:8016;
        proxy_http_version 1.1;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Forwarded "";
        proxy_cache off;
        proxy_buffering off;
        proxy_read_timeout 15s;
    }
}
EOF
install -m 0644 "$temporary/site.conf" "$conf"
nginx -t
systemctl reload nginx
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > "$hook" <<'EOF'
#!/bin/sh
set -eu
conf=/etc/nginx/sites-enabled/access-site.conf
if [ -f "$conf" ] && grep -Fxq "    ssl_certificate $RENEWED_LINEAGE/fullchain.pem;" "$conf"; then
    /usr/sbin/nginx -t -q
    /usr/bin/systemctl reload nginx
fi
EOF
chmod 0755 "$hook"
curl --silent --show-error --max-time 8 --noproxy '*' --connect-to "$host:$port:127.0.0.1:$port" "https://$authority/health" >/dev/null
printf 'HTTPS enabled: https://%s/\n' "$authority"
