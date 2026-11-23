#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
source "$root/deploy/lib.sh"
require_root
exec 9>/run/lock/access-site-deploy.lock
flock -n 9
load_site
# Do not change journal prefixes, policy or executors during an unfinished job.
/opt/access-site/current/venv/bin/python - <<'PY'
import os, sqlite3
from pathlib import Path
path = Path(os.environ['SITE_DATA_DIR']) / 'infrastructure.sqlite3'
if path.exists():
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        if db.execute("SELECT 1 FROM jobs WHERE status NOT IN ('ready','cancelled','expired','simulated','recovered') LIMIT 1").fetchone():
            raise SystemExit('Finish or cancel the current replacement before updating')
PY
old=$(readlink -f /opt/access-site/current)
expected='{"status":"ok"}'
if /usr/local/sbin/access-site status | grep -q '"ready": false'; then
    expected='{"status":"unavailable"}'
fi
build_release "$root"
if [[ $expected == '{"status":"ok"}' ]]; then
    systemctl start access-site-backup.service
fi
activate_release "$release"
if ! /usr/local/sbin/access-site init || ! systemctl restart access-site.service ||
    ! check_service "${SITE_ORIGIN#https://}" "$expected"; then
    activate_release "$old"
    systemctl restart access-site.service
    check_service "${SITE_ORIGIN#https://}" "$expected"
    echo 'Update rolled back.' >&2
    exit 1
fi
if [[ -d /opt/asmove-control/deploy ]]; then
    for file in vpn-lifecycle.py delete-first.py vpn_recovery.py lifecycle-result.py xui_setup.py install-3x-ui-remote.py vpn-probe.py notification-proxy.py tcp-relay.py vpn-tls.py export-state.py; do
        install -m 0644 "$root/deploy/$file" "/opt/asmove-control/deploy/$file"
    done
    if [[ -f /var/lib/access-site/control/notification-targets.json ]]; then
        install -m 0644 "$root/deploy/systemd/access-site-notification-proxy.service" /etc/systemd/system/
    fi
    install -m 0644 "$root/deploy/systemd/access-site-tcp-relay.service" /etc/systemd/system/
fi
install -m 0644 "$root/deploy/systemd/"* /etc/systemd/system/
systemctl daemon-reload
if [[ -f /var/lib/access-site/data/tcp-relay.json ]]; then
    systemctl enable --now access-site-tcp-relay.service
    systemctl restart access-site-tcp-relay.service
fi
if [[ -f /var/lib/access-site/infrastructure.json ]]; then
    systemctl enable --now access-site-delete-first.timer
fi
if [[ -s /etc/access-site/ntfy.env ]]; then
    systemctl enable --now access-site-ntfy.timer
fi
if [[ $SITE_ROLE == primary && -s /etc/access-site/telegram.env ]]; then
    systemctl enable --now access-site-reminders.timer
fi
if [[ -n ${SITE_EMERGENCY_CONTROLLER:-} || -n ${SITE_EVENT_CONTROLLER:-} || -s /etc/access-site/telegram.env ]]; then
    systemctl enable --now access-site-events.timer
fi
