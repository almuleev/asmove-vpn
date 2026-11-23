"""Owner-authorized automatic recovery; no provider calls from the web process."""
import hashlib
import json

from .db import connect

DEFAULTS = dict(enabled=False, trigger='vpn_failed', failures=3, failure_seconds=180,
                cooldown_seconds=3600, max_per_day=2)


def validate(value):
    if not isinstance(value, dict) or set(value) - DEFAULTS.keys():
        raise ValueError('Unknown automatic recovery setting')
    policy = {**DEFAULTS, **value}
    if type(policy['enabled']) is not bool or policy['trigger'] not in {'vpn_failed', 'tcp_and_vpn_failed'}:
        raise ValueError('Invalid recovery mode or trigger')
    for key, low, high in [('failures', 3, 20), ('failure_seconds', 120, 3600),
                           ('cooldown_seconds', 600, 86400), ('max_per_day', 1, 10)]:
        if type(policy[key]) is not int or not low <= policy[key] <= high:
            raise ValueError('Invalid automatic recovery threshold: ' + key)
    return policy


def fingerprint(policy):
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()


def read(db):
    row = db.execute('SELECT value FROM automation_policy WHERE id=1').fetchone()
    return validate(json.loads(row[0]) if row else {})


def save(store, value, *, accept_downtime=False):
    policy = validate(value)
    if policy['enabled'] and not accept_downtime:
        raise ValueError('Confirm that automatic recovery deletes the old VPS and causes downtime')
    store.initialize()
    with store.write() as db:
        db.execute('INSERT OR REPLACE INTO automation_policy VALUES (1,?)', (json.dumps(policy),))
        db.execute('DELETE FROM automation_observations')
    return policy


def failed(evidence, policy, config):
    probes = evidence.get('probes', [])
    healthy = [p for p in probes if p.get('region') == 'ru' and p.get('observer_ok') is True]
    # Two distinct HTTPS destinations must have working direct controls. A broken
    # observer, target or Xray process must not be interpreted as a VPN failure.
    return (len(healthy) >= config['required_ru_probes']
            and all(p.get('vpn_ok') is False and p.get('targets_total', 0) >= 2 for p in healthy)
            and (policy['trigger'] == 'vpn_failed' or evidence.get('tcp') is False))


def record(db, node, evidence, config, now):
    policy = read(db)
    if not policy['enabled'] or not failed(evidence, policy, config):
        db.execute('DELETE FROM automation_observations WHERE node=?', (node,))
        return
    old = db.execute('SELECT * FROM automation_observations WHERE node=?', (node,)).fetchone()
    continuous = old and now - old['last_at'] <= config['probe_max_age']
    # Duplicate/replayed timestamps never advance the consecutive sample count.
    if continuous and now <= old['last_at']:
        return
    db.execute('INSERT OR REPLACE INTO automation_observations VALUES (?,?,?,?)',
               (node, old['since_at'] if continuous else now, now, old['failures'] + 1 if continuous else 1))


def eligible(db, node, config, now, *, excluding=None, expected_policy=None):
    policy = read(db)
    if not policy['enabled'] or config['mode'] != 'live' or not config['delete_first']['enabled']:
        return False
    if expected_policy and fingerprint(policy) != expected_policy:
        return False
    sample = db.execute('SELECT * FROM automation_observations WHERE node=?', (node,)).fetchone()
    if (not sample or not 0 <= now - sample['last_at'] <= config['probe_max_age']
            or sample['failures'] < policy['failures'] or now - sample['since_at'] < policy['failure_seconds']):
        return False
    jobs = db.execute("SELECT id,json_extract(spec,'$.approved_at') AS created FROM jobs WHERE json_extract(spec,'$.automatic')=1 "
                      "AND status NOT IN ('cancelled','expired','recovered') AND json_extract(spec,'$.approved_at')>?",
                      (now - 86400,)).fetchall()
    previous = [j for j in jobs if j['id'] != excluding]
    if len(previous) >= policy['max_per_day']:
        return False
    if previous and now - max(j['created'] for j in previous) < policy['cooldown_seconds']:
        return False
    if db.execute("SELECT 1 FROM jobs WHERE id!=? AND status IN ('approved','preparing','deleting',"
                  "'waiting_delete','ordering_ready','ordering','uncertain','provisioning','verifying','publishing','attention')",
                  (excluding or '',)).fetchone():
        return False
    return True


def maybe_start(store, operations):
    """Called only by root worker. Existing pending incidents may be authorized once."""
    from .delete_first import DeleteFirstControl
    from .infrastructure import load_config, timestamp
    config = load_config(store.config_path)
    for configured in config['nodes']:
        with connect(store.path) as db:
            if not eligible(db, configured['id'], config, timestamp()):
                continue
        node = DeleteFirstControl(store).node(config, configured['id'])
        policy = None
        with connect(store.path) as db:
            policy = read(db)
        # Fresh direct proof and provider/archive preflight before authorizing.
        if not failed(operations.automation_probe(node), policy, config):
            with store.write() as db:
                db.execute('DELETE FROM automation_observations WHERE node=?', (node['id'],))
            continue
        operations.check(node['id'], config)
        job_id = DeleteFirstControl(store).prepare(node['id'], manual=False)
        with store.write() as db:
            job = db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            if job['status'] != 'pending' or job['expires'] <= timestamp():
                continue
            policy = read(db)
            if not eligible(db, node['id'], config, timestamp(), excluding=job_id):
                continue
            spec = json.loads(job['spec'])
            if spec['fingerprint'] != config['fingerprint'] or spec['old'] != node:
                continue
            spec.update(automatic=True, automation_policy=fingerprint(policy), approved_at=timestamp(),
                        approved_ip=node['ip'], accepted_downtime=True)
            store.update(db, job_id, 'approved', reserved=1, spec=json.dumps(spec))
