"""Delete-first replacement control and restart-safe orchestration.

Destructive operations require acknowledgement of the exact old service and IP.
"""
import json
from decimal import Decimal
from uuid import uuid4

from .db import connect
from .infrastructure import InfrastructureError, OPEN, timestamp, load_config
from .vdsina import REQUIRED_DAILY_COST

STAGES = ('approved', 'preparing', 'deleting', 'waiting_delete', 'ordering_ready',
          'ordering', 'uncertain', 'provisioning', 'verifying', 'publishing')


def validate_approval(config, spec, acknowledgement):
    policy = config['delete_first']
    if not policy['enabled']:
        raise InfrastructureError('Замена с простоем отключена.')
    ack = acknowledgement or {}
    if ack.get('ip') != spec['old']['ip'] or ack.get('downtime') != 'yes':
        raise InfrastructureError('Введите IP удаляемого VPS и подтвердите простой.')


class DeleteFirstControl:
    def __init__(self, infrastructure):
        self.store = infrastructure

    def node(self, config, node_id):
        node = next((dict(n) for n in config['nodes'] if n['id'] == node_id), None)
        if node is None or node.get('country') == 'ru':
            raise InfrastructureError('Зарубежный VPN-узел не найден.')
        with connect(self.store.path) as db:
            row = db.execute('SELECT spec FROM overrides WHERE node=?', (node_id,)).fetchone()
        if row:
            node.update(json.loads(row['spec']))
        return node

    def prepare(self, node_id, *, manual=True):
        self.store.initialize()
        config = load_config(self.store.config_path)
        if not config['delete_first']['enabled']:
            raise InfrastructureError('Замена с простоем отключена.')
        node = self.node(config, node_id)
        candidates = sorted(config['candidates'], key=lambda row: (row['datacenter_id'] == node['datacenter_id'], row['country'] == node['country']))
        candidate = next((row for row in candidates if Decimal(str(row['daily_cost'])) == REQUIRED_DAILY_COST), None)
        if not candidate:
            raise InfrastructureError('Нет доступной конфигурации для создания нового сервера.')
        from .infrastructure import Worker
        daily = Worker(self.store).rubles(candidate['daily_cost'])
        month, days = self.store.month()
        spec = dict(delete_first=True, fingerprint=config['fingerprint'], candidate=candidate, old=node,
                    mode=config['mode'], daily_rub=daily, overlap=False, manual=manual,
                    incident=uuid4().hex, acknowledgement_required=True)
        job_id = uuid4().hex
        with self.store.write() as db:
            if not manual:
                observed = db.execute('SELECT incident FROM nodes WHERE id=?', (node_id,)).fetchone()
                spec['incident'] = observed['incident'] if observed else spec['incident']
                previous = db.execute("SELECT id FROM jobs WHERE node=? AND json_extract(spec,'$.incident')=? AND status IN ('cancelled','simulated')",
                                      (node_id,spec['incident'])).fetchone()
                if previous:return previous['id']
            existing = db.execute('SELECT id FROM jobs WHERE node=? AND status IN (' + ','.join('?' for _ in OPEN) + ')', (node_id, *OPEN)).fetchone()
            if existing:
                if not manual:return existing['id']
                raise InfrastructureError('Сначала завершите текущую заявку этого узла.')
            db.execute('INSERT INTO jobs(id,node,status,created,expires,updated,spec,monthly,charge) VALUES (?,?,?,?,?,?,?,?,?)',
                       (job_id, node_id, 'pending', timestamp(), timestamp()+config['approval_ttl'], timestamp(), json.dumps(spec), month, 0))
            self.store.update(db, job_id, 'pending')
        return job_id

    def request_check(self, node_id):
        self.store.initialize()
        config = load_config(self.store.config_path)
        if not config['delete_first']['enabled']:
            raise InfrastructureError('Замена с простоем отключена.')
        self.node(config, node_id)
        with self.store.write() as db:
            db.execute('INSERT INTO replacement_checks(node,request_id,requested) VALUES (?,?,?) '
                       'ON CONFLICT(node) DO UPDATE SET request_id=excluded.request_id,requested=excluded.requested,finished=0,result=?',
                       (node_id, uuid4().hex, timestamp(), '{}'))


class DeleteFirstRunner:
    """Runs only in the independent root service; external effects are injected."""
    def __init__(self, control, provider, operations):
        self.control, self.provider, self.ops = control, provider, operations

    def job(self, job_id):
        with connect(self.control.path, 'ro') as db:
            row = db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
        return dict(row) if row else None

    def status(self, job, state, **values):
        with self.control.write() as db:
            current = db.execute('SELECT status FROM jobs WHERE id=?', (job['id'],)).fetchone()
            if not current or current[0] != job['status']:
                return False
            self.control.update(db, job['id'], state, **values)
        return True

    def gate(self, job, config, *, first_delete=False):
        spec = json.loads(job['spec'])
        if not config['delete_first']['enabled']:
            raise InfrastructureError('delete_first_disabled')
        if spec.get('approved_ip') != spec['old']['ip'] or not spec.get('accepted_downtime'):
            raise InfrastructureError('destructive_acknowledgement_required')
        if spec['fingerprint'] != config['fingerprint']:
            raise InfrastructureError('configuration_changed')
        if first_delete and job['expires'] <= timestamp():
            raise InfrastructureError('approval_expired_before_deletion')
        if spec.get('automatic'):
            from .automation import eligible, failed, read
            with connect(self.control.path) as db:
                policy = read(db)
                allowed = eligible(db, job['node'], config, timestamp(), excluding=job['id'],
                                   expected_policy=spec.get('automation_policy'))
            if not allowed or not failed(self.ops.automation_probe(spec['old']), policy, config):
                raise InfrastructureError('automatic_recovery_conditions_changed')
        if spec['old']['country'] == 'ru' or spec['old']['service_id'] <= 0:
            raise InfrastructureError('invalid_delete_target')
        return spec

    def exclusive(self, job):
        with connect(self.control.path) as db:
            self.control.check_replacement_slot(db, excluding=job['id'])

    def attention(self, job, stage, reason):
        spec = json.loads(job['spec']); spec['resume_stage'] = stage
        spec['pre_deletion_failure'] = not bool(self.ops.journal(job).get('delete_intent'))
        self.status(job, 'attention', spec=json.dumps(spec), error='delete_first:'+reason)
        if not self.ops.journal(job).get('delete_intent'):
            self.ops.release(job)

    def advance(self, job):
        spec = json.loads(job['spec'])
        if not spec.get('delete_first') or job['status'] not in STAGES:
            return
        config = load_config(self.control.config_path)
        state = job['status']
        if config['mode'] == 'simulate' or spec['mode'] == 'simulate':
            if state == 'approved' and not self.ops.journal(job).get('delete_intent'):
                self.status(job, 'simulated', reserved=0)
            return
        try:
            # Reconcile a persisted intent even if the approval expired during a restart.
            if state == 'deleting' and self.ops.journal(job).get('delete_intent'):
                self.status(job, 'waiting_delete')
                return
            if state in ('approved', 'preparing', 'deleting'):
                self.gate(job, config, first_delete=True)
                self.exclusive(job)
            if state == 'approved':
                self.status(job, 'preparing')
            elif state == 'preparing':
                self.ops.prepare(job, config)
                if not self.status(job, 'deleting'):
                    self.ops.release(job)
            elif state == 'deleting':
                journal = self.ops.journal(job)
                if journal.get('delete_intent'):
                    self.status(job, 'waiting_delete')
                    return
                self.ops.before_delete(job, config)
                if spec.get('automatic'):
                    self.gate(job, load_config(self.control.config_path), first_delete=True)
                self.ops.save_journal(job, {**journal, 'delete_intent': timestamp()})
                try:
                    self.provider.delete(spec['old']['service_id'])
                finally:
                    # A lost DELETE reply is reconciled; never blindly delete again.
                    self.status(job, 'waiting_delete')
            elif state == 'waiting_delete':
                journal = self.ops.journal(job)
                if not journal.get('delete_intent'):
                    raise InfrastructureError('deletion_intent_missing')
                old = self.provider.server_or_none(spec['old']['service_id'])
                if old is not None and old.get('status') != 'deleted':
                    self.ops.validate_old(job, old)
                    if timestamp()-journal['delete_intent'] > config['delete_first']['deletion_timeout']:
                        raise InfrastructureError('deletion_not_confirmed')
                    return
                if any(row['id'] == spec['old']['service_id'] for row in self.provider.servers()):
                    return
                self.ops.save_journal(job, {**journal, 'deletion_confirmed': timestamp()})
                self.status(job, 'ordering_ready')
            elif state == 'ordering_ready':
                journal = self.ops.journal(job)
                if not journal.get('deletion_confirmed'):
                    raise InfrastructureError('deletion_not_confirmed')
                old = self.provider.server_or_none(spec['old']['service_id'])
                if old is not None and old.get('status') != 'deleted':
                    raise InfrastructureError('old_service_still_exists')
                found = self.provider.reconcile('asmove-'+job['id'])
                if found:
                    self.status(job, 'provisioning', service_id=found)
                    return
                if journal.get('order_intent'):
                    self.status(job, 'uncertain')
                    return
                self.exclusive(job)
                price = self.provider.quote(spec['candidate'])
                if Decimal(str(price)) != REQUIRED_DAILY_COST:
                    raise InfrastructureError('price_changed_after_deletion')
                if len(self.provider.servers()) + config.get('external_server_count', 0) >= config['max_servers']:
                    raise InfrastructureError('server_limit_reached')
                if not self.status(job, 'ordering'):
                    return
                current = self.job(job['id'])
                self.ops.save_journal(job, {**journal, 'order_intent': timestamp()})
                try:
                    service = self.provider.order('asmove-'+job['id'], spec['candidate'])
                except Exception as error:
                    from .vdsina import ProviderValidationError
                    if isinstance(error, ProviderValidationError):
                        self.ops.save_journal(job, {**journal, 'order_rejected': str(error)})
                        self.attention(current, 'ordering_ready', str(error))
                    else:
                        self.status(current, 'uncertain', error='provider_order_uncertain')
                    return
                self.status(current, 'provisioning', service_id=service)
            elif state in ('ordering', 'uncertain'):
                found = self.provider.reconcile('asmove-'+job['id'])
                if found:
                    self.status(job, 'provisioning', service_id=found, error='')
                elif timestamp()-job['updated'] > config['setup_timeout']:
                    raise InfrastructureError('order_result_unknown')
            elif state in ('provisioning', 'verifying', 'publishing'):
                if timestamp()-job['updated'] > config['setup_timeout']:
                    raise InfrastructureError('stage_timeout')
                service = self.provider.server(job['service_id'])
                if service.get('name') != 'asmove-'+job['id']:
                    raise InfrastructureError('provider_identity_mismatch')
                if service.get('status') != 'active':
                    return
                ip = self.provider.address(service)
                if ip == spec['old']['ip']:
                    raise InfrastructureError('provider_reused_old_ip')
                if job['ip'] and job['ip'] != ip:
                    raise InfrastructureError('provider_address_changed')
                if state == 'provisioning':
                    result = self.ops.provision(job, ip)
                    if result.get('ready'):
                        spec['vpn_port'] = result.get('port', spec['old']['port'])
                        self.status(job, 'verifying', ip=ip, spec=json.dumps(spec))
                elif state == 'verifying':
                    if self.ops.verify(job, ip):
                        self.status(job, 'publishing')
                elif self.ops.publish(job, ip).get('published'):
                    self.ops.finish(job, ip)
                    with self.control.write() as db:
                        db.execute('INSERT OR IGNORE INTO replacement_charges VALUES (?,?,?)', (job['id'], job['monthly'], spec['daily_rub']))
                        self.control.update(db, job['id'], 'ready', reserved=0, error='')
                    self.ops.release(job)
        except Exception as error:
            # Requests never print remote output or credentials into the public job.
            current = self.job(job['id'])
            if current and current['status'] in STAGES:
                reason = str(error) if isinstance(error, InfrastructureError) else type(error).__name__
                self.attention(current, current['status'], reason)
