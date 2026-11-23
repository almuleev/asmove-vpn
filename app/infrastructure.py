"""Persistent monitoring and administrator-approved VPN replacement jobs."""

import calendar
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal, ROUND_CEILING
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
from uuid import uuid4

from .access_term import MOSCOW
from .db import connect, transaction
from .vdsina import ProviderError, ProviderValidationError, Vdsina, REQUIRED_DAILY_COST


OPEN = ("pending", "approved", "preparing", "deleting", "waiting_delete", "ordering_ready",
        "ordering", "uncertain", "provisioning", "verifying", "publishing", "attention")
LABELS = {
    "pending": "Ждёт подтверждения", "approved": "Подтверждена", "ordering": "Заказ отправляется",
    "uncertain": "Проверяется результат заказа", "provisioning": "Настройка VPS",
    "verifying": "Проверка VPN", "publishing": "Обновление подписок", "ready": "Замена готова",
    "attention": "Требуется проверка администратора", "simulated": "Имитация завершена",
    "cancelled": "Отменена", "expired": "Подтверждение просрочено", "recovered": "Узел восстановился",
    "preparing": "Проверка резервной копии", "deleting": "Удаление старого VPS",
    "waiting_delete": "Ожидание завершения удаления", "ordering_ready": "Подготовка нового заказа",
}


class InfrastructureError(Exception):
    pass


def timestamp():
    return int(time.time())


def money(value):
    return f"{value / 100:.2f} ₽"


def operation_error(code):
    return {
        'provider_tariff_limit': 'Провайдер отклонил создание дополнительного сервера. Новый сервер не создан.',
        'server_limit_reached': 'Достигнут лимит количества VPS. Новый сервер не создан.',
        'provider_unavailable': 'API провайдера недоступен. Повторите проверку позже.',
        'backup_too_old': 'Требуется актуальная резервная копия. Повторите проверку готовности.',
        'backup_too_old_or_changed': 'Резервная копия требует повторной проверки.',
        'old_service_identity_mismatch': 'Данные действующего сервера изменились. Повторите проверку готовности.',
    }.get(code, 'Операция не завершена. Проверьте настройки в панели провайдера и повторите проверку.')


def command(value):
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ValueError("Expected a command argument array")
    if not Path(value[0]).is_absolute():
        raise ValueError("Command executable must have an absolute path")
    return value


def load_config(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("api_host", "userapi.vdsina.com") != "userapi.vdsina.com":
        raise ValueError("Only the VDSina.com USD API is supported")
    if data.get("mode") not in {"simulate", "live"}:
        raise ValueError("Expected simulate or live mode")
    # Legacy spending caps and the support receipt are no longer authorization gates.
    for key in ('monthly_limit', 'max_orders', 'reserve_monthly', 'ordering_blocked_reason'):
        data.pop(key, None)
    defaults = dict(baseline_daily=0, fixed_monthly=0,
                    max_servers=3, allow_overlap=False, approval_ttl=900,
                    failures=3, required_ru_probes=2, probe_max_age=120, setup_timeout=1200)
    data = {**defaults, **data}
    recovery = {"enabled": False, "auto_propose": False, "daily_cost": "0.07", "backup_max_age": 900,
                "backup_interval": 300, "deletion_timeout": 900, **data.get("delete_first", {})}
    for key in ('provider_reorder_confirmed', 'confirmation_reference', 'max_daily_cost'):
        recovery.pop(key, None)
    if (any(type(recovery[key]) is not bool for key in ("enabled", "auto_propose"))
            or any(type(recovery[key]) is not int or not 60 <= recovery[key] <= 86400
                   for key in ("backup_max_age", "backup_interval", "deletion_timeout"))
            or Decimal(str(recovery["daily_cost"])) != REQUIRED_DAILY_COST):
        raise ValueError("Invalid delete-first replacement policy")
    data["delete_first"] = recovery
    for key in defaults.keys() - {"allow_overlap"}:
        if type(data[key]) is not int or data[key] < 0:
            raise ValueError("Invalid infrastructure integer: " + key)
    if (not 1 <= data["approval_ttl"] <= 3600 or not 1 <= data["failures"] <= 20
            or not 1 <= data["required_ru_probes"] <= 10 or data["max_servers"] < 1
            or not 10 <= data["probe_max_age"] <= 300 or not 60 <= data["setup_timeout"] <= 3600
            or type(data["allow_overlap"]) is not bool):
        raise ValueError("Invalid infrastructure policy")
    if data.get("currency") not in {"RUB", "USD"}:
        raise ValueError("Set provider account currency")
    rate = Decimal(str(data["rub_per_unit"]))
    if not rate.is_finite() or rate <= 0 or (data["currency"] == "RUB" and rate != 1):
        raise ValueError("Invalid currency rate")
    if type(data.get("rate_valid_until")) is not int:
        raise ValueError("Set the currency rate expiry")
    identities = set()
    for node in data["nodes"]:
        if node["id"] in identities or not str(node["id"]).isascii() or not node["id"].isalnum():
            raise ValueError("Node IDs must be unique ASCII letters and numbers")
        identities.add(node["id"])
        if not ipaddress.ip_address(node["ip"]).is_global or not 1 <= node["port"] <= 65535:
            raise ValueError("Invalid public node address")
        if type(node["service_id"]) is not int or node["service_id"] <= 0:
            raise ValueError("Invalid server ID")
    if not identities:
        raise ValueError("Configure at least one node")
    probes = data.get("probes", [])
    if (len({probe["id"] for probe in probes}) != len(probes)
            or len({probe["network"] for probe in probes}) != len(probes)):
        raise ValueError("Probe IDs and observer networks must be unique")
    for probe in probes:
        if probe.get("region") not in {"ru", "foreign"} or not probe["network"]:
            raise ValueError("Set the observer region and network")
        command(probe["command"])
    additions = data.get("additions", [])
    if len(additions) > 1 or any(not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", row.get("id", "")) or row["id"] in identities for row in additions):
        raise ValueError("Invalid additional VPN node")
    for candidate in data["candidates"]:
        for key in ("plan_id", "group_id", "datacenter_id", "template_id", "ssh_key_id"):
            if type(candidate[key]) is not int or candidate[key] <= 0:
                raise ValueError("Invalid candidate ID")
        if not candidate["country"] or candidate["country"] == "ru":
            raise ValueError("VPN candidate must be abroad")
        price = Decimal(str(candidate["daily_cost"]))
        if not price.is_finite() or price != REQUIRED_DAILY_COST or data['currency'] != 'USD':
            raise ValueError("VPN candidates must cost exactly USD 0.07 per day")
    for key in ("provision_command", "verify_command", "publish_command"):
        if data.get(key):
            command(data[key])
    if type(data.get("external_server_count", 0)) is not int or data.get("external_server_count", 0) < 0:
        raise ValueError("Invalid external server count")
    policy = {key: value for key, value in data.items() if key not in {
        "rate_valid_until", "rate_checked_at", "rate_source_date", "rub_per_unit", "baseline_daily", "fixed_monthly", "rate_policy"}}
    data["fingerprint"] = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
    return data


SCHEMA = """
CREATE TABLE IF NOT EXISTS automation_policy (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS automation_observations (node TEXT PRIMARY KEY, since_at INTEGER NOT NULL, last_at INTEGER NOT NULL, failures INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
    observed_at INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'unknown', evidence TEXT NOT NULL DEFAULT '{}',
    incident TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, node TEXT NOT NULL, status TEXT NOT NULL,
    created INTEGER NOT NULL, expires INTEGER NOT NULL, updated INTEGER NOT NULL, spec TEXT NOT NULL,
    monthly TEXT NOT NULL, charge INTEGER NOT NULL, error TEXT NOT NULL DEFAULT '',
    service_id INTEGER, ip TEXT, reserved INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS one_open_replacement ON jobs(node)
WHERE status IN ('pending','approved','preparing','deleting','waiting_delete','ordering_ready','ordering','uncertain','provisioning','verifying','publishing','attention');
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, happened_at INTEGER NOT NULL,
    action TEXT NOT NULL, job TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, message TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS overrides (node TEXT PRIMARY KEY, spec TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS manual_requests (node TEXT PRIMARY KEY, request_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS replacement_checks (node TEXT PRIMARY KEY, request_id TEXT NOT NULL,
    requested INTEGER NOT NULL, finished INTEGER NOT NULL DEFAULT 0, result TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS replacement_charges (job TEXT PRIMARY KEY, monthly TEXT NOT NULL, amount INTEGER NOT NULL);
"""


class Infrastructure:
    def __init__(self, directory, config_path):
        self.directory = Path(directory)
        self.path = self.directory / "infrastructure.sqlite3"
        self.config_path = Path(config_path)

    def initialize(self):
        with connect(self.path, "rwc") as db, db:
            db.executescript(SCHEMA)
            index = db.execute("SELECT sql FROM sqlite_master WHERE name='one_open_replacement'").fetchone()
            if index and "waiting_delete" not in index[0]:
                db.execute("DROP INDEX one_open_replacement")
                db.execute("CREATE UNIQUE INDEX one_open_replacement ON jobs(node) WHERE status IN ("
                           + ",".join("'" + status + "'" for status in OPEN) + ")")
        self.path.chmod(0o600)

    @contextmanager
    def write(self):
        with connect(self.path) as db, transaction(db):
            yield db

    def update(self, db, job_id, status, **fields):
        updates = {"status": status, "updated": timestamp(), **fields}
        db.execute("UPDATE jobs SET " + ",".join(key + "=?" for key in updates) + " WHERE id=?",
                   [*updates.values(), job_id])
        db.execute("INSERT INTO audit(happened_at,action,job) VALUES (?,?,?)", (timestamp(), status, job_id))
        job = db.execute("SELECT node,spec,charge FROM jobs WHERE id=?", (job_id,)).fetchone()
        spec = json.loads(job["spec"])
        candidate = spec["candidate"]
        message = (f"ASMove VPN — {LABELS[status]}\nУзел {job['node']}\nЗаявка {job_id}\n"
                   f"Замена — {candidate['country'].upper()}, площадка {candidate['datacenter_id']}\n"
                   f"Тариф {candidate['daily_cost']} USD/сутки")
        if spec.get("delete_first"):
            message += f"\nЗамена с простоем. Старый VPS: {spec['old']['ip']} / №{spec['old']['service_id']}."
        db.execute("INSERT OR IGNORE INTO notifications(id,message) VALUES (?,?)", (job_id + ":" + status, message))

    def overview(self):
        config = load_config(self.config_path)
        if not self.path.exists():
            return config, [], [], []
        with connect(self.path) as db:
            nodes = [dict(row) for row in db.execute("SELECT * FROM nodes ORDER BY id")]
            jobs = [dict(row) for row in db.execute("SELECT * FROM jobs ORDER BY created DESC,rowid DESC LIMIT 30")]
            audit = [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 30")]
        for job in jobs:
            job["spec"] = json.loads(job["spec"])
        return config, nodes, jobs, audit

    def decide(self, job_id, action, acknowledgement=None):
        config = load_config(self.config_path)
        with self.write() as db:
            job = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                raise InfrastructureError("Заявка не найдена.")
            if action == "cancel" and (job["status"] in ("pending", "approved", "preparing") or
                    (job["status"] == "attention" and json.loads(job["spec"]).get("pre_deletion_failure"))):
                self.update(db, job_id, "cancelled", reserved=0)
                return
            if action == "resume" and job["status"] == "attention":
                spec = json.loads(job["spec"])
                if spec.get("delete_first"):
                    from .delete_first import STAGES
                    stage = spec.get("resume_stage", "uncertain")
                    if stage not in STAGES:
                        raise InfrastructureError("Некорректный этап продолжения заявки.")
                    self.update(db, job_id, stage, error="")
                    return
                # Recover the same service/order. This never authorizes another POST /server.
                status = job["error"].removeprefix("replacement_step_failed:")
                if status not in ("provisioning", "verifying", "publishing"):
                    status = "uncertain"
                self.update(db, job_id, status, error="")
                return
            if job["status"] != "pending":
                return
            if action != "approve":
                raise InfrastructureError("Неизвестное действие.")
            if job["expires"] <= timestamp():
                self.update(db, job_id, "expired")
                return
            spec = json.loads(job["spec"])
            if spec.get("delete_first"):
                from .delete_first import validate_approval
                validate_approval(config, spec, acknowledgement)
                spec["approved_at"] = timestamp()
                spec["approved_ip"] = acknowledgement["ip"]
                spec["accepted_downtime"] = True
            if spec["fingerprint"] != config["fingerprint"]:
                raise InfrastructureError("Настройки изменились. Дождитесь новой заявки.")
            node = db.execute("SELECT * FROM nodes WHERE id=?", (job["node"],)).fetchone()
            if (not spec.get("addition") and not spec.get("manual") and
                    (not node or node["state"] != "failed" or timestamp() - node["observed_at"] > config["probe_max_age"])):
                raise InfrastructureError("Нужна свежая проверка неисправного узла.")
            if config["mode"] == "live":
                self.check_replacement_slot(db, excluding=job_id)
            self.update(db, job_id, "approved", reserved=1, spec=json.dumps(spec))

    def request_replacement(self, node_id):
        config = load_config(self.config_path)
        if config['delete_first']['enabled']:
            from .delete_first import DeleteFirstControl
            return DeleteFirstControl(self).prepare(node_id)
        if node_id not in {node["id"] for node in config["nodes"]}:
            raise InfrastructureError("Узел не найден.")
        if not config["candidates"]:
            raise InfrastructureError("Сначала настройте параметры создания нового сервера.")
        self.initialize()
        with self.write() as db:
            db.execute("INSERT OR IGNORE INTO manual_requests VALUES (?,?)", (node_id, uuid4().hex))

    def request_addition(self, node_id):
        config = load_config(self.config_path)
        if node_id not in {row["id"] for row in config.get("additions", [])}:
            raise InfrastructureError("Дополнительный узел не настроен.")
        self.initialize()
        with self.write() as db:
            db.execute("INSERT OR IGNORE INTO manual_requests VALUES (?,?)", (node_id, uuid4().hex))

    @staticmethod
    def month():
        local = datetime.fromtimestamp(timestamp(), MOSCOW)
        return local.strftime("%Y-%m"), calendar.monthrange(local.year, local.month)[1]

    def check_replacement_slot(self, db, *, excluding=""):
        """Serialize unfinished changes; spending totals never authorize or block them."""
        if db.execute("SELECT 1 FROM jobs WHERE reserved=1 AND status IN ('approved','preparing','deleting','waiting_delete','ordering_ready','ordering','uncertain',"
                      "'provisioning','verifying','publishing','attention') AND id!=?", (excluding,)).fetchone():
            raise InfrastructureError("Сначала завершите текущую замену.")

    def observe(self, node_id, evidence, config):
        # A missing observer never counts as proof that a VPN endpoint is blocked.
        valid = [item for item in evidence["probes"] if item["region"] == "ru" and item["observer_ok"]]
        failed = len(valid) >= config["required_ru_probes"] and all(not item["vpn_ok"] for item in valid)
        healthy = any(item["vpn_ok"] for item in valid)
        with self.write() as db:
            db.execute("INSERT OR IGNORE INTO nodes(id) VALUES (?)", (node_id,))
            previous = db.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
            consecutive = previous["failures"] if timestamp() - previous["observed_at"] <= config["probe_max_age"] else 0
            count = consecutive + 1 if failed else 0
            incident = previous["incident"] if count > 1 else uuid4().hex if count == 1 else ""
            state = "failed" if count >= config["failures"] else "healthy" if healthy else "suspect" if failed else "unknown"
            db.execute("UPDATE nodes SET failures=?,observed_at=?,state=?,evidence=?,incident=? WHERE id=?",
                       (count, timestamp(), state, json.dumps(evidence), incident, node_id))
            if state == "healthy":
                for job in db.execute("SELECT id FROM jobs WHERE node=? AND status IN ('pending','approved') "
                                      "AND COALESCE(json_extract(spec,'$.manual'),0)=0", (node_id,)).fetchall():
                    self.update(db, job["id"], "recovered", reserved=0)
            from .automation import record
            record(db, node_id, evidence, config, timestamp())
            return state


def execute(argv, payload, timeout=45):
    """Hooks receive JSON on stdin and return a small JSON object. Never run a shell."""
    result = subprocess.run(command(argv), input=json.dumps(payload), capture_output=True,
                            text=True, timeout=timeout, check=False)
    if result.returncode or len(result.stdout) > 65536:
        raise InfrastructureError("hook_failed")
    data = json.loads(result.stdout)
    if not isinstance(data, dict):
        raise InfrastructureError("hook_response_invalid")
    return data


class Worker:
    def __init__(self, infrastructure, provider=None):
        self.store = infrastructure
        self.config = load_config(infrastructure.config_path)
        self.provider = provider or Vdsina(self.config.get("api_host", "userapi.vdsina.com"))

    def rubles(self, price):
        return int((Decimal(str(price)) * Decimal(str(self.config["rub_per_unit"])) * 100).to_integral_value(rounding=ROUND_CEILING))

    def probe(self, node):
        tcp = False
        try:
            with socket.create_connection((node["ip"], node["port"]), timeout=3):
                tcp = True
        except OSError:
            pass
        evidence = {"tcp": tcp, "probes": []}
        for probe in self.config.get("probes", []):
            result = {"observer_ok": False, "vpn_ok": False}
            try:
                reply = execute(probe["command"], {"node": node}, timeout=45)
                if type(reply.get("observer_ok")) is bool and type(reply.get("vpn_ok")) is bool:
                    result = {key: reply[key] for key in result}
                    total = reply.get("targets_total", 0)
                    if type(total) is int and 0 <= total <= 3:
                        result["targets_total"] = total
            except (OSError, ValueError, subprocess.TimeoutExpired, InfrastructureError):
                pass
            evidence["probes"].append({"id": probe["id"], "region": probe["region"], **result})
        return evidence

    def propose(self, node, manual=None, *, addition=False):
        config = self.config
        with connect(self.store.path) as db:
            if db.execute("SELECT 1 FROM jobs WHERE node=? AND status IN (" + ",".join("?" for _ in OPEN) + ")",
                          (node["id"], *OPEN)).fetchone():
                return True
        other_countries = {row["country"] for row in config["nodes"] if row["id"] != node["id"]}
        other_datacenters = {row["datacenter_id"] for row in config["nodes"] if row["id"] != node["id"]}
        candidates = sorted(config["candidates"], key=lambda row: (row["country"] in other_countries,
                                                                  row["datacenter_id"] in other_datacenters))
        candidate = next((row for row in candidates if row["datacenter_id"] != node["datacenter_id"]), None)
        if candidate is None:
            return False
        price = candidate["daily_cost"] if config["mode"] == "simulate" else self.provider.quote(candidate)
        if Decimal(str(price)) != REQUIRED_DAILY_COST:
            raise InfrastructureError("Параметры создания сервера изменились. Обновите настройки.")
        month, days = self.store.month()
        charge = 0
        spec = {"fingerprint": config["fingerprint"], "candidate": candidate, "mode": config["mode"],
                "daily_rub": self.rubles(price), "old": node, "overlap": config["allow_overlap"]}
        if manual:
            spec["manual"] = True
        if addition:
            spec["addition"] = True
        now = timestamp()
        with self.store.write() as db:
            incident = manual or db.execute("SELECT incident FROM nodes WHERE id=?", (node["id"],)).fetchone()[0]
            spec["incident"] = incident
            if db.execute("SELECT 1 FROM jobs WHERE node=? AND json_extract(spec,'$.incident')=? "
                          "AND status IN ('cancelled','simulated')", (node["id"], incident)).fetchone():
                return True
            if db.execute("SELECT 1 FROM jobs WHERE node=? AND status IN (" + ",".join("?" for _ in OPEN) + ")",
                          (node["id"], *OPEN)).fetchone():
                return True
            job_id = uuid4().hex
            db.execute("INSERT INTO jobs(id,node,status,created,expires,updated,spec,monthly,charge) VALUES (?,?,?,?,?,?,?,?,?)",
                       (job_id, node["id"], "pending", now, now + config["approval_ttl"], now, json.dumps(spec), month, charge))
            self.store.update(db, job_id, "pending")
            return True

    def status(self, job_id, status, **fields):
        with self.store.write() as db:
            self.store.update(db, job_id, status, **fields)

    def advance(self, job):
        config = self.config
        spec = json.loads(job["spec"])
        if spec.get("delete_first"):
            return  # Privileged independent runner owns destructive jobs.
        job_id = job["id"]
        payload = {"job_id": job_id, "node": spec["old"], "candidate": spec["candidate"],
                   "service_id": job["service_id"], "ip": job["ip"]}
        if job["status"] == "approved":
            if job["expires"] <= timestamp():
                self.status(job_id, "expired", reserved=0)
                return
            if config["fingerprint"] != spec["fingerprint"]:
                self.status(job_id, "cancelled", reserved=0, error="configuration_changed")
                return
            with connect(self.store.path) as db:
                observed = db.execute("SELECT * FROM nodes WHERE id=?", (job["node"],)).fetchone()
                if (not spec.get("addition") and not spec.get("manual") and
                        (not observed or observed["state"] != "failed" or timestamp() - observed["observed_at"] > config["probe_max_age"])):
                    raise InfrastructureError("fresh_failed_probe_required")
                if config["mode"] == "live":
                    self.store.check_replacement_slot(db, excluding=job_id)
            if config["mode"] == "simulate":
                self.status(job_id, "simulated", reserved=0)
                return
            if any(not config.get(key) for key in ("provision_command", "verify_command", "publish_command")):
                raise InfrastructureError("deployment_commands_missing")
            price = self.provider.quote(spec["candidate"])
            if Decimal(str(price)) != REQUIRED_DAILY_COST:
                raise InfrastructureError("price_changed")
            count = len(self.provider.servers()) + config.get("external_server_count", 0)
            ceiling = config["max_servers"] + int(config["allow_overlap"])
            if count >= ceiling:
                raise InfrastructureError("server_limit_reached")
            # Commit before the non-idempotent POST. A crash resumes by reconciliation only.
            with self.store.write() as db:
                current = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
                observed = db.execute("SELECT * FROM nodes WHERE id=?", (job["node"],)).fetchone()
                if current["status"] != "approved":
                    return
                if current["expires"] <= timestamp():
                    self.store.update(db, job_id, "expired", reserved=0)
                    return
                if (not spec.get("addition") and not spec.get("manual") and
                        (not observed or observed["state"] != "failed" or timestamp() - observed["observed_at"] > config["probe_max_age"])):
                    raise InfrastructureError("fresh_failed_probe_required")
                self.store.check_replacement_slot(db, excluding=job_id)
                self.store.update(db, job_id, "ordering")
            server_id = self.provider.order("asmove-" + job_id, spec["candidate"])
            self.status(job_id, "provisioning", service_id=server_id)
            return
        if job["status"] in ("ordering", "uncertain"):
            server_id = self.provider.reconcile("asmove-" + job_id)
            if server_id:
                self.status(job_id, "provisioning", service_id=server_id, error="")
            elif timestamp() - job["updated"] > config["setup_timeout"]:
                self.status(job_id, "attention", error="order_result_unknown")
            else:
                # Do not change updated here: it is the start of the reconciliation window.
                with self.store.write() as db:
                    db.execute("UPDATE jobs SET status='uncertain' WHERE id=?", (job_id,))
            return
        if timestamp() - job["updated"] > config["setup_timeout"]:
            self.status(job_id, "attention", error="stage_timeout")
            return
        if job["status"] == "provisioning":
            server = self.provider.server(job["service_id"])
            if server.get("name") != "asmove-" + job_id:
                raise InfrastructureError("provider_identity_mismatch")
            if server.get("status") != "active":
                return
            address = self.provider.address(server)
            payload["ip"] = address
            result = execute(config["provision_command"], payload, timeout=90)
            if result.get("ready") is True:
                port = result.get("port", spec["old"]["port"])
                if type(port) is not int or not 1 <= port <= 65535:
                    raise InfrastructureError("invalid_provisioned_port")
                spec["vpn_port"] = port
                self.status(job_id, "verifying", ip=address, spec=json.dumps(spec))
        elif job["status"] == "verifying":
            candidate_node = {**spec["old"], "ip": job["ip"], "service_id": job["service_id"],
                              "port": spec.get("vpn_port", spec["old"]["port"])}
            evidence = self.probe(candidate_node)
            probes = [probe for probe in evidence["probes"] if probe["region"] == "ru" and probe["observer_ok"] and probe["vpn_ok"]]
            if len(probes) < config["required_ru_probes"]:
                return
            result = execute(config["verify_command"], payload, timeout=45)
            if result.get("ready") is True:
                self.status(job_id, "publishing")
        elif job["status"] == "publishing":
            result = execute(config["publish_command"], payload, timeout=45)
            if result.get("pending") is True:
                return
            if result.get("published") is not True:
                raise InfrastructureError("publication_not_confirmed")
            with self.store.write() as db:
                replacement = {**spec["old"], "service_id": job["service_id"], "ip": job["ip"],
                               "port": spec.get("vpn_port", spec["old"]["port"]),
                               "datacenter_id": spec["candidate"]["datacenter_id"], "country": spec["candidate"]["country"]}
                db.execute("INSERT OR REPLACE INTO overrides VALUES (?,?)", (job["node"], json.dumps(replacement)))
                db.execute("UPDATE nodes SET failures=0,observed_at=0,state='unknown',incident='' WHERE id=?", (job["node"],))
                # An addition is included in baseline_daily by the publisher.
                self.store.update(db, job_id, "ready", **({"reserved": 0} if spec.get("addition") else {}))

    def tick(self):
        self.store.initialize()
        # One runner owns the lock across network calls. Process exit releases the lock.
        with (self.store.directory / "infrastructure.lock").open("a+b") as lock:
            if os.name == "nt":
                import msvcrt
                lock.write(b"0")
                lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.config = load_config(self.store.config_path)
            self.run()

    def run(self):
        config = self.config
        with self.store.write() as db:
            for job in db.execute("SELECT id FROM jobs WHERE status='pending' AND expires<=?", (timestamp(),)).fetchall():
                self.store.update(db, job["id"], "expired")
            for job in db.execute("SELECT id FROM jobs WHERE status='pending' AND json_extract(spec,'$.fingerprint')!=?",
                                  (config["fingerprint"],)).fetchall():
                self.store.update(db, job["id"], "cancelled")
            overrides = {row["node"]: json.loads(row["spec"]) for row in db.execute("SELECT * FROM overrides")}
        for configured in config["nodes"]:
            node = {**configured, **overrides.get(configured["id"], {})}
            state = self.store.observe(node["id"], self.probe(node), config)
            with connect(self.store.path) as db:
                requested = db.execute("SELECT request_id FROM manual_requests WHERE node=?", (node["id"],)).fetchone()
            if state == "failed" or requested:
                try:
                    if config["delete_first"]["enabled"] and config["delete_first"]["auto_propose"] and not requested:
                        from .delete_first import DeleteFirstControl
                        DeleteFirstControl(self.store).prepare(node["id"], manual=False)
                        accepted = True
                    else:
                        accepted = self.propose(node, requested["request_id"] if requested else None)
                    if accepted and requested:
                        with self.store.write() as db:
                            db.execute("DELETE FROM manual_requests WHERE node=? AND request_id=?", (node["id"], requested["request_id"]))
                except (ProviderError, InfrastructureError):
                    # Preserve the incident even while the provider API is unavailable.
                    with self.store.write() as db:
                        db.execute("INSERT OR IGNORE INTO notifications(id,message) VALUES (?,?)",
                                   (node["id"] + ":offer_unavailable", "ASMove VPN — нет доступного тарифа для " + node["id"]))
        for addition in config.get("additions", []):
            with connect(self.store.path) as db:
                requested = db.execute("SELECT request_id FROM manual_requests WHERE node=?", (addition["id"],)).fetchone()
            if requested:
                node = {"id": addition["id"], "ip": "1.1.1.1", "port": 443, "service_id": 0,
                        "datacenter_id": 0, "country": ""}
                try:
                    if self.propose(node, requested["request_id"], addition=True):
                        with self.store.write() as db:
                            db.execute("DELETE FROM manual_requests WHERE node=? AND request_id=?", (node["id"], requested["request_id"]))
                except (ProviderError, InfrastructureError):
                    with self.store.write() as db:
                        db.execute("INSERT OR IGNORE INTO notifications(id,message) VALUES (?,?)",
                                   (node["id"] + ":offer_unavailable", "ASMove VPN — не удалось получить предложение для " + node["id"]))
        with connect(self.store.path) as db:
            jobs = [dict(row) for row in db.execute("SELECT * FROM jobs WHERE status IN "
                                                   "('approved','ordering','uncertain','provisioning','verifying','publishing')")]
        for job in jobs:
            try:
                self.advance(job)
            except (ProviderError, InfrastructureError, OSError, ValueError, subprocess.TimeoutExpired) as error:
                with connect(self.store.path) as db:
                    current = db.execute("SELECT status FROM jobs WHERE id=?", (job["id"],)).fetchone()[0]
                if current == "approved" or (current == "ordering" and isinstance(error, ProviderValidationError)):
                    # No POST has started. Release the reservation so the administrator
                    # can request a fresh offer after correcting budget or inventory.
                    reason = str(error) if isinstance(error, (ProviderError, InfrastructureError)) else "preflight_failed"
                    self.status(job["id"], "cancelled", reserved=0, error=reason)
                elif current in ("ordering", "uncertain"):
                    # Preserve the start time and the reservation after a lost order response.
                    with self.store.write() as db:
                        db.execute("UPDATE jobs SET status='uncertain',error='provider_order_uncertain' WHERE id=?", (job["id"],))
                else:
                    self.status(job["id"], "attention", error="replacement_step_failed:" + current)

    def notify(self, telegram, admin_origin):
        from .reminders import ReminderError

        with connect(self.store.path) as db:
            pending = db.execute("SELECT * FROM notifications WHERE sent=0 LIMIT 10").fetchall()
        for notification in pending:
            try:
                telegram.send(notification["message"] + "\n" + admin_origin + "/admin/infrastructure")
            except ReminderError:
                # Keep the outbox for the next tick without stopping monitoring or replacement reconciliation.
                return
            with self.store.write() as db:
                db.execute("UPDATE notifications SET sent=1 WHERE id=?", (notification["id"],))


def register_routes(app, settings, auth, page, read_form, require_csrf):
    from fastapi import HTTPException, Request
    from fastapi.concurrency import run_in_threadpool
    from fastapi.responses import RedirectResponse
    from .auth import SESSION_COOKIE

    def authorize(request):
        session = request.cookies.get(SESSION_COOKIE, "")
        kind, _ = auth.get_session(session)
        if kind != "admin":
            raise HTTPException(403)
        if settings.role != "primary" or not settings.infrastructure_config:
            raise HTTPException(404)
        return session

    @app.get("/admin/infrastructure")
    def overview(request: Request):
        session = authorize(request)
        infrastructure = Infrastructure(settings.data_dir, settings.infrastructure_config)
        try:
            infrastructure.initialize()
            config, nodes, jobs, audit = infrastructure.overview()
        except (OSError, ValueError, KeyError, sqlite3.Error):
            return page(request, "error.html", 503, message="Проверьте настройки управления серверами.")
        checks = {}
        from . import ntfy
        ntfy_state = ntfy.state(settings)
        ntfy_url = None
        connection_file = settings.data_dir / 'ntfy-connection.json'
        if ntfy_state and connection_file.exists():
            ntfy_url = json.loads(connection_file.read_text()).get('url')
        queued_notifications = 0
        report_queue = settings.data_dir / "problem-reports.sqlite3"
        if report_queue.exists():
            with connect(report_queue, "ro") as db:
                queued_notifications += db.execute('SELECT count(*) FROM reports WHERE sent=0').fetchone()[0]
        if infrastructure.path.exists():
            with connect(infrastructure.path) as db:
                queued_notifications += db.execute('SELECT count(*) FROM notifications WHERE sent=0').fetchone()[0]
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='replacement_checks'").fetchone():
                    checks = {row["node"]: {**dict(row), "result": json.loads(row["result"])}
                              for row in db.execute("SELECT * FROM replacement_checks")}
        from .automation import read as read_automation
        with connect(infrastructure.path) as db:
            automation_policy = read_automation(db)
        current = timestamp()
        configured = {node['id']: node for node in config['nodes']}
        for node in nodes:
            node.update(ip=configured.get(node['id'], {}).get('ip'),port=configured.get(node['id'], {}).get('port'))
            if current-node['observed_at'] > config['probe_max_age']:
                node['state'] = 'unknown'
        return page(request, "infrastructure.html", automation=automation_policy, config=config, nodes=nodes, jobs=jobs, audit=audit, replacement_checks=checks,
                    queued_notifications=queued_notifications,
                    ntfy_state=ntfy_state, ntfy_url=ntfy_url,
                    labels=LABELS, operation_error=operation_error, csrf=auth.sign("session", session))

    def decision(request, job_id, action, form):
        session = authorize(request)
        require_csrf(request, form, "session", session)
        try:
            control = Infrastructure(settings.data_dir, settings.infrastructure_config)
            if action == "automation":
                from .automation import save
                try:
                    policy = {"enabled": form.get("enabled") == "yes", "trigger": form.get("trigger", "vpn_failed")}
                    for key in ("failures", "failure_seconds", "cooldown_seconds", "max_per_day"):
                        policy[key] = int(form.get(key, ""))
                    save(control, policy, accept_downtime=form.get("accept_automatic_downtime") == "yes")
                except ValueError:
                    raise InfrastructureError("Проверьте пороги и подтвердите автоматическое удаление и простой.") from None
            elif action == "request":
                control.request_replacement(job_id)
            elif action == "add":
                control.request_addition(job_id)
            elif action in {"delete-first", "check-delete-first"}:
                from .delete_first import DeleteFirstControl
                replacement = DeleteFirstControl(control)
                if action == "delete-first": replacement.prepare(job_id)
                else: replacement.request_check(job_id)
            else:
                control.decide(job_id, action, {"ip": form.get("delete_ip"), "downtime": form.get("accept_downtime")})
        except InfrastructureError as error:
            return page(request, "error.html", 409, message=str(error))
        except (OSError, ValueError, KeyError, sqlite3.Error):
            return page(request, "error.html", 503, message="Не удалось сохранить решение.")
        return RedirectResponse("/admin/infrastructure", 303)

    @app.post("/admin/infrastructure/{job_id}/{action}")
    async def decide(request: Request, job_id: str, action: str):
        return await run_in_threadpool(decision, request, job_id, action, await read_form(request))
