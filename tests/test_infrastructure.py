from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.auth import HASHER
from app.db import Store, connect
from app.infrastructure import Infrastructure, InfrastructureError, Worker, load_config, timestamp
from app.main import create_app
from app.settings import Settings
from app.reminders import ReminderError
from app.vdsina import ProviderError, ProviderValidationError, Vdsina


class InfrastructureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config_path = self.root / "infrastructure.json"
        self.config = {
            "mode": "live", "currency": "USD", "rub_per_unit": "100", "rate_valid_until": timestamp() + 3600,
            "baseline_daily": 1000, "allow_overlap": True, "external_server_count": 1,
            "nodes": [{"id": "EU1", "ip": "1.1.1.1", "port": 443, "service_id": 12,
                       "datacenter_id": 1, "country": "nl"}],
            "candidates": [{"plan_id": 1, "group_id": 1, "template_id": 1, "ssh_key_id": 1,
                            "datacenter_id": 2, "country": "de", "daily_cost": "0.07"}],
            "probes": [
                {"id": "ru1", "region": "ru", "network": "AS-one", "command": [str(self.root / "probe1")]},
                {"id": "ru2", "region": "ru", "network": "AS-two", "command": [str(self.root / "probe2")]},
            ],
            "provision_command": [str(self.root / "provision")],
            "verify_command": [str(self.root / "verify")],
            "publish_command": [str(self.root / "publish")],
        }
        self.save_config()
        self.store = Infrastructure(self.root, self.config_path)
        self.store.initialize()
        self.provider = Mock()
        self.provider.quote.return_value = "0.07"
        self.provider.servers.return_value = [{"id": 12}, {"id": 13}]
        self.provider.order.return_value = 20
        self.worker = Worker(self.store, self.provider)
        self.evidence = {"tcp": True, "probes": [
            {"id": "ru1", "region": "ru", "observer_ok": True, "vpn_ok": False},
            {"id": "ru2", "region": "ru", "observer_ok": True, "vpn_ok": False},
        ]}

    def save_config(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")

    def test_second_node_requires_approval_and_uses_a_different_datacenter(self):
        self.config["additions"] = [{"id": "EU2"}]
        self.save_config()
        self.worker = Worker(self.store, self.provider)
        self.store.request_addition("EU2")
        healthy = {"tcp": True, "probes": [{"id": "ru1", "region": "ru", "observer_ok": True, "vpn_ok": True}]}
        with patch.object(self.worker, "probe", return_value=healthy):
            self.worker.run()
        job = self.job()
        self.assertEqual(job["status"], "pending")
        self.assertTrue(job["spec"]["addition"])
        self.assertNotEqual(job["spec"]["candidate"]["datacenter_id"], self.config["nodes"][0]["datacenter_id"])
        self.provider.order.assert_not_called()
        self.store.decide(job["id"], "approve")
        self.worker.advance(self.raw_job())
        self.provider.order.assert_called_once()
        self.assertEqual(self.job()["status"], "provisioning")
        self.worker.status(job["id"], "ready", reserved=0)
        with connect(self.store.path) as db:
            self.store.check_replacement_slot(db)

    def test_rate_refresh_keeps_approval_only_when_the_price_policy_is_unchanged(self):
        before = load_config(self.config_path)["fingerprint"]
        self.config["rate_valid_until"] += 86400
        self.config["rate_source_date"] = "20.11.2026"
        self.config["rate_checked_at"] = timestamp()
        self.save_config()
        self.assertEqual(load_config(self.config_path)["fingerprint"], before)
        self.config["rub_per_unit"] = "101"
        self.save_config()
        self.assertEqual(load_config(self.config_path)["fingerprint"], before)

    def job(self):
        return self.store.overview()[2][0]

    def incident(self):
        with patch.object(self.worker, "probe", return_value=self.evidence):
            for _ in range(3):
                self.worker.run()
        return self.job()["id"]

    def raw_job(self):
        with connect(self.store.path) as db:
            return dict(db.execute("SELECT * FROM jobs ORDER BY created DESC,rowid DESC LIMIT 1").fetchone())

    def test_monitor_requires_real_vpn_failures_and_distinct_healthy_observers(self):
        node = self.config["nodes"][0]
        with patch.object(self.worker, "probe", return_value={"tcp": False, "probes": []}):
            for _ in range(5):
                self.worker.run()
        self.assertEqual(self.store.overview()[2], [])
        job_id = self.incident()
        self.assertEqual(self.job()["status"], "pending")
        self.provider.order.assert_not_called()
        self.assertEqual(self.store.observe(node["id"], {"tcp": True, "probes": [
            {"region": "ru", "observer_ok": True, "vpn_ok": True}]}, self.worker.config), "healthy")
        self.assertEqual(self.job()["status"], "recovered")
        self.store.decide(job_id, "approve")
        self.assertEqual(self.job()["status"], "recovered")

    def test_duplicate_approval_and_lost_order_response_never_resubmit(self):
        job_id = self.incident()
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: self.store.decide(job_id, "approve"), range(2)))
        self.provider.order.side_effect = ProviderError("response_lost")
        with patch.object(self.worker, "probe", return_value=self.evidence):
            self.worker.run()
        self.assertEqual(self.job()["status"], "uncertain")
        self.assertEqual(self.job()["reserved"], 1)
        self.provider.reconcile.return_value = 20
        with patch.object(self.worker, "probe", return_value=self.evidence):
            self.worker.run()
        self.assertEqual(self.job()["service_id"], 20)
        self.assertEqual(self.job()["status"], "provisioning")
        self.provider.order.assert_called_once()

    def test_expiry_blocks_orders_but_legacy_budget_does_not(self):
        job_id = self.incident()
        with self.store.write() as db:
            db.execute("UPDATE jobs SET expires=? WHERE id=?", (timestamp() - 1, job_id))
        self.store.decide(job_id, "approve")
        self.assertEqual(self.job()["status"], "expired")
        self.worker.propose(self.config["nodes"][0])
        self.config["monthly_limit"] = 10
        self.save_config()
        self.store.decide(self.job()["id"], "approve")
        self.assertEqual(self.job()['status'],'approved')
        self.provider.order.assert_not_called()

    def test_concurrent_unfinished_replacements_are_serialized(self):
        job_id = self.incident()
        self.store.decide(job_id, "approve")
        with self.store.write() as db:
            with self.assertRaises(InfrastructureError):
                self.store.check_replacement_slot(db)

    def test_cancel_wins_even_if_worker_already_read_approved_job(self):
        job_id = self.incident()
        self.store.decide(job_id, "approve")
        old_job = self.raw_job()
        self.store.decide(job_id, "cancel")
        self.worker.advance(old_job)
        self.provider.order.assert_not_called()
        self.assertEqual(self.job()["status"], "cancelled")

    def test_simulation_never_calls_provider_or_deployment(self):
        self.config["mode"] = "simulate"
        self.config["rate_valid_until"] = 0
        self.save_config()
        self.worker = Worker(self.store, self.provider)
        job_id = self.incident()
        self.store.decide(job_id, "approve")
        with patch("app.infrastructure.execute") as hook:
            self.worker.advance(self.raw_job())
        self.assertEqual(self.job()["status"], "simulated")
        self.provider.order.assert_not_called()
        self.provider.quote.assert_not_called()
        hook.assert_not_called()

    def test_failed_candidate_does_not_publish_and_full_pipeline_persists_override(self):
        job_id = self.incident()
        self.store.decide(job_id, "approve")
        self.worker.advance(self.raw_job())
        self.provider.server.return_value = {"id": 20, "name": "nodeguard-" + job_id, "status": "active"}
        self.provider.address.return_value = "8.8.8.8"
        with patch("app.infrastructure.execute", return_value={"ready": True, "port": 8080}) as hook:
            self.worker.advance(self.raw_job())
            self.assertEqual(self.job()["status"], "verifying")
            with patch.object(self.worker, "probe", return_value=self.evidence) as candidate_probe:
                self.worker.advance(self.raw_job())
            self.assertEqual(candidate_probe.call_args.args[0]["port"], 8080)
            hook.assert_called_once()
            self.assertEqual(self.job()["status"], "verifying")
        healthy = {"tcp": True, "probes": [{"region": "ru", "observer_ok": True, "vpn_ok": True}] * 2}
        with patch.object(self.worker, "probe", return_value=healthy), patch("app.infrastructure.execute", return_value={"ready": True}):
            self.worker.advance(self.raw_job())
        self.assertEqual(self.job()["status"], "publishing")
        with patch("app.infrastructure.execute", return_value={"pending": True}):
            self.worker.advance(self.raw_job())
        self.assertEqual(self.job()["status"], "publishing")
        with patch("app.infrastructure.execute", return_value={"published": True}):
            self.worker.advance(self.raw_job())
        self.assertEqual(self.job()["status"], "ready")
        with connect(self.store.path) as db:
            override = json.loads(db.execute("SELECT spec FROM overrides").fetchone()[0])
        self.assertEqual(override["ip"], "8.8.8.8")
        self.assertEqual(override["datacenter_id"], 2)
        self.assertEqual(override["port"], 8080)

    def test_server_limit_is_enforced_before_post(self):
        job_id = self.incident()
        self.store.decide(job_id, "approve")
        self.provider.servers.return_value = [{"id": index} for index in range(3)]
        with patch.object(self.worker, "probe", return_value=self.evidence):
            self.worker.run()
        self.assertEqual(self.job()["status"], "cancelled")
        self.assertEqual(self.raw_job()["reserved"], 0)
        self.assertEqual(self.job()["error"], "server_limit_reached")
        self.provider.order.assert_not_called()

    def test_explicit_provider_validation_releases_reservation_without_retry(self):
        job_id = self.incident()
        self.store.decide(job_id, "approve")
        self.provider.order.side_effect = ProviderValidationError("provider_tariff_limit")
        with patch.object(self.worker, "probe", return_value=self.evidence):
            self.worker.run()
            self.worker.run()
        self.assertEqual(self.job()["status"], "cancelled")
        self.assertEqual(self.raw_job()["reserved"], 0)
        self.assertEqual(self.job()["error"], "provider_tariff_limit")
        self.provider.order.assert_called_once()

    def test_admin_routes_require_session_and_csrf(self):
        settings = Settings("primary", "https://primary.example", self.root, b"s" * 32, b"k" * 32,
                            HASHER.hash("admin-password"), infrastructure_config=self.config_path)
        Store(self.root).initialize(True, settings.access_key_id)
        with TestClient(create_app(settings), base_url=settings.origin) as client:
            self.assertEqual(client.get("/admin/infrastructure").status_code, 403)
            form = client.get("/admin/login")
            import re
            csrf = re.search('name="csrf" value="([a-f0-9]+)"', form.text)[1]
            client.post("/admin/login", data={"csrf": csrf, "password": "admin-password"}, headers={"Origin": settings.origin})
            page = client.get("/admin/infrastructure")
            self.assertEqual(page.status_code, 200)
            job_id = self.incident()
            self.assertEqual(client.post(f"/admin/infrastructure/{job_id}/approve", data={"csrf": "a" * 64}).status_code, 403)
            page = client.get("/admin/infrastructure")
            csrf = re.search('name="csrf" value="([a-f0-9]+)"', page.text)[1]
            result = client.post(f"/admin/infrastructure/{job_id}/approve", data={"csrf": csrf},
                                 headers={"Origin": settings.origin}, follow_redirects=False)
            self.assertEqual(result.status_code, 303)
            self.assertEqual(self.job()["status"], "approved")

    def test_ru_admin_shows_stale_monitor_and_queued_telegram_without_a_replica(self):
        settings=Settings('primary','https://primary.example',self.root,b's'*32,b'k'*32,
                          HASHER.hash('admin-password'),infrastructure_config=self.config_path,replication_enabled=False)
        Store(self.root).initialize(True,settings.access_key_id)
        job_id=self.incident()
        with self.store.write() as db:db.execute('UPDATE nodes SET observed_at=?',(timestamp()-1000,))
        with TestClient(create_app(settings),base_url=settings.origin) as client:
            import re
            form=client.get('/admin/login');csrf=re.search('name="csrf" value="([a-f0-9]+)"',form.text)[1]
            client.post('/admin/login',data={'csrf':csrf,'password':'admin-password'},headers={'Origin':settings.origin})
            page=client.get('/admin/infrastructure')
            self.assertEqual(page.status_code,200)
            self.assertIn('Недостаточно свежих данных',page.text)
            self.assertIn('Сообщений в очереди',page.text)
            self.assertIn('Доступность Telegram на управление не влияет',page.text)
            self.assertIn('1.1.1.1:443',page.text)
            home=client.get('/admin')
            self.assertIn('База пользователей находится на этом сервере.',home.text)
            self.assertNotIn('name="reserve_enabled"',home.text)
            self.assertNotIn('Локальные изменения ещё не подтверждены резервным сервером',home.text)

    def test_disabled_replication_cli_never_contacts_retiring_host(self):
        from app import cli
        settings=Settings('primary','https://primary.example',self.root,b's'*32,b'k'*32,
                          HASHER.hash('admin-password'),replication_enabled=False)
        Store(self.root).initialize(True,settings.access_key_id)
        with patch.object(cli.Settings,'from_env',return_value=settings),patch.object(cli,'send') as sender,patch('sys.argv',['access-site','send']):
            self.assertEqual(cli.main(),0)
            sender.assert_not_called()

    def test_admin_omits_financial_details_from_stored_jobs_and_failed_checks(self):
        self.config['candidates'][0]['label'] = 'Example VPS — $0.07 / 200 рублей'
        self.save_config()
        job_id = self.incident()
        with self.store.write() as db:
            db.execute('UPDATE jobs SET error=? WHERE id=?', ('Недостаточно денег для оплаты тарифа', job_id))
            db.execute('INSERT INTO replacement_checks(node,request_id,requested,finished,result) VALUES (?,?,?,?,?)',
                       ('EU1', 'test-check', timestamp(), timestamp(), json.dumps({'error': 'provider_balance_insufficient'})))
        settings = Settings('primary', 'https://primary.example', self.root, b's'*32, b'k'*32,
                            HASHER.hash('admin-password'), infrastructure_config=self.config_path)
        Store(self.root).initialize(True, settings.access_key_id)
        with TestClient(create_app(settings), base_url=settings.origin) as client:
            import re
            form = client.get('/admin/login')
            csrf = re.search('name="csrf" value="([a-f0-9]+)"', form.text)[1]
            client.post('/admin/login', data={'csrf': csrf, 'password': 'admin-password'}, headers={'Origin': settings.origin})
            page = client.get('/admin/infrastructure')
            self.assertEqual(page.status_code, 200)
            self.assertNotRegex(page.text.lower(), r'оплат|плат[её]ж|ден[еь]г|бюджет|тариф|рубл|usd|balance|\$0')
            self.assertIn('Проверьте настройки в панели провайдера', page.text)
            self.assertIn('Подтвердить заказ', page.text)

    def test_duplicate_probe_network_is_rejected(self):
        self.config["probes"][1]["network"] = "AS-one"
        self.save_config()
        with self.assertRaises(ValueError):
            load_config(self.config_path)

    def test_cancelled_incident_does_not_reopen_until_a_new_failure_episode(self):
        job_id = self.incident()
        self.store.decide(job_id, "cancel")
        with patch.object(self.worker, "probe", return_value=self.evidence):
            self.worker.run()
        self.assertEqual(len(self.store.overview()[2]), 1)

    def test_stale_exchange_rate_does_not_block_order(self):
        job_id = self.incident()
        self.store.decide(job_id, "approve")
        self.worker.config["rate_valid_until"] = timestamp() - 1
        self.worker.advance(self.raw_job())
        self.provider.order.assert_called_once()

    def test_repeat_after_unknown_order_reconciles_without_ordering(self):
        job_id = self.incident()
        self.store.decide(job_id, "approve")
        self.worker.status(job_id, "attention", error="order_result_unknown")
        self.store.decide(job_id, "resume")
        self.provider.reconcile.return_value = None
        self.worker.advance(self.raw_job())
        self.assertEqual(self.job()["status"], "uncertain")
        self.provider.order.assert_not_called()

    def test_manual_request_can_be_confirmed_without_independent_failure_reports(self):
        unknown = {"tcp": True, "probes": []}
        self.store.request_replacement("EU1")
        with patch.object(self.worker, "probe", return_value=unknown):
            self.worker.run()
        self.assertTrue(self.job()["spec"]["manual"])
        job_id = self.job()["id"]
        healthy = {"tcp": True, "probes": [{"region": "ru", "observer_ok": True, "vpn_ok": True}]}
        with patch.object(self.worker, "probe", return_value=healthy):
            self.worker.run()
        self.assertEqual(self.job()["status"], "pending")
        self.provider.order.assert_not_called()
        self.store.decide(job_id, "approve")
        self.worker.advance(self.raw_job())
        self.provider.order.assert_called_once()

    def test_notification_failure_keeps_outbox_without_failing_monitoring(self):
        self.incident()
        telegram = Mock()
        telegram.send.side_effect = ReminderError("Telegram request failed")
        self.worker.notify(telegram, "https://primary.example")
        with connect(self.store.path) as db:
            self.assertGreater(db.execute("SELECT count(*) FROM notifications WHERE sent=0").fetchone()[0], 0)
        telegram.send.side_effect = None
        self.worker.notify(telegram, "https://primary.example")
        with connect(self.store.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM notifications WHERE sent=0").fetchone()[0], 0)


class VdsinaTests(unittest.TestCase):
    def test_empty_account_inventory_uses_null_and_still_rejects_invalid_shapes(self):
        api=Vdsina()
        with patch.object(api,'request',return_value=None):
            self.assertEqual(api.servers(),[])
            self.assertIsNone(api.reconcile('not-created'))
        with patch.object(api,'request',return_value={'unexpected':'shape'}),self.assertRaises(ProviderError):
            api.servers()

    def test_tariff_quota_validation_is_definitive_and_safe_to_cancel(self):
        response = Mock(status=400)
        response.read.return_value = json.dumps({"status":"error","description":"Validation Error",
                                                "data":{"server-plan":["You cannot order more services under this tariff plan"]}}).encode()
        with patch.dict(os.environ, {"VDSINA_API_TOKEN":"test-only"}), patch("app.vdsina.http.client.HTTPSConnection") as connection:
            connection.return_value.getresponse.return_value = response
            with self.assertRaisesRegex(ProviderValidationError, "provider_tariff_limit"):
                Vdsina().request("POST", "server", {"datacenter":0,"server-plan":0})

    def test_created_response_is_successful(self):
        response = Mock(status=201)
        response.read.return_value = b'{"status":"ok","data":{"id":18}}'
        with patch.dict(os.environ, {"VDSINA_API_TOKEN": "test-only"}), patch(
            "app.vdsina.http.client.HTTPSConnection"
        ) as connection:
            connection.return_value.getresponse.return_value = response
            self.assertEqual(Vdsina().request("POST", "ssh-key", {"name": "test"}), {"id": 18})

    def test_native_currency_and_order_payload(self):
        api = Vdsina()
        with patch.object(api,'quote',return_value='0.07'), patch.object(api, "request", return_value={"id": 18}) as request:
            self.assertEqual(api.order("nodeguard-job", {"plan_id": 1, "datacenter_id": 2,
                                                       "template_id": 3, "ssh_key_id": 4}), 18)
        request.assert_called_once_with("POST", "server", {"name": "nodeguard-job", "datacenter": 2,
                                                           "server-plan": 1, "template": 3, "ssh-key": 4})

    def test_reconciliation_refuses_ambiguous_orders(self):
        api = Vdsina()
        with patch.object(api, "servers", return_value=[{"id": 1, "name": "same"}, {"id": 2, "name": "same"}]):
            with self.assertRaises(ProviderError):
                api.reconcile("same")

    def test_server_addresses_support_both_documented_response_shapes(self):
        for value in ({"ip": "1.1.1.1", "type": "4"}, [{"ip": "1.1.1.1", "type": "4"}]):
            self.assertEqual(Vdsina.address({"ip": value}), "1.1.1.1")
        with self.assertRaises(ProviderError):
            Vdsina.address({"ip": [{"ip": "1.1.1.1"}, {"ip": "8.8.8.8"}]})


if __name__ == "__main__":
    unittest.main()
