import base64
import re
import ssl
import tempfile
import time
import unittest
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app import admin_relay, reserve
from app.access_term import access_date, noon
from app.auth import HASHER
from app.db import Store, connect
from app.main import create_app
from app.settings import Settings
from app.sync import SyncError, backup, receive, restore, snapshot, sync_health
from app.xui import Panel, PanelError, PanelSettings
from app.subscriptions import subscription_url


PRIMARY = "https://primary.example"
REPLICA = "https://replica.example"
CONFIG = "https://config.example/test?key=private-test-value"
ADMIN_PASSWORD = "test-admin-password"


def csrf(response):
    return re.search(r'name="csrf" value="([a-f0-9]{64})"', response.text)[1]


def login(client, origin, password, path="/login"):
    form = client.get("/admin/login" if path == "/admin/login" else "/")
    return client.post(path, data={"csrf": csrf(form), "password": password}, headers={"Origin": origin})


class PanelTLSTests(unittest.TestCase):
    def test_public_certificate_is_verified_over_loopback(self):
        settings = PanelSettings("https://127.0.0.1:2053", 7, "panel.example:443", "test-token",
                                 tls_verify_public_address=True)
        tcp = Mock()
        with patch("app.xui.socket.create_connection", return_value=tcp) as dial, patch.object(
            ssl.SSLContext, "wrap_socket", autospec=True,
            side_effect=ssl.SSLCertVerificationError("wrong certificate"),
        ) as handshake:
            with self.assertRaisesRegex(PanelError, "panel_unavailable"):
                Panel(settings).inbound()

        dial.assert_called_once_with(("127.0.0.1", 2053), 4)
        context, socket = handshake.call_args.args
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(socket, tcp)
        self.assertEqual(handshake.call_args.kwargs, {"server_hostname": "panel.example"})
        tcp.sendall.assert_not_called()
        tcp.close.assert_called_once()


class AccessSiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_hash = HASHER.hash(ADMIN_PASSWORD)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.settings = Settings("primary", PRIMARY, self.directory / "primary", b"a" * 32, b"k" * 32, self.admin_hash)
        self.replica_settings = replace(self.settings, role="replica", origin=REPLICA,
                                        data_dir=self.directory / "replica", secret=b"b" * 32)
        self.primary = Store(self.settings.data_dir)
        self.replica = Store(self.replica_settings.data_dir)
        self.primary.initialize(True, self.settings.access_key_id)
        self.replica.initialize(False, self.settings.access_key_id)
        app = create_app(self.settings)
        self.admin = TestClient(app, base_url=PRIMARY, follow_redirects=False)
        self.user = TestClient(app, base_url=PRIMARY, follow_redirects=False)
        self.backup = TestClient(create_app(self.replica_settings), base_url=REPLICA, follow_redirects=False)
        for client in (self.admin, self.user, self.backup):
            self.addCleanup(client.close)

    def create_user(self, name="example", platform="any", *, reserve_enabled=False):
        self.assertEqual(login(self.admin, PRIMARY, ADMIN_PASSWORD, "/admin/login").status_code, 303)
        form = {"csrf": csrf(self.admin.get("/admin")), "login": name, "platform": platform}
        if reserve_enabled:
            form["reserve_enabled"] = "1"
        response = self.admin.post("/admin/users", data=form)
        self.assertEqual(response.status_code, 200)
        password = re.search(r'id="new-password"[^>]+value="([^"]+)"', response.text)[1]
        account = self.primary.account("login", name)
        self.assertTrue(account["password_hash"].startswith("$argon2id$"))
        self.assertNotIn(password, account["password_hash"])
        return account["id"], password

    def change(self, account_id, action, **fields):
        fields["csrf"] = csrf(self.admin.get("/admin"))
        return self.admin.post(f"/admin/users/{account_id}/{action}", data=fields)

    def test_guide_svg_allows_only_embedded_image_resources(self):
        response = self.user.get('/static/guides/demo.svg')
        self.assertEqual(response.status_code, 200)
        self.assertIn('image/svg+xml', response.headers['content-type'])
        self.assertEqual(response.headers['content-security-policy'], "default-src 'none'; img-src data:;")
        self.assertIn("img-src 'self';", self.user.get('/').headers['content-security-policy'])

    def test_current_password_is_admin_only_and_does_not_reset_credentials(self):
        account_id, password = self.create_user()
        before = dict(self.primary.account("id", account_id))
        response = self.change(account_id, "show-password")
        self.assertEqual(response.status_code, 200)
        self.assertIn(password, response.text)
        self.assertEqual(dict(self.primary.account("id", account_id)), before)
        path = f"/admin/users/{account_id}/show-password"
        self.assertEqual(self.user.post(path, data={"csrf": "invalid"}).status_code, 403)
        self.assertEqual(self.admin.post(path, data={"csrf": "invalid"}).status_code, 403)
        with connect(self.primary.data) as db, db:
            encrypted = db.execute('SELECT ciphertext FROM password_vault').fetchone()[0]
            self.assertNotIn(password, encrypted)
            db.execute('DELETE FROM password_vault')
        self.assertEqual(self.change(account_id, "show-password").status_code, 409)
        self.assertEqual(login(self.user, PRIMARY, password).status_code, 303)
        self.assertIn(password, self.change(account_id, "show-password").text)
        self.change(account_id, "password")
        self.assertNotIn(f'value="{password}"', self.change(account_id, "show-password").text)

    def replicate(self, name):
        path = self.directory / name
        revision = snapshot(self.primary, path)
        with path.open("rb") as stream:
            self.assertEqual(receive(self.replica, stream), revision)
        return path

    def test_permissions_and_csrf(self):
        self.assertEqual(self.user.get("/admin").headers["location"], "/admin/login")
        self.assertEqual(self.user.post("/admin/users", data={"login": "forbidden"}).status_code, 403)
        form = self.user.get("/")
        self.assertEqual(self.user.post("/login", data={"password": "bad"}).status_code, 403)
        self.assertEqual(self.user.post("/login", data={"csrf": csrf(form), "password": "bad"},
                                        headers={"Origin": "https://other.example"}).status_code, 403)
        _, password = self.create_user()
        self.assertEqual(login(self.user, PRIMARY, password, "/admin/login").status_code, 401)
        response = login(self.user, PRIMARY, password)
        self.assertEqual(response.status_code, 303)
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertIn("Secure", response.headers["set-cookie"])
        self.assertIn("SameSite=strict", response.headers["set-cookie"])
        self.assertEqual(self.user.get("/admin").status_code, 403)
        self.assertEqual(self.user.post("/admin/users", data={"csrf": csrf(self.user.get("/")), "login": "x"}).status_code, 403)

    def test_launcher_origin_can_read_only_health(self):
        launcher_origin = "https://launcher.example"
        app = create_app(replace(self.settings, launcher_origin=launcher_origin))
        with TestClient(app, base_url=PRIMARY) as client:
            health = client.get("/health", headers={"Origin": launcher_origin})
            self.assertEqual(health.json(), {"status": "ok"})
            self.assertEqual(health.headers["access-control-allow-origin"], launcher_origin)
            self.assertEqual(health.headers["vary"], "Origin")
            self.assertNotIn("access-control-allow-credentials", health.headers)
            self.assertNotIn("access-control-allow-origin", client.get(
                "/health", headers={"Origin": "https://other.example"}).headers)
            for path in ("/", "/admin/login"):
                self.assertNotIn("access-control-allow-origin", client.get(
                    path, headers={"Origin": launcher_origin}).headers)
        self.assertNotIn("access-control-allow-origin", self.user.get(
            "/health", headers={"Origin": launcher_origin}).headers)

    def test_account_changes_and_logout(self):
        account_id, password = self.create_user()
        self.assertEqual(self.change(account_id, "config", config=CONFIG).status_code, 303)
        self.assertNotIn(CONFIG, self.admin.get("/admin").text)
        self.assertEqual(login(self.user, PRIMARY, password).status_code, 303)
        cabinet = self.user.get("/")
        self.assertIn(CONFIG, cabinet.text)
        self.assertEqual(cabinet.text.count('data-copy="config"'), 1)
        self.assertIn("Копировать ссылку подключения", cabinet.text)
        self.assertIn("Инструкция для прямого подключения", cabinet.text)
        self.assertIn("Инструкция для подключения подписки", cabinet.text)
        self.assertIn('<details id="ordinary-connection" class="alternative-method">', cabinet.text)
        for guide in ("iPhone / iPad · V2RC", "Android · v2rayNG", "Windows · v2rayN"):
            self.assertIn(f"<summary>{guide}</summary>", cabinet.text)
        self.assertIn("<time datetime=", cabinet.text)
        self.assertEqual(self.user.post("/logout", data={"csrf": csrf(cabinet)}).status_code, 303)
        self.assertNotIn(CONFIG, self.user.get("/").text)
        self.assertEqual(login(self.user, PRIMARY, password).status_code, 303)
        self.assertEqual(self.change(account_id, "revoke").status_code, 303)
        self.assertNotIn(CONFIG, self.user.get("/").text)
        self.assertEqual(login(self.user, PRIMARY, password).status_code, 401)

    def test_subscription_survives_vpn_move_and_rejects_revoked_or_rotated_access(self):
        account_id, _ = self.create_user()
        self.change(account_id, "config", config="vless://credential@1.1.1.1:443")
        account = self.primary.account("id", account_id)
        url = subscription_url(self.settings, account)
        response = self.user.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(base64.b64decode(response.content).decode().strip(), account["config"])
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.change(account_id, "config", config="vless://credential@8.8.8.8:443")
        self.assertEqual(subscription_url(self.settings, self.primary.account("id", account_id)), url)
        self.assertIn(b"8.8.8.8", base64.b64decode(self.user.get(url).content))
        self.assertEqual(self.user.get(url[:-1] + ("0" if url[-1] != "0" else "1")).status_code, 404)
        self.change(account_id, "password")
        self.assertEqual(self.user.get(url).status_code, 404)
        fresh = subscription_url(self.settings, self.primary.account("id", account_id))
        self.change(account_id, "revoke")
        self.assertEqual(self.user.get(fresh).status_code, 404)

    def test_subscription_expiry_and_publication_maintenance_are_enforced(self):
        account_id, _ = self.create_user()
        self.change(account_id, "config", config=CONFIG)
        account = self.primary.account("id", account_id)
        url = subscription_url(self.settings, account)
        self.primary.change("access", account_id=account_id, access_until=1, access_day=1)
        self.assertEqual(self.user.get(url).status_code, 404)
        maintenance = self.settings.data_dir / "vpn-publication-maintenance"
        maintenance.touch()
        self.assertEqual(self.change(account_id, "config", config="https://new.example").status_code, 503)
        self.assertEqual(self.primary.account("id", account_id)["config"], CONFIG)

    def test_rate_limit(self):
        for _ in range(31):
            response = login(self.user, PRIMARY, "incorrect")
            if response.status_code == 429:
                break
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)

    def test_github_cabinet_reports_problems_without_reserve_permissions_or_controller(self):
        _, enabled_code = self.create_user("portal-enabled", reserve_enabled=True)
        _, disabled_code = self.create_user("portal-disabled")
        origin = "https://asmove.github.io";prefix = "/api/cabinet"
        app = create_app(replace(self.settings, portal_origin=origin, emergency_controller="https://controller.example"))
        with (TestClient(app, base_url=PRIMARY, follow_redirects=False) as user,
              patch.object(admin_relay, "exchange") as relay, patch.object(Panel, "issue") as issue):
            options = user.options(prefix + "/account", headers={"Origin": origin, "Access-Control-Request-Headers": "authorization"})
            self.assertEqual(options.headers["Access-Control-Allow-Origin"], origin)
            self.assertEqual(user.post(prefix + "/report-problem", headers={"Origin": origin}).status_code, 401)
            self.assertEqual(user.post(prefix + "/report-problem", headers={"Origin": "https://other.example"}).status_code, 403)
            for code in (enabled_code, disabled_code):
                logged = user.post(prefix + "/login", data={"password": code}, headers={"Origin": origin})
                self.assertEqual(logged.status_code, 200)
                headers = {"Origin": origin, "Authorization": f"Bearer {logged.json()['session']}"}
                profile = user.get(prefix + "/account", headers=headers)
                self.assertFalse(profile.json()["reserve_enabled"])
                self.assertIsNone(profile.json()["problem_report"]["next_at"])
                self.assertEqual(user.post(prefix + "/reserve", headers=headers).status_code, 410)
                first = user.post(prefix + "/report-problem", headers=headers)
                self.assertTrue(first.json()["accepted"])
                self.assertFalse(user.post(prefix + "/report-problem", headers=headers).json()["accepted"])
                self.assertEqual(user.get(prefix + "/account", headers=headers).json()["problem_report"]["next_at"], first.json()["next_at"])
                user.post(prefix + "/logout", headers=headers)
                self.assertEqual(user.post(prefix + "/report-problem", headers=headers).status_code, 401)
            relay.assert_not_called();issue.assert_not_called()
        with connect(self.settings.data_dir / "problem-reports.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM reports").fetchone()[0], 2)

    def test_user_problem_button_checks_csrf_and_never_requests_a_reserve(self):
        _, password = self.create_user()
        app = create_app(replace(self.settings, emergency_controller="https://controller.example"))
        with (TestClient(app, base_url=PRIMARY, follow_redirects=False) as user,
              patch.object(admin_relay, "exchange") as relay, patch.object(Panel, "issue") as issue):
            self.assertEqual(user.post("/report-problem", data={"csrf": "bad"}).status_code, 403)
            self.assertEqual(login(user, PRIMARY, password).status_code, 303)
            cabinet = user.get("/")
            self.assertIn("Сообщить о проблеме", cabinet.text)
            self.assertNotIn("Запросить запасную ссылку", cabinet.text)
            self.assertNotIn("Запасной сервер", cabinet.text)
            self.assertEqual(user.post("/report-problem", data={"csrf": "bad"}).status_code, 403)
            self.assertEqual(user.post("/report-problem", data={"csrf": csrf(cabinet)}, headers={"Origin": "https://other.example"}).status_code, 403)
            first = user.post("/report-problem", data={"csrf": csrf(cabinet)})
            self.assertEqual(first.status_code, 200)
            self.assertIn("Сообщение сохранено", first.text)
            second = user.post("/report-problem", data={"csrf": csrf(cabinet)})
            self.assertIn("Вы уже сообщили", second.text)
            self.assertEqual(user.post("/reserve", data={"csrf": csrf(cabinet)}).status_code, 410)
            relay.assert_not_called();issue.assert_not_called()
        with connect(self.settings.data_dir / "problem-reports.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM reports").fetchone()[0], 1)

    def test_existing_reserve_links_still_expire_and_cleanup_without_user_requests(self):
        account_id, _ = self.create_user(reserve_enabled=True)
        panel = Panel(PanelSettings("http://127.0.0.1:8080", 7, "panel.example:443", "test-token"))
        links = reserve.ReserveLinks(self.primary, panel);links.initialize()
        stamp = int(time.time());account = self.primary.account("id", account_id)
        with (patch("app.reserve.now", return_value=stamp) as clock,
              patch.object(Panel, "issue", return_value="vless://existing@panel.example:443"),
              patch.object(Panel, "remove") as remove):
            link = links.issue(account)["link"]
            self.assertEqual(links.status(account)["link"], link)
            clock.return_value = stamp + reserve.TTL + reserve.RETENTION
            links.cleanup();remove.assert_called_once()
            self.assertIsNone(links.status(account).get("link"))

    def test_legacy_reserve_link_without_saved_deadline_expires_after_twelve_hours(self):
        account_id, _ = self.create_user(reserve_enabled=True)
        account = self.primary.account("id", account_id)
        start = int(time.time())
        client_id = "a" * 32
        config = "vless://legacy-reserve@panel.example:443"
        panel = Panel(PanelSettings("http://127.0.0.1:8080", 7, "panel.example:443", "test-token"))
        links = reserve.ReserveLinks(self.primary, panel)
        links.initialize()
        with connect(links.path) as connection, connection:
            connection.execute("INSERT INTO requests VALUES (?, ?, ?, ?)", (client_id, account_id, start, config))

        with (patch("app.reserve.now", return_value=start + 12 * 3600 - 1) as clock,
              patch.object(Panel, "remove") as remove):
            self.assertEqual(links.status(account)["link"], {"config": config, "expires_at": start + 12 * 3600})
            clock.return_value += 1
            self.assertEqual(links.status(account), {"link": None, "next_at": start + 24 * 3600})
            clock.return_value += reserve.RETENTION
            links.cleanup()
            remove.assert_called_once_with(client_id)

    def test_platform_controls_comment_and_ip_limit_for_permanent_links(self):
        panel = PanelSettings("http://127.0.0.1:8080", 7, "panel.example:443", "test-token")
        app = create_app(replace(self.settings, panel=panel))
        clients = {}
        issued = []
        discard_ip_limit = False

        def panel_request(path, payload=None):
            if path == "inbounds/get/7":
                return {"id": 7, "protocol": "vless", "enable": True}
            if path == "clients/add":
                record = payload["client"].copy()
                record["uuid"] = record["id"]
                record["allowedIPs"] = ""
                issued.append((record["comment"], record["limitIp"]))
                if discard_ip_limit:
                    record["limitIp"] = 0
                clients[record["email"]] = {"client": record, "inboundIds": payload["inboundIds"]}
                return
            if path == "clients/list":
                return [record["client"] for record in clients.values()]
            prefix, email = path.rsplit("/", 1)
            if prefix == "clients/get":
                return clients.get(email)
            if prefix == "clients/del":
                del clients[email]
                return
            if prefix == "clients/traffic":
                return clients[email]["client"]
            if prefix == "clients/update":
                self.assertNotIn("allowedIPs", payload)
                self.assertEqual(payload["id"], clients[email]["client"]["uuid"])
                clients[email]["client"].update(payload)
                return
            if prefix == "clients/links":
                return [f"vless://{clients[email]['client']['uuid']}@panel.example:443"]
            self.fail(f"Unexpected panel API request: {path}")

        with (
            TestClient(app, base_url=PRIMARY, follow_redirects=False) as admin,
            patch.object(Panel, "request", side_effect=panel_request),
        ):
            self.assertEqual(login(admin, PRIMARY, ADMIN_PASSWORD, "/admin/login").status_code, 303)
            form = {"csrf": csrf(admin.get("/admin")), "login": " Example.User ", "platform": "windows"}
            self.assertEqual(admin.post("/admin/users", data={**form, "platform": "invalid"}).status_code, 400)
            self.assertEqual(issued, [])
            response = admin.post("/admin/users", data=form)
            self.assertEqual(response.status_code, 200)
            account = self.primary.account("login", "example.user")
            _, email = Panel.identity(account["id"])
            self.assertEqual(clients[email]["client"]["expiryTime"], account["access_until"] * 1000)
            extension = admin.post(f"/admin/users/{account['id']}/extend", data={"csrf": csrf(admin.get("/admin"))})
            self.assertEqual(extension.status_code, 303)
            renewed = self.primary.account("id", account["id"])
            self.assertGreater(renewed["access_until"], account["access_until"])
            self.assertEqual(clients[email]["client"]["expiryTime"], renewed["access_until"] * 1000)
            self.assertEqual(clients[email]["client"]["limitIp"], 1)
            base = f"/admin/users/{account['id']}"
            self.assertEqual(admin.post(f"{base}/access", data={
                "csrf": csrf(admin.get("/admin")), "access_date": "2020-01-01",
            }).status_code, 303)
            self.assertFalse(clients[email]["client"]["enable"])
            self.assertEqual(admin.post(f"{base}/access", data={
                "csrf": csrf(admin.get("/admin")), "access_date": access_date(renewed["access_until"]).isoformat(),
            }).status_code, 303)
            self.assertTrue(clients[email]["client"]["enable"])
            for action in ("revoke", "enable"):
                response = admin.post(f"/admin/users/{account['id']}/{action}", data={"csrf": csrf(admin.get("/admin"))})
                self.assertEqual(response.status_code, 303)

            for platform, label, limit in (("any", "Любая", 0), ("ios", "iOS", 1), ("android", "Android", 1)):
                with self.subTest(platform=platform):
                    form = {"csrf": csrf(admin.get("/admin")), "login": f"user.{platform}", "platform": platform}
                    self.assertEqual(admin.post("/admin/users", data=form).status_code, 200)
                    self.assertEqual(issued[-1], (f"user.{platform} · {label}", limit))

            discard_ip_limit = True
            form = {"csrf": csrf(admin.get("/admin")), "login": "missing.limit", "platform": "android"}
            self.assertEqual(admin.post("/admin/users", data=form).status_code, 503)
            self.assertIsNone(self.primary.account("login", "missing.limit"))
            self.assertEqual(len(clients), 4)

        self.assertEqual(issued[:2], [("example.user · Windows", 1), ("example.user · Windows", 1)])

    def test_replica_admin_uses_primary_and_reads_changes_immediately(self):
        key = "a" * 64
        primary_settings = replace(self.settings, admin_relay_key=key)
        replica_settings = replace(self.replica_settings, admin_relay_key=key, admin_primary_origin=PRIMARY)
        with (
            TestClient(create_app(primary_settings), base_url=PRIMARY, follow_redirects=False) as main,
            TestClient(create_app(replica_settings), base_url=REPLICA, follow_redirects=False) as reserve,
        ):
            self.assertEqual(main.get(admin_relay.PATH).status_code, 403)
            self.assertEqual(main.post(admin_relay.PATH, headers={"Authorization": "Bearer bad"}).status_code, 403)
            self.assertEqual(reserve.post("/admin/users", data={"login": "example"}).status_code, 403)
            self.assertEqual(login(reserve, REPLICA, ADMIN_PASSWORD, "/admin/login").status_code, 303)

            def relay(settings, form=None):
                headers = {"Authorization": f"Bearer {settings.admin_relay_key}"}
                if form is None:
                    response = main.get(admin_relay.PATH, headers=headers)
                else:
                    response = main.post(admin_relay.PATH, headers=headers, data=form)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["cache-control"], "no-store")
                return response.json()

            with patch("app.admin_relay.request", side_effect=relay) as forward:
                self.assertEqual(reserve.post("/admin/users", data={"login": "example"}).status_code, 403)
                forward.assert_not_called()
                panel = reserve.get("/admin")
                self.assertIn("Создать и получить пароль", panel.text)
                self.assertNotIn('name="reserve_enabled"', panel.text)
                data = {"login": "example", "csrf": csrf(panel), "platform": "ios", "reserve_enabled": "1"}
                created = reserve.post("/admin/users", data=data)
                self.assertEqual(created.status_code, 200)
                password = re.search(r'id="new-password"[^>]+value="([^"]+)"', created.text)[1]
                self.assertEqual(reserve.post("/admin/users", data=data).status_code, 409)
                account = self.primary.account("login", "example")
                self.assertEqual(account["platform"], "ios")
                self.assertEqual(account["reserve_enabled"], 1)
                self.assertIsNone(self.replica.account("login", "example"))
                self.assertEqual(login(self.user, PRIMARY, password).status_code, 303)
                self.assertIn('class="account-name">example', reserve.get("/admin").text)
                base = f"/admin/users/{account['id']}"
                panel = reserve.get("/admin")
                self.assertNotIn('name="reserve_enabled"', panel.text)
                self.assertEqual(reserve.post(f"{base}/reserve", data={"csrf": csrf(panel)}).status_code, 410)
                self.assertEqual(self.primary.account("login", "example")["reserve_enabled"], 1)
                panel = reserve.get("/admin")
                self.assertNotIn('name="reserve_enabled" value="1" checked', panel.text)
                self.assertEqual(reserve.post(f"{base}/reserve", data={
                    "csrf": csrf(panel), "reserve_enabled": "1",
                }).status_code, 410)
                self.assertEqual(self.primary.account("login", "example")["reserve_enabled"], 1)
                self.assertEqual(reserve.post(f"{base}/access", data={
                    "csrf": csrf(reserve.get("/admin")), "access_date": "2035-01-31",
                }).status_code, 303)
                self.assertEqual(reserve.post(f"{base}/extend", data={"csrf": csrf(reserve.get("/admin"))}).status_code, 303)
                self.assertEqual(self.primary.account("login", "example")["access_until"], noon(date(2035, 2, 28)))
                for action in ("config", "password", "revoke", "enable", "delete"):
                    form = {"csrf": csrf(reserve.get("/admin")), "config": CONFIG}
                    response = reserve.post(f"{base}/{action}", data=form)
                    self.assertEqual(response.status_code, 200 if action == "password" else 303)
                self.assertIsNone(self.primary.account("login", "example"))

            with patch("app.admin_relay.request", side_effect=admin_relay.RelayError):
                panel = reserve.get("/admin")
                self.assertEqual(panel.status_code, 200)
                self.assertNotIn("Создать и получить пароль", panel.text)
                self.assertEqual(reserve.post("/admin/users", data={"csrf": csrf(panel), "login": "example"}).status_code, 503)

    def test_calendar_access_deadline_can_be_edited_and_extended(self):
        with patch("app.main.now", return_value=noon(date(2032, 1, 31))):
            account_id, password = self.create_user()
        self.assertEqual(self.primary.account("id", account_id)["access_until"], noon(date(2032, 2, 29)))
        self.assertEqual(self.change(account_id, "access", access_date="2032-02-30").status_code, 400)
        self.assertEqual(self.change(account_id, "access", access_date="2032-01-31").status_code, 303)

        for expected in (date(2032, 2, 29), date(2032, 3, 31)):
            response = self.change(account_id, "extend")
            self.assertEqual(response.status_code, 303)
            panel = self.admin.get(response.headers["location"])
            self.assertIn(f'id="user-{account_id}" open', panel.text)
            self.assertIn(f"{expected:%d.%m.%Y} в 12:00 МСК", panel.text)
            self.assertEqual(access_date(self.primary.account("id", account_id)["access_until"]), expected)

        deadline = noon(date(2032, 3, 31))
        self.replicate("access-deadline.sqlite3")
        with (patch("app.main.now", return_value=deadline - 1) as app_clock,
              patch("app.auth.now", return_value=deadline - 1) as auth_clock):
            for client, origin in ((self.user, PRIMARY), (self.backup, REPLICA)):
                self.assertEqual(login(client, origin, password).status_code, 303)
                self.assertIn("31.03.2032 в 12:00 МСК", client.get("/").text)
            app_clock.return_value = auth_clock.return_value = deadline
            for client, origin in ((self.user, PRIMARY), (self.backup, REPLICA)):
                self.assertNotIn("31.03.2032 в 12:00 МСК", client.get("/").text)
                self.assertEqual(login(client, origin, password).status_code, 403)

    def test_replica_serves_snapshot_and_rejects_stale_snapshot(self):
        self.assertEqual(self.backup.get("/health").status_code, 503)
        account_id, password = self.create_user(platform="android")
        self.assertEqual(self.change(account_id, "config", config=CONFIG).status_code, 303)
        previous = self.replicate("previous.sqlite3")
        self.admin.close()
        self.user.close()
        self.assertEqual(self.backup.get("/health").status_code, 200)
        self.assertEqual(login(self.backup, REPLICA, password).status_code, 303)
        cabinet = self.backup.get("/").text
        self.assertIn(CONFIG, cabinet)
        self.assertIn("<summary>Android · v2rayNG</summary>", cabinet)
        self.assertNotIn("<summary>iPhone / iPad · V2RC</summary>", cabinet)
        self.assertNotIn("<summary>Windows · v2rayN</summary>", cabinet)

        with TestClient(create_app(self.replica_settings), base_url=REPLICA, follow_redirects=False) as admin:
            self.assertEqual(login(admin, REPLICA, ADMIN_PASSWORD, "/admin/login").status_code, 303)
            self.assertEqual(admin.post("/admin/users", data={"csrf": csrf(admin.get("/admin")),
                                                               "login": "forbidden"}).status_code, 409)
        self.primary.change("revoke", account_id=account_id)
        self.replicate("next.sqlite3")
        self.assertNotIn(CONFIG, self.backup.get("/").text)
        with previous.open("rb") as stream, self.assertRaisesRegex(SyncError, "snapshot_conflict"):
            receive(self.replica, stream)
        self.assertEqual(login(self.backup, REPLICA, password).status_code, 401)

    def test_sync_status_distinguishes_revision_lag_from_time(self):
        self.assertEqual(sync_health(self.primary, "primary", 0, 300), (None, True, False))
        self.primary.record_sync("sent", revision=0)
        self.create_user()
        self.assertEqual(sync_health(self.primary, "primary", 1, 300)[1:], (False, True))
        self.assertIn("ещё не подтверждены", self.admin.get("/admin").text)
        self.primary.record_sync("sent", revision=1)
        self.assertEqual(sync_health(self.primary, "primary", 1, 300)[1:], (False, False))
        self.assertNotIn("ещё не подтверждены", self.admin.get("/admin").text)

    def test_accounts_from_legacy_database_and_snapshot_keep_reserve_access(self):
        account_id, _ = self.create_user()
        previous = self.directory / "legacy.sqlite3"
        snapshot(self.primary, previous)
        for path in (self.primary.data, previous):
            with connect(path) as connection, connection:
                connection.execute("ALTER TABLE accounts DROP COLUMN platform")
                connection.execute("ALTER TABLE accounts DROP COLUMN reserve_enabled")
                connection.execute("ALTER TABLE accounts DROP COLUMN access_until")
                connection.execute("ALTER TABLE accounts DROP COLUMN access_day")
                schema = connection.execute("SELECT sql FROM sqlite_schema WHERE name = 'audit'").fetchone()[0]
                connection.execute("ALTER TABLE audit RENAME TO audit_new")
                connection.execute(schema.replace(", 'reserve', 'access'", ""))
                connection.execute("INSERT INTO audit SELECT * FROM audit_new")
                connection.execute("DROP TABLE audit_new")
        self.primary.initialize(True, self.settings.access_key_id)
        self.assertEqual(self.primary.account("id", account_id)["platform"], "any")
        self.assertEqual(self.primary.account("id", account_id)["reserve_enabled"], 1)
        with previous.open("rb") as stream:
            self.assertEqual(receive(self.replica, stream), 1)
        self.assertEqual(self.replica.account("id", account_id)["platform"], "any")
        self.assertEqual(self.replica.account("id", account_id)["reserve_enabled"], 1)
        self.assertIsNone(self.replica.account("id", account_id)["access_until"])
        self.assertEqual(self.change(account_id, "reserve").status_code, 410)
        self.assertEqual(self.primary.account("id", account_id)["reserve_enabled"], 1)
        self.primary.change('reserve', account_id=account_id, reserve_enabled=False)
        _, audit, revision = self.primary.overview()
        self.assertEqual(revision, 2)
        self.assertEqual([event["action"] for event in audit], ["reserve", "create"])

    def test_snapshot_restores_account_settings_after_replica_upgrade_at_same_revision(self):
        account_id, _ = self.create_user()
        original = self.primary.account("id", account_id)
        path = self.replicate("before-replica-upgrade.sqlite3")
        with connect(self.replica.data) as connection, connection:
            connection.execute("ALTER TABLE accounts DROP COLUMN reserve_enabled")
            connection.execute("ALTER TABLE accounts DROP COLUMN access_until")
            connection.execute("ALTER TABLE accounts DROP COLUMN access_day")
        self.replica.initialize(False, self.settings.access_key_id)
        self.assertEqual(self.replica.account("id", account_id)["reserve_enabled"], 1)
        with path.open("rb") as stream:
            self.assertEqual(receive(self.replica, stream), 1)
        restored = self.replica.account("id", account_id)
        self.assertEqual(restored["reserve_enabled"], 0)
        self.assertEqual(restored["access_until"], original["access_until"])
        self.assertEqual(restored["access_day"], original["access_day"])

    def test_promoted_replica_can_manage_accounts_from_its_snapshot(self):
        account_id, _ = self.create_user()
        self.replicate("before-promotion.sqlite3")
        promoted = replace(self.replica_settings, role="primary",
                           admin_relay_key="a" * 64, admin_primary_origin=PRIMARY)
        with TestClient(create_app(promoted), base_url=REPLICA, follow_redirects=False) as admin:
            self.assertEqual(login(admin, REPLICA, ADMIN_PASSWORD, "/admin/login").status_code, 303)
            panel = admin.get("/admin")
            self.assertIn("Создать и получить пароль", panel.text)
            response = admin.post(f"/admin/users/{account_id}/revoke", data={"csrf": csrf(panel)})
            self.assertEqual(response.status_code, 303)
        self.assertFalse(self.replica.account("id", account_id)["enabled"])

    def test_backup_restore_clears_old_sessions(self):
        account_id, password = self.create_user()
        self.assertEqual(self.change(account_id, "config", config=CONFIG).status_code, 303)
        self.assertEqual(backup(self.primary), 2)
        saved, = (self.primary.directory / "backups").glob("access-*.sqlite3")
        self.assertEqual(login(self.user, PRIMARY, password).status_code, 303)
        self.assertEqual(self.change(account_id, "delete").status_code, 303)
        self.assertIsNone(self.primary.account("id", account_id))
        self.assertEqual(restore(self.primary, saved), 2)
        self.assertNotIn(CONFIG, self.user.get("/").text)
        self.assertEqual(login(self.user, PRIMARY, password).status_code, 303)
        self.assertIn(CONFIG, self.user.get("/").text)
