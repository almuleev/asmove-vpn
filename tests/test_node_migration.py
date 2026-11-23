import importlib.util
import json
from contextlib import nullcontext
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4
from urllib.parse import parse_qs, urlsplit

from app.db import Store
from app.node_migration import prepare_links, publish_links, synchronize_retiring_panel
from app.xui import Panel, PanelSettings, PanelGroup, PanelError


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(Path(self.temporary.name))
        self.store.initialize(True, "a" * 64)
        for index in range(2):
            self.store.change("create", account_id=uuid4().hex, login="user" + str(index),
                              access_index=str(index), password_hash="unchanged-hash", config="old-link")

    def test_atomic_publication_keeps_codes_terms_and_sessions(self):
        before, _, revision = self.store.overview()
        credentials = [dict(self.store.account("id", user["id"])) for user in before]
        links = {user["id"]: "new-" + user["id"] for user in before}
        publish_links(self.store, revision, links)
        for account in credentials:
            current = dict(self.store.account("id", account["id"]))
            self.assertEqual(current.pop("config"), links[account["id"]])
            current.pop("config_at"); account.pop("config"); account.pop("config_at")
            self.assertEqual(current, account)
        self.assertEqual(self.store.overview()[2], revision + 2)

    def test_grpc_links_use_one_approved_sni_and_keep_credentials(self):
        panel=Panel(PanelSettings('http://127.0.0.1:1234/',4,'1.1.1.1:8080','x'*20))
        panel.inbound=Mock(return_value={'streamSettings':{'network':'grpc','realitySettings':{
            'target':'dl.google.com:443','serverNames':['youtube.com','dl.google.com']}}})
        original='vless://123@1.1.1.1:8080?type=grpc&security=reality&sni=youtube.com&pbk=same-key&sid=abcd&serviceName=&alpn=http%2F1.1#old'
        normalized=panel.stable_link(original,'Connection');parsed=urlsplit(normalized);params=parse_qs(parsed.query,keep_blank_values=True)
        self.assertEqual(params['sni'],['dl.google.com']);self.assertEqual(params['alpn'],['h2'])
        self.assertEqual(params['pbk'],['same-key']);self.assertEqual(params['sid'],['abcd'])
        self.assertEqual(parsed.username,'123');self.assertEqual(parsed.fragment,'Connection')
        self.assertEqual(panel.stable_link(normalized,'Connection'),normalized)
        panel.inbound.return_value['streamSettings']['realitySettings']['serverNames']=['youtube.com']
        self.assertEqual(parse_qs(urlsplit(panel.stable_link(original,'Connection')).query)['sni'],['youtube.com'])

    def test_tcp_companion_keeps_its_own_sni(self):
        panel=Panel(PanelSettings('http://127.0.0.1:1234/',4,'1.1.1.1:8080','x'*20))
        panel.inbound=Mock()
        original='vless://123@1.1.1.1:443?type=tcp&security=reality&sni=www.mozilla.org&flow=xtls-rprx-vision'
        self.assertEqual(panel.stable_link(original,'Connection-TCP'),original+'#Connection-TCP')
        panel.inbound.assert_not_called()

    def test_stale_or_incomplete_publication_changes_nothing(self):
        before, _, revision = self.store.overview()
        links = {user["id"]: "new-link" for user in before}
        for stale, supplied in ((revision - 1, links), (revision, {before[0]["id"]: "new"})):
            with self.assertRaises(ValueError):
                publish_links(self.store, stale, supplied)
            self.assertEqual(self.store.overview()[2], revision)
            self.assertTrue(all(row["config"] == "old-link" for row in self.store.overview()[0]))

    def test_disabled_or_expired_clients_remain_disabled(self):
        panel = Panel(PanelSettings("http://127.0.0.1:1234/", 1, "1.1.1.1:443", "x" * 20))
        added = []
        panel.find_client = Mock(return_value=None)
        panel.check_identity = lambda record, *_: record["client"]
        account = dict(self.store.overview()[0][0], enabled=0, access_until=1)
        uuid, email = panel.identity(account["id"])

        def request(path, payload=None):
            if path == "clients/add":
                added.append(payload["client"])
            elif path == "clients/get/" + email:
                return {"client": {**added[0], "uuid": uuid}, "inboundIds": [1]}
            elif path.startswith("clients/links/"):
                return ["vless://" + uuid + "@1.1.1.1:443?security=reality"]
            elif path == "clients/list":
                return []
            else:
                self.fail(path)
        panel.request = request
        links = prepare_links(panel, [account])
        self.assertFalse(added[0]["enable"])
        self.assertEqual(added[0]["expiryTime"], 1000)
        self.assertIn(account["id"], links)

    def test_legacy_panel_revokes_deleted_accounts_without_issuing_new_clients(self):
        panel = Panel(PanelSettings("http://127.0.0.1:1234/", 1, "1.1.1.1:443", "x" * 20))
        accounts = [dict(self.store.overview()[0][0], access_until=1)]
        deleted = uuid4().hex
        panel.request = Mock(return_value=[{"email": panel.identity(accounts[0]["id"])[1]},
                                           {"email": panel.identity(deleted)[1]}, {"email": "manual-client"}])
        panel.remove = Mock(); panel.set_expiry = Mock()
        synchronize_retiring_panel(panel, accounts)
        panel.remove.assert_called_once_with(deleted)
        panel.set_expiry.assert_called_once_with(accounts[0]["id"], 1, enabled=False)

    def lifecycle(self):
        spec = importlib.util.spec_from_file_location("lifecycle", Path(__file__).parents[1] / "deploy/vpn-lifecycle.py")
        import sys
        sys.path.insert(0, str(Path(__file__).parents[1] / "deploy"))
        self.addCleanup(sys.path.pop, 0)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_all_nodes_receive_revocation_even_when_one_panel_fails(self):
        group = PanelGroup(PanelSettings("http://127.0.0.1:1234/", 1, "1.1.1.1:443", "x" * 20), self.temporary.name)
        secondary = Mock()
        secondary.remove.side_effect = PanelError("offline")
        with patch.object(group, "secondaries", return_value=[secondary]), patch.object(Panel, "remove") as primary:
            with self.assertRaises(PanelError):
                group.remove("a" * 32)
        primary.assert_called_once_with("a" * 32)
        secondary.remove.assert_called_once_with("a" * 32)

    def test_probe_template_rejects_other_protocols_and_preserves_reality_keys(self):
        module = self.lifecycle()
        with self.assertRaises(ValueError):
            module.client_template("https://example.com")
        template = module.client_template("vless://" + str(uuid4()) + "@1.1.1.1:443?security=reality&type=tcp&sni=example.com&pbk=public&sid=abcd&flow=xtls-rprx-vision")
        self.assertEqual(template["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"], "public")
        self.assertEqual(len(template["outbounds"]), 1)

    def test_managed_identity_accepts_only_configured_companion_inbounds(self):
        panel = Panel(PanelSettings("http://127.0.0.1:1234/", 4, "1.1.1.1:8080", "x" * 20,
                                    companion_inbounds=(1,)))
        account_id = uuid4().hex
        client_id, email = panel.identity(account_id)
        record = {"client": {"uuid": client_id, "email": email, "enable": True,
                              "expiryTime": 0, "limitIp": 0}, "inboundIds": [1, 4]}
        panel.find_client = Mock(return_value=record)
        panel.request = Mock(return_value=[f"vless://{client_id}@1.1.1.1:443?type=tcp",
                                           f"vless://{client_id}@1.1.1.1:8080?type=grpc"])
        self.assertIn(":8080?type=grpc#Connection", panel.issue(account_id))
        for inbound_ids in ([1], [4], [1, 4, 9], [4, 4]):
            with self.subTest(inbound_ids=inbound_ids), self.assertRaises(PanelError):
                panel.check_identity({**record, "inboundIds": inbound_ids}, client_id, email)
        record["inboundIds"] = [4, 1]
        panel.find_client.side_effect = [record, None]
        panel.remove(account_id)
        panel.request.assert_called_with("clients/del/" + email, {})

    def test_grpc_probe_preserves_service_and_authority(self):
        module = self.lifecycle()
        template = module.client_template("vless://" + str(uuid4())
            + "@1.1.1.1:8080?security=reality&type=grpc&sni=example.com&pbk=public&sid=abcd"
            + "&serviceName=connection&authority=example.com&mode=multi")
        stream = template["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["network"], "grpc")
        self.assertEqual(stream["grpcSettings"], {"serviceName": "connection", "authority": "example.com", "multiMode": True})

    def test_xhttp_probe_and_export_keep_certificate_verification_and_tested_fingerprint(self):
        module = self.lifecycle()
        uid = str(uuid4())
        link = f'vless://{uid}@1.1.1.1:2053?security=tls&type=xhttp&sni=1.1.1.1&fp=ios&path=%2Fconnect&mode=auto'
        config = module.client_template(link)
        stream = config['outbounds'][0]['streamSettings']
        self.assertEqual(stream['tlsSettings'], {'serverName': '1.1.1.1', 'fingerprint': 'ios', 'alpn': ['h2'], 'allowInsecure': False})
        self.assertEqual(stream['xhttpSettings'], {'path': '/connect', 'mode': 'auto'})
        self.assertNotIn('realitySettings', stream)
        with self.assertRaises(ValueError): module.client_template(link+'&allowInsecure=1')
        panel = Panel(PanelSettings('http://127.0.0.1:1234/', 6, '1.1.1.1:2053', 'x'*20))
        panel.inbound = Mock(return_value={'streamSettings': {'xhttpSettings': {'path': '/connect'}}})
        query = parse_qs(urlsplit(panel.stable_link(link+'&allowInsecure=1&flow=xtls-rprx-vision', 'Connection')).query)
        self.assertNotIn('allowInsecure', query)
        self.assertNotIn('flow', query)
        self.assertEqual(query['sni'], ['1.1.1.1'])
        self.assertEqual(query['fp'], ['ios'])

    def test_xhttp_replacement_uses_fresh_ip_certificate_and_keeps_tcp_companion(self):
        module = self.lifecycle()
        policy = Path(self.temporary.name)/'xhttp.json'
        policy.write_text(json.dumps({'network': 'xhttp', 'security': 'tls', 'port': 2053,
                                      'xhttpSettings': {'path': '/connect', 'mode': 'auto'}}))
        panel = Panel(PanelSettings('http://127.0.0.1:1234/', 1, '1.1.1.1:443', 'x'*20))
        base = {'id': 1, 'port': 443, 'protocol': 'vless', 'enable': True,
                'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {}}}
        panel.inbound = Mock(return_value=base)
        uid = str(uuid4()); created = []
        def request(instance, path, payload=None):
            if path == 'inbounds/list': return [base, *created]
            if path == 'inbounds/add': created.append({**payload, 'id': 6}); return
            if path == 'inbounds/get/6': return created[0]
            if path == 'clients/list': return [{'uuid': uid, 'email': 'monitor'}]
            if path == 'clients/monitor/attach': return
            if path == 'clients/links/monitor': return [f'vless://{uid}@1.1.1.1:2053?security=tls&type=xhttp&sni=1.1.1.1']
            self.fail(path)
        with patch.object(module, 'TRANSPORT_POLICY', policy), patch.object(Panel, 'request', request):
            primary, details = module.configure_transport(panel, {'ip': '1.1.1.1', 'link': f'vless://{uid}@1.1.1.1:443'})
        self.assertEqual(primary.inbound_ids, [6, 1])
        self.assertEqual(details['vpn_port'], 2053)
        stream = json.loads(created[0]['streamSettings'])
        self.assertEqual(stream['security'], 'tls')
        self.assertNotIn('realitySettings', stream)
        self.assertEqual(stream['tlsSettings']['certificates'][0]['certificateFile'], '/etc/nodeguard-vpn-tls/fullchain.pem')
        self.assertEqual(parse_qs(urlsplit(details['link']).query)['fp'], ['ios'])

    def test_restore_installs_new_ip_certificate_before_starting_restored_panel(self):
        self.lifecycle()  # Adds deploy to the module path.
        import vpn_recovery
        events = []; uid = str(uuid4())
        panel = Mock()
        panel.request.side_effect = lambda path: ([{'uuid': uid, 'email': 'monitor'}] if path == 'clients/list'
                                                  else [f'vless://{uid}@8.8.8.8:2053?security=tls&type=xhttp'])
        panel.link_matches.return_value = True
        panel.stable_link.side_effect = lambda link, label: link+'#'+label
        lifecycle = SimpleNamespace(
            bootstrap_node=lambda *args: (events.append('bootstrap') or {'panel_port': 1234}),
            ensure_transport_certificate=lambda *args: events.append('certificate'),
            ssh_args=lambda *args: ['ssh'], save=Mock(),
            run=lambda *args, **kwargs: (events.append('restore') or b'{"token":"new-token"}'),
            panel_connection=lambda *args: nullcontext(panel))
        old = {'ip': '1.1.1.1'}
        manifest = {'node': old, 'inbound': 6, 'companion_inbounds': [1, 4], 'vpn_port': 2053, 'probe_uuid': uid}
        with patch.object(vpn_recovery, 'validate_archive', return_value=(manifest, {'x-ui.db': b'snapshot'})):
            result = vpn_recovery.restore_panel(lifecycle, {'id': 'a'*32, 'service_id': 1,
                'spec': json.dumps({'old': old})}, '8.8.8.8', Path(self.temporary.name), b'archive')
        self.assertEqual(events, ['bootstrap', 'certificate', 'restore'])
        self.assertEqual(result['vpn_port'], 2053)

    def test_replacement_keeps_grpc_primary_and_tcp_companion(self):
        module = self.lifecycle()
        policy = Path(self.temporary.name) / "transport.json"
        policy.write_text(json.dumps({"network": "grpc", "port": 8080, "grpcSettings": {"serviceName": "connection"},
                                      "target": "example.com:443", "serverNames": ["example.com"]}))
        panel = Panel(PanelSettings("http://127.0.0.1:1234/", 1, "1.1.1.1:443", "x" * 20))
        base = {"id": 1, "port": 443, "protocol": "vless", "enable": True,
                "streamSettings": {"network": "tcp", "security": "reality",
                                   "realitySettings": {"privateKey": "new-node-key"}}}
        panel.inbound = Mock(return_value=base)
        uid = str(uuid4())
        target = {"id": 4, "port": 8080, "protocol": "vless", "enable": True,
                  "remark": "access-site-grpc", "streamSettings": {"network": "grpc"}}
        created = []
        def request(path, payload=None):
            if path == "inbounds/list": return [base, *([target] if created else [])]
            if path == "inbounds/add": created.append(payload); return
            if path == "clients/list": return [{"uuid": uid, "email": "monitor"}]
            if path == "clients/monitor/attach":
                self.assertEqual(payload, {"inboundIds": [4]}); return
            if path == "clients/links/monitor": return [f"vless://{uid}@1.1.1.1:8080?type=grpc"]
            self.fail(path)
        panel.request = request
        details = {"ip": "1.1.1.1", "inbound": 1, "link": f"vless://{uid}@1.1.1.1:443?type=tcp"}
        with patch.object(module, "TRANSPORT_POLICY", policy):
            primary, result = module.configure_transport(panel, details)
            self.assertEqual(primary.inbound_ids, [4, 1])
            self.assertEqual(result["vpn_port"], 8080)
            self.assertEqual(result["companion_inbounds"], [1])
            self.assertIn(":8080?type=grpc", result["link"])
            stream = json.loads(created[0]["streamSettings"])
            self.assertEqual(stream["realitySettings"]["privateKey"], "new-node-key")
            self.assertEqual(stream["grpcSettings"], {"serviceName": "connection"})
            self.assertEqual(base["streamSettings"]["network"], "tcp")
            same, repeated = module.configure_transport(primary, result)
            self.assertIs(same, primary)
            self.assertEqual(repeated, result)

    def test_failed_publication_restores_links_and_settings_and_can_retry(self):
        module = self.lifecycle()
        root = Path(self.temporary.name)
        env = root / "site.env"; env.write_text("SITE_XUI_URL='http://127.0.0.1:1/old/'\n")
        unit = root / "panel.service"; unit.write_text("old-unit")
        probes = root / "probes"; probes.mkdir()
        (probes / "notifications.json").write_text('{}')
        work = root / "job"; work.mkdir()
        before, _, revision = self.store.overview()
        links = {row["id"]: "new-link" for row in before}

        def save(path, value, **_):
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(json.dumps(value) if isinstance(value, dict) else value)
        def run(argv, **_):
            if argv[0] == "curl":
                raise subprocess.CalledProcessError(1, argv)
            return b""
        fake_pwd = SimpleNamespace(getpwnam=lambda _: SimpleNamespace(pw_uid=0, pw_gid=0))
        details = {"ip": "1.1.1.1", "panel_path": "/new/", "panel_port": 1234, "inbound": 1, "token": "x" * 24,
                   "link": "vless://" + str(uuid4()) + "@1.1.1.1:443?type=tcp&security=reality&sni=example.com&pbk=pub&sid=abcd"}
        with patch.object(module, "ENV", env), patch.object(module, "UNIT", unit), patch.object(module, "save", side_effect=save), \
             patch.object(module.Settings, "from_env", return_value=SimpleNamespace(data_dir=root, origin="https://example.com")), \
             patch.object(module, "run", side_effect=run), patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
             patch.object(module, "Panel"), patch.object(module, "panel_connection", return_value=nullcontext(Mock())), \
             patch.object(module, "prepare_links", return_value=links), patch.object(module.os, "chown", create=True), \
             patch.dict("sys.modules", {"pwd": fake_pwd}):
            for _ in range(2):
                with self.assertRaises(subprocess.CalledProcessError):
                    module.publish({"service_id": 123}, details, work)
                self.assertEqual(self.store.overview()[2], revision)
                self.assertEqual(env.read_text(), "SITE_XUI_URL='http://127.0.0.1:1/old/'\n")
                self.assertEqual(unit.read_text(), "old-unit")
                self.assertFalse((root / "vpn-publication-maintenance").exists())
                self.assertFalse((work / "publication.json").exists())
        self.assertEqual(len(list(work.glob('before-publication-*.sqlite3'))), 2)
