import json
import re
import unittest
from unittest.mock import patch

import test_delete_first as fixtures
from app import automation
from app.db import connect
from app.infrastructure import load_config, timestamp
from app.vdsina import ProviderError


class AutomationTests(unittest.TestCase):
    setUp = fixtures.ReplacementTests.setUp
    save = fixtures.ReplacementTests.save
    raw = fixtures.ReplacementTests.raw
    tick = fixtures.ReplacementTests.tick

    def enable(self, **values):
        return automation.save(self.store, {'enabled': True, **values}, accept_downtime=True)

    def failures(self, *, tcp=False, healthy=False, observer=True, targets=2):
        evidence = {'tcp': tcp, 'probes': [{'region': 'ru', 'observer_ok': observer,
                                           'vpn_ok': healthy, 'targets_total': targets}]}
        current = timestamp()
        for age in (180, 120, 60, 0):
            with patch('app.infrastructure.timestamp', return_value=current-age):
                self.store.observe('EU1', evidence, load_config(self.path))
        self.ops.automation_probe.return_value = evidence

    def jobs(self):
        with connect(self.store.path) as db:
            return db.execute('SELECT count(*) FROM jobs').fetchone()[0]

    def test_default_is_manual_and_enabling_requires_explicit_downtime_consent(self):
        with self.assertRaises(ValueError):
            automation.save(self.store, {'enabled': True})
        self.failures()
        automation.maybe_start(self.store, self.ops)
        self.assertEqual(self.jobs(), 0)
        self.ops.check.assert_not_called()

    def test_sustained_failure_authorizes_same_incident_once_and_retains_gates(self):
        self.enable(); self.failures()
        automation.maybe_start(self.store, self.ops)
        job = self.raw()
        self.assertEqual(job['status'], 'approved')
        spec = json.loads(job['spec'])
        self.assertTrue(spec['automatic']); self.assertEqual(spec['approved_ip'], '1.1.1.1')
        automation.maybe_start(self.store, self.ops)
        self.assertEqual(self.jobs(), 1)
        self.assertEqual([self.tick() for _ in range(4)], ['preparing','deleting','waiting_delete','ordering_ready'])
        self.ops.before_delete.assert_called_once()
        self.api.delete.assert_called_once_with(12)

    def test_missing_observer_single_target_and_partial_recovery_never_authorize(self):
        for options in ({'observer': False}, {'targets': 1}, {'healthy': True}):
            self.enable(); self.failures(**options)
            automation.maybe_start(self.store, self.ops)
            self.assertEqual(self.jobs(), 0)
        self.api.delete.assert_not_called()

    def test_short_and_stale_failure_do_not_authorize(self):
        self.enable(); self.failures()
        with self.store.write() as db:
            db.execute('UPDATE automation_observations SET since_at=?', (timestamp()-10,))
        automation.maybe_start(self.store,self.ops)
        self.assertEqual(self.jobs(), 0)
        self.failures()
        with self.store.write() as db:
            db.execute('UPDATE automation_observations SET last_at=?', (timestamp()-1000,))
        automation.maybe_start(self.store,self.ops)
        self.assertEqual(self.jobs(), 0)

    def test_tcp_rule_keeps_a_working_port_from_triggering_replacement(self):
        self.enable(trigger='tcp_and_vpn_failed'); self.failures(tcp=True)
        automation.maybe_start(self.store,self.ops)
        self.assertEqual(self.jobs(), 0)

    def test_disabling_policy_or_recovery_after_approval_prevents_delete(self):
        self.enable(); self.failures(); automation.maybe_start(self.store,self.ops)
        self.tick(); self.tick()
        automation.save(self.store, {'enabled': False})
        self.assertEqual(self.tick(), 'attention')
        self.api.delete.assert_not_called()

    def test_fresh_probe_and_archive_must_pass_before_authorization(self):
        self.enable(); self.failures()
        self.ops.check.side_effect=ValueError('bad archive')
        with self.assertRaises(ValueError):
            automation.maybe_start(self.store,self.ops)
        self.assertEqual(self.jobs(),0)
        self.api.delete.assert_not_called()

    def test_daily_limit_blocks_next_automatic_incident(self):
        self.enable(max_per_day=1); self.failures(); automation.maybe_start(self.store,self.ops)
        with self.store.write() as db:
            self.store.update(db,self.raw()['id'],'ready',reserved=0)
            db.execute('UPDATE jobs SET created=?',(timestamp()-7200,))
        automation.maybe_start(self.store,self.ops)
        self.assertEqual(self.jobs(),1)

    def test_automatic_unknown_order_never_repeats_post(self):
        self.enable(); self.failures(); automation.maybe_start(self.store,self.ops)
        for _ in range(4): self.tick()
        self.api.order.side_effect=ProviderError('lost reply')
        self.assertEqual(self.tick(),'uncertain')
        self.assertEqual(self.tick(),'uncertain')
        self.api.order.assert_called_once()
        self.api.reconcile.return_value=20
        self.assertEqual(self.tick(),'provisioning')

    def test_invalid_thresholds_are_rejected(self):
        for change in ({'failures':1}, {'failure_seconds':0}, {'cooldown_seconds':0},
                       {'max_per_day':False}, {'trigger':'port_only'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                automation.validate(change)

    def test_admin_settings_require_authentication_csrf_and_downtime_consent(self):
        from fastapi.testclient import TestClient
        from app.auth import HASHER
        from app.db import Store
        from app.main import create_app
        from app.settings import Settings
        settings=Settings('primary','https://primary.example',self.root,b's'*32,b'k'*32,
                          HASHER.hash('admin-password'),infrastructure_config=self.path)
        Store(self.root).initialize(True,settings.access_key_id)
        endpoint='/admin/infrastructure/settings/automation'
        with TestClient(create_app(settings),base_url=settings.origin,follow_redirects=False) as client:
            self.assertEqual(client.post(endpoint,data={'enabled':'yes'}).status_code,403)
            token=re.search('name="csrf" value="([a-f0-9]+)"',client.get('/admin/login').text)[1]
            client.post('/admin/login',data={'csrf':token,'password':'admin-password'},headers={'Origin':settings.origin})
            page=client.get('/admin/infrastructure')
            token=re.search('name="csrf" value="([a-f0-9]+)"',page.text)[1]
            fields=dict(enabled='yes',trigger='vpn_failed',failures='3',failure_seconds='180',
                        cooldown_seconds='3600',max_per_day='2')
            self.assertEqual(client.post(endpoint,data=fields,headers={'Origin':settings.origin}).status_code,403)
            fields['csrf']=token
            self.assertNotEqual(client.post(endpoint,data=fields,headers={'Origin':settings.origin}).status_code,303)
            with connect(self.store.path) as db: self.assertFalse(automation.read(db)['enabled'])
            fields['accept_automatic_downtime']='yes'
            self.assertEqual(client.post(endpoint,data=fields,headers={'Origin':settings.origin}).status_code,303)
            with connect(self.store.path) as db: self.assertTrue(automation.read(db)['enabled'])

    def test_owner_disables_during_final_preflight_and_delete_is_prevented(self):
        self.enable(); self.failures(); automation.maybe_start(self.store,self.ops)
        self.tick(); self.tick()
        self.ops.before_delete.side_effect=lambda job,cfg: automation.save(self.store,{'enabled':False})
        self.assertEqual(self.tick(),'attention')
        self.api.delete.assert_not_called()

    def test_cooldown_uses_authorization_time_of_an_old_pending_job(self):
        self.enable(); self.failures(); automation.maybe_start(self.store,self.ops)
        with self.store.write() as db:
            db.execute("UPDATE jobs SET created=?, status='ready',reserved=0",(timestamp()-7200,))
        automation.maybe_start(self.store,self.ops)
        self.assertEqual(self.jobs(),1)
