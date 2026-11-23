import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from app.auth import HASHER
from app.db import Store, connect
from app.delete_first import DeleteFirstControl, DeleteFirstRunner
from app.infrastructure import Infrastructure, InfrastructureError, Worker, load_config, timestamp
from app.main import create_app
from app.settings import Settings
from app.vdsina import ProviderError, ProviderValidationError, Vdsina

spec = importlib.util.spec_from_file_location('vpn_recovery_test', Path(__file__).resolve().parents[1]/'deploy/vpn_recovery.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class ReplacementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.path = self.root/'infrastructure.json'
        self.config = dict(mode='live', currency='USD', rub_per_unit='100', rate_valid_until=timestamp()+86400,
            monthly_limit=75000, fixed_monthly=28900, baseline_daily=700, external_server_count=1,
            required_ru_probes=1, nodes=[dict(id='EU1',ip='1.1.1.1',port=8080,service_id=12,datacenter_id=1,country='nl')],
            candidates=[dict(plan_id=1,group_id=1,template_id=1,ssh_key_id=1,datacenter_id=2,country='nl',daily_cost='0.07')],
            delete_first=dict(enabled=True,provider_reorder_confirmed=True,confirmation_reference='test-only support reply'))
        self.save(); self.store = Infrastructure(self.root,self.path); self.store.initialize()
        self.store.observe('EU1',dict(tcp=True,probes=[dict(region='ru',observer_ok=True,vpn_ok=True)]),load_config(self.path))
        self.control = DeleteFirstControl(self.store)
        self.api = Mock(); self.api.quote.return_value='0.07'; self.api.reconcile.return_value=None
        self.api.servers.return_value=[]; self.api.server_or_none.return_value=None; self.api.order.return_value=20
        self.journal = {}; self.ops=Mock()
        self.ops.journal.side_effect=lambda job:dict(self.journal)
        def save_journal(job,value):self.journal.clear();self.journal.update(value)
        self.ops.save_journal.side_effect=save_journal
        self.ops.provision.return_value={'ready':True,'port':8080}; self.ops.verify.return_value=True
        self.ops.publish.return_value={'published':True}
        self.runner=DeleteFirstRunner(self.store,self.api,self.ops)

    def save(self):self.path.write_text(json.dumps(self.config))
    def raw(self):
        with connect(self.store.path) as db:return dict(db.execute('SELECT * FROM jobs ORDER BY rowid DESC LIMIT 1').fetchone())
    def approve(self):
        identity=self.control.prepare('EU1')
        self.store.decide(identity,'approve',{'ip':'1.1.1.1','downtime':'yes'})
        return identity
    def tick(self):self.runner.advance(self.raw()); return self.raw()['status']
    def move(self,state,**values):
        with self.store.write() as db:self.store.update(db,self.raw()['id'],state,**values)
    def to_order(self):
        self.approve()
        self.assertEqual([self.tick() for _ in range(4)],['preparing','deleting','waiting_delete','ordering_ready'])
        self.api.delete.assert_called_once_with(12)
        self.api.order.assert_not_called()

    def test_no_support_receipt_is_needed_but_exact_acknowledgement_is_mandatory(self):
        self.config['delete_first'].update(provider_reorder_confirmed=False,confirmation_reference=''); self.save()
        identity=self.control.prepare('EU1')
        self.store.decide(identity,'approve',{'ip':'1.1.1.1','downtime':'yes'})
        self.assertEqual(self.raw()['status'],'approved')
        self.api.delete.assert_not_called(); self.api.order.assert_not_called()
        self.store.decide(identity,'cancel')
        self.config['delete_first'].update(provider_reorder_confirmed=True,confirmation_reference='support reply'); self.save()
        identity=self.control.prepare('EU1')
        for ack in (None,{'ip':'8.8.8.8','downtime':'yes'},{'ip':'1.1.1.1'}):
            with self.assertRaises(InfrastructureError):self.store.decide(identity,'approve',ack)

    def test_root_rechecks_gate_before_delete_even_for_preapproved_database_job(self):
        self.approve(); self.tick(); self.tick()
        self.config['delete_first']['enabled']=False; self.save()
        self.assertEqual(self.tick(),'attention')
        self.api.delete.assert_not_called(); self.api.order.assert_not_called()
        self.store.decide(self.raw()['id'],'cancel'); self.assertEqual(self.raw()['status'],'cancelled')

    def test_backup_failure_or_cancellation_never_deletes(self):
        self.approve(); self.tick(); self.ops.prepare.side_effect=ValueError('corrupt backup')
        self.assertEqual(self.tick(),'attention'); self.api.delete.assert_not_called()
        self.ops.release.assert_called()
        self.store.decide(self.raw()['id'],'cancel'); self.ops.prepare.side_effect=None
        self.approve(); self.tick()
        self.ops.prepare.side_effect=lambda job,cfg:self.store.decide(job['id'],'cancel')
        self.assertEqual(self.tick(),'cancelled'); self.api.delete.assert_not_called()

    def test_expiry_and_price_increase_prevent_destructive_step(self):
        self.approve(); self.tick(); self.tick()
        with self.store.write() as db:db.execute('UPDATE jobs SET expires=?',(timestamp()-1,))
        self.assertEqual(self.tick(),'attention'); self.api.delete.assert_not_called()

    def test_lost_delete_reply_reconciles_without_repeating_delete(self):
        self.approve(); self.tick(); self.tick(); self.api.delete.side_effect=ProviderError('timeout')
        self.assertEqual(self.tick(),'attention')
        self.store.decide(self.raw()['id'],'resume')
        self.api.server_or_none.return_value={'id':12,'status':'active'}
        self.assertEqual(self.tick(),'waiting_delete'); self.api.order.assert_not_called()
        self.api.server_or_none.return_value=None; self.api.servers.return_value=[{'id':12}]
        self.assertEqual(self.tick(),'waiting_delete'); self.api.order.assert_not_called()
        self.api.servers.return_value=[]
        self.assertEqual(self.tick(),'ordering_ready'); self.api.delete.assert_called_once_with(12)

    def test_restart_after_delete_intent_does_not_resend_or_require_unexpired_approval(self):
        self.approve(); self.tick(); self.tick(); self.journal['delete_intent']=timestamp()
        with self.store.write() as db:db.execute('UPDATE jobs SET expires=?',(timestamp()-1,))
        self.assertEqual(self.tick(),'waiting_delete'); self.api.delete.assert_not_called()

    def test_lost_order_reply_and_runner_restart_never_duplicate_order(self):
        self.to_order(); self.api.order.side_effect=ProviderError('response lost')
        self.assertEqual(self.tick(),'uncertain')
        self.assertEqual(self.tick(),'uncertain')
        self.api.reconcile.return_value=20
        self.assertEqual(self.tick(),'provisioning'); self.api.order.assert_called_once()
        self.assertEqual(self.raw()['service_id'],20)

    def test_persisted_order_intent_without_response_is_reconciled_only(self):
        self.to_order(); self.journal['order_intent']=timestamp()
        self.assertEqual(self.tick(),'uncertain'); self.api.order.assert_not_called()

    def test_explicit_validation_rejection_requires_manual_resume(self):
        self.to_order(); self.api.order.side_effect=ProviderValidationError('provider_tariff_limit')
        self.assertEqual(self.tick(),'attention'); self.tick(); self.api.order.assert_called_once()
        self.store.decide(self.raw()['id'],'resume'); self.api.order.side_effect=None
        self.assertEqual(self.tick(),'provisioning'); self.assertEqual(self.api.order.call_count,2)

    def test_new_price_or_budget_failure_never_orders_more_expensive_server(self):
        self.to_order(); self.api.quote.return_value='0.50'
        self.assertEqual(self.tick(),'attention'); self.api.order.assert_not_called()

    def test_same_ip_and_provisioning_failure_resume_existing_service(self):
        self.to_order(); self.tick()
        self.api.server.return_value={'id':20,'name':'asmove-'+self.raw()['id'],'status':'active'}
        self.api.address.return_value='1.1.1.1'
        self.assertEqual(self.tick(),'attention'); self.ops.provision.assert_not_called()
        self.store.decide(self.raw()['id'],'resume'); self.api.address.return_value='8.8.8.8'
        self.ops.provision.side_effect=OSError('SSH unavailable')
        self.assertEqual(self.tick(),'attention'); self.store.decide(self.raw()['id'],'resume')
        self.ops.provision.side_effect=None
        self.assertEqual(self.tick(),'verifying'); self.api.order.assert_called_once()

    def test_complete_rehearsal_orders_once_verifies_before_publication_and_releases_lock(self):
        self.to_order(); self.assertEqual(self.tick(),'provisioning')
        self.api.server.return_value={'id':20,'name':'asmove-'+self.raw()['id'],'status':'active'}
        self.api.address.return_value='8.8.8.8'
        self.assertEqual(self.tick(),'verifying'); self.ops.publish.assert_not_called()
        self.ops.verify.return_value=False
        self.assertEqual(self.tick(),'verifying'); self.ops.publish.assert_not_called()
        self.ops.verify.return_value=True
        self.assertEqual(self.tick(),'publishing'); self.assertEqual(self.tick(),'ready')
        self.assertEqual(self.raw()['reserved'],0); self.ops.finish.assert_called_once(); self.ops.release.assert_called_once()
        with connect(self.store.path) as db:self.assertEqual(db.execute('SELECT amount FROM replacement_charges').fetchone()[0],700)
        self.api.order.assert_called_once(); self.api.delete.assert_called_once()

    def test_simulation_never_calls_provider_or_deployment(self):
        self.config['mode']='simulate';self.save(); self.approve()
        self.assertEqual(self.tick(),'simulated'); self.api.delete.assert_not_called(); self.api.order.assert_not_called()
        self.ops.prepare.assert_not_called()

    def test_monitor_proposes_one_draft_per_incident_without_provider_confirmation(self):
        self.config['delete_first'].update(auto_propose=True,provider_reorder_confirmed=False,confirmation_reference='');self.save()
        worker=Worker(self.store,self.api)
        evidence=dict(tcp=False,probes=[dict(region='ru',observer_ok=True,vpn_ok=False)])
        with patch.object(worker,'probe',return_value=evidence):
            for _ in range(6):worker.run()
            identity=self.raw()['id'];self.assertEqual(self.raw()['status'],'pending')
            self.store.decide(identity,'cancel');worker.run()
        with connect(self.store.path) as db:self.assertEqual(db.execute('SELECT count(*) FROM jobs').fetchone()[0],1)
        self.api.delete.assert_not_called();self.api.order.assert_not_called()

    def test_admin_approval_and_order_ignore_caps_stale_rate_and_prior_paid_replacements(self):
        self.config.update(monthly_limit=1,max_orders=0,rate_valid_until=0);self.save()
        for index in range(5):
            identity=self.control.prepare('EU1')
            self.store.decide(identity,'approve',{'ip':'1.1.1.1','downtime':'yes'})
            with self.store.write() as db:self.store.update(db,identity,'ready',service_id=100+index,reserved=0)
        with self.store.write() as db:db.execute("UPDATE nodes SET observed_at=0,state='unknown'")
        self.to_order();self.assertEqual(self.tick(),'provisioning');self.api.order.assert_called_once()

    def test_real_policy_changes_still_invalidate_an_old_draft(self):
        identity=self.control.prepare('EU1');self.config['candidates'][0]['datacenter_id']=3;self.save()
        with self.assertRaises(InfrastructureError):self.store.decide(identity,'approve',{'ip':'1.1.1.1','downtime':'yes'})
        self.api.delete.assert_not_called()

    def test_admin_check_and_prepare_are_protected_and_approval_is_available_without_support(self):
        self.config['delete_first'].update(provider_reorder_confirmed=False,confirmation_reference='');self.save()
        settings=Settings('primary','https://primary.example',self.root,b's'*32,b'k'*32,HASHER.hash('test-password'),infrastructure_config=self.path)
        Store(self.root).initialize(True,settings.access_key_id)
        with TestClient(create_app(settings),base_url=settings.origin) as client:
            self.assertEqual(client.post('/admin/infrastructure/EU1/check-delete-first',data={'csrf':'bad'}).status_code,403)
            csrf=re.search('name="csrf" value="([a-f0-9]+)"',client.get('/admin/login').text)[1]
            client.post('/admin/login',data={'csrf':csrf,'password':'test-password'},headers={'Origin':settings.origin})
            page=client.get('/admin/infrastructure');csrf=re.search('name="csrf" value="([a-f0-9]+)"',page.text)[1]
            self.assertEqual(client.post('/admin/infrastructure/EU1/delete-first',data={'csrf':'wrong'},headers={'Origin':settings.origin}).status_code,403)
            for action in ('check-delete-first','delete-first'):
                result=client.post('/admin/infrastructure/EU1/'+action,data={'csrf':csrf},headers={'Origin':settings.origin},follow_redirects=False)
                self.assertEqual(result.status_code,303)
            page=client.get('/admin/infrastructure')
            self.assertNotIn(' disabled>Подтвердить удаление и заказ',page.text)
            self.assertNotRegex(page.text, r'750\s*(?:₽|руб)');self.assertNotIn('Резерв бюджета',page.text)
            result=client.post('/admin/infrastructure/'+self.raw()['id']+'/approve',data={'csrf':csrf,'delete_ip':'1.1.1.1','accept_downtime':'yes'},headers={'Origin':settings.origin})
            self.assertEqual(result.status_code,200);self.assertEqual(self.raw()['status'],'approved')
            self.api.delete.assert_not_called()


class RecoveryArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.node=dict(id='EU1',ip='1.1.1.1',service_id=12)
        path=self.root/'x-ui.db'
        with sqlite3.connect(path) as db:
            db.executescript('CREATE TABLE users(id,password); CREATE TABLE settings(key,value);'
                'CREATE TABLE clients(id,email,uuid); CREATE TABLE client_inbounds(client_id,inbound_id);'
                'CREATE TABLE inbounds(id,listen,share_addr,stream_settings);'
                "INSERT INTO users VALUES(1,'unchanged-admin-hash');"
                "INSERT INTO clients VALUES(1,'access-site-managed','managed-uuid'),(2,'manual-client','manual-uuid');"
                'INSERT INTO client_inbounds VALUES(1,4),(2,4);')
            db.executemany('INSERT INTO settings VALUES (?,?)',[('webListen','1.1.1.1'),('webPort','46065'),('webDomain','1.1.1.1'),('webBasePath','/same-secret-path/'),('webCertFile','old-cert')])
            stream=json.dumps(dict(network='grpc',realitySettings=dict(privateKey='unchanged-key',shortIds=['unchanged-shortid']),externalProxy=[dict(dest='1.1.1.1',port=8080)]))
            db.execute('INSERT INTO inbounds VALUES (4,?,?,?)',('1.1.1.1','1.1.1.1',stream))
        store=Store(self.root);store.initialize(True,'a'*64)
        self.files={'x-ui.db':path.read_bytes(),'accounts.sqlite3':store.data.read_bytes()}
        self.manifest=dict(version=1,node=self.node,panel_clients=2,created_at=timestamp(),account_revision=0)

    def test_whole_sqlite_snapshot_retains_manual_clients_and_validates_target(self):
        data=recovery.encode_archive(self.files,self.manifest)
        manifest,files=recovery.validate_archive(data,self.node)
        self.assertEqual(manifest['panel_clients'],2);self.assertEqual(files,self.files)
        with self.assertRaises(ValueError):recovery.validate_archive(data,{**self.node,'service_id':13})

    def test_corrupt_database_and_count_mismatch_are_rejected(self):
        for files,manifest in (({**self.files,'x-ui.db':b'bad sqlite'},self.manifest),(self.files,{**self.manifest,'panel_clients':1})):
            with self.assertRaises((ValueError,sqlite3.DatabaseError)):recovery.validate_archive(recovery.encode_archive(files,manifest))

    def test_traversal_and_checksum_modification_are_rejected(self):
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
            item=tarfile.TarInfo('../outside');item.size=1;archive.addfile(item,io.BytesIO(b'x'))
        with self.assertRaises(ValueError):recovery.validate_archive(buffer.getvalue())
        data=recovery.encode_archive(self.files,self.manifest);buffer=io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as source,tarfile.open(fileobj=buffer,mode='w:gz') as target:
            for item in source:
                body=source.extractfile(item).read()
                if item.name=='x-ui.db':body=body[:-1]+bytes([body[-1]^1])
                target.addfile(item,io.BytesIO(body))
        with self.assertRaisesRegex(ValueError,'checksum'):recovery.validate_archive(buffer.getvalue())

    def test_restore_changes_endpoint_only_keeps_all_clients_keys_and_admin_credentials(self):
        with sqlite3.connect(self.root/'x-ui.db') as db:
            before={t:db.execute('SELECT * FROM '+t).fetchall() for t in ('users','clients','client_inbounds')}
            recovery.adapt_database(db,'1.1.1.1','8.8.8.8',12345)
            for table,rows in before.items():self.assertEqual(db.execute('SELECT * FROM '+table).fetchall(),rows)
            settings=dict(db.execute('SELECT key,value FROM settings'))
            self.assertEqual(settings['webListen'],'127.0.0.1');self.assertEqual(settings['webPort'],'12345')
            self.assertEqual(settings['webBasePath'],'/same-secret-path/');self.assertEqual(settings['webCertFile'],'')
            row=db.execute('SELECT listen,share_addr,stream_settings FROM inbounds').fetchone()
            self.assertEqual(row[:2],('8.8.8.8','8.8.8.8'))
            stream=json.loads(row[2]);self.assertEqual(stream['realitySettings']['privateKey'],'unchanged-key')
            self.assertEqual(stream['externalProxy'][0]['dest'],'8.8.8.8')

    def test_restored_tls_links_use_new_ip_without_changing_certificate_paths(self):
        with sqlite3.connect(self.root/'x-ui.db') as db:
            stream = {'network': 'xhttp', 'security': 'tls', 'tlsSettings': {
                'settings': {'serverName': '1.1.1.1'},
                'certificates': [{'certificateFile': '/etc/asmove-vpn-tls/fullchain.pem'}]}}
            db.execute('UPDATE inbounds SET stream_settings=?', (json.dumps(stream),))
            recovery.adapt_database(db, '1.1.1.1', '8.8.8.8', 12345)
            actual = json.loads(db.execute('SELECT stream_settings FROM inbounds').fetchone()[0])
            self.assertEqual(actual['tlsSettings']['settings']['serverName'], '8.8.8.8')
            self.assertEqual(actual['tlsSettings']['certificates'], stream['tlsSettings']['certificates'])

    def test_readonly_backup_endpoint_rejects_arbitrary_commands(self):
        for command in ('','python3 -','rm -rf /'):
            result=subprocess.run([sys.executable,'-c',recovery.backup_program().decode()],
                                  env={**os.environ,'SSH_ORIGINAL_COMMAND':command},capture_output=True)
            self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b'')

    def test_wal_restore_persists_endpoint_changes_before_atomic_rename(self):
        source=self.root/'x-ui.db'
        db=sqlite3.connect(source)
        db.execute('PRAGMA journal_mode=WAL');db.commit();db.close()
        staged=self.root/'staged.db'
        recovery.prepare_database(staged,source.read_bytes(),'1.1.1.1','8.8.8.8',12345)
        published=self.root/'published.db';os.replace(staged,published)
        db=sqlite3.connect(published)
        try:
            values=dict(db.execute('SELECT key,value FROM settings'))
            self.assertEqual(values['webListen'],'127.0.0.1')
            self.assertEqual(values['webPort'],'12345')
            self.assertEqual(values['webCertFile'],'')
            self.assertEqual(db.execute('SELECT count(*) FROM clients').fetchone()[0],2)
        finally:db.close()


class ProviderSafetyTests(unittest.TestCase):
    def test_order_rechecks_live_exact_price_and_never_posts_a_different_tariff(self):
        api=Vdsina();candidate=dict(plan_id=36,group_id=2,datacenter_id=5,country='nl',template_id=23,ssh_key_id=1,daily_cost='0.07')
        for offered in ('0.05','0.50'):
            def request(method,path,data=None):
                self.assertNotEqual(method,'POST')
                return {'server-plan/2':[{'id':36,'active':True,'enable':True,'period':'day','cost':offered}],
                        'datacenter':[{'id':5,'active':True,'country':'nl'}],
                        'template':[{'id':23,'active':True,'ssh-key':True,'server-plan':[36]}]}[path]
            with patch.object(api,'request',side_effect=request):
                with self.assertRaisesRegex(ProviderValidationError,'price_mismatch'):api.order('test',candidate)

    def test_preflight_quota_excludes_only_the_exact_retiring_service(self):
        api=Vdsina();candidate=dict(plan_id=36,group_id=2,datacenter_id=5,country='nl',template_id=23,max_existing=1,daily_cost='0.07')
        inventory=[{'id':12,'server-plan':{'id':36}}]
        def request(method,path,data=None):
            return {'server-plan/2':[{'id':36,'active':True,'enable':True,'period':'day','cost':'0.07'}],
                    'datacenter':[{'id':5,'active':True,'country':'nl'}],
                    'template':[{'id':23,'active':True,'ssh-key':True,'server-plan':[36]}],
                    'account.balance':{'real':'20'},'server':inventory}[path]
        with patch.object(api,'request',side_effect=request):
            with self.assertRaises(ProviderValidationError):api.quote(candidate)
            self.assertEqual(str(api.quote(candidate,retiring_service_id=12)),'0.07')
            inventory.append({'id':13,'server-plan':{'id':36}})
            with self.assertRaises(ProviderValidationError):api.quote(candidate,retiring_service_id=12)

    def test_only_exact_404_counts_as_deleted(self):
        api=Vdsina(direct=True)
        for error in ('provider_http_401','provider_http_403','provider_unavailable'):
            with patch.object(api,'server',side_effect=ProviderError(error)),self.assertRaises(ProviderError):api.server_or_none(12)
        with patch.object(api,'server',side_effect=ProviderError('provider_http_404')):self.assertIsNone(api.server_or_none(12))

    def test_direct_api_never_uses_failed_vpn_proxy(self):
        response=Mock(status=200);response.read.return_value=b'{"status":"ok","data":{}}'
        with patch.dict(os.environ,{'VDSINA_API_TOKEN':'test-only','VDSINA_SOCKS_PROXY':'127.0.0.1:1'}),patch('app.vdsina.SocksHTTPSConnection') as proxy,patch('app.vdsina.http.client.HTTPSConnection') as direct:
            direct.return_value.getresponse.return_value=response
            Vdsina(direct=True).request('GET','account.balance');proxy.assert_not_called();direct.assert_called_once()

    def test_delete_targets_only_explicit_positive_service_id(self):
        api=Vdsina()
        with patch.object(api,'request') as request:
            for value in (0,-1,True,'12'):
                with self.assertRaises(ValueError):api.delete(value)
            api.delete(12);request.assert_called_once_with('DELETE','server/12')


if __name__=='__main__':unittest.main()
