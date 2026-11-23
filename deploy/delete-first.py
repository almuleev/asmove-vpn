"""Privileged delete-first runner. Rehearsals and snapshots never delete/order VPS."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from decimal import Decimal

sys.path.insert(0,str(Path.cwd()))
sys.path.insert(0,str(Path(__file__).parent))
from app.db import Store,connect
from app.delete_first import DeleteFirstControl,DeleteFirstRunner,STAGES
from app.infrastructure import Infrastructure,InfrastructureError,Worker,load_config,timestamp
from app.settings import Settings
from app.sync import snapshot
from app.vdsina import Vdsina,REQUIRED_DAILY_COST
import vpn_recovery as recovery


def lifecycle_module():
    spec=importlib.util.spec_from_file_location('nodeguard_lifecycle',Path(__file__).with_name('vpn-lifecycle.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class Operations:
    def __init__(self,settings,control,provider,lifecycle):
        self.settings,self.control,self.provider,self.lifecycle=settings,control,provider,lifecycle
        self.store=Store(settings.data_dir)

    def directory(self,job):
        if not re.fullmatch(r'[a-f0-9]{32}',job['id']):raise InfrastructureError('invalid_job_id')
        path=recovery.PRIVATE/'jobs'/job['id'];path.mkdir(mode=0o700,parents=True,exist_ok=True)
        if path.is_symlink():raise InfrastructureError('invalid_job_directory')
        return path

    def journal(self,job):
        path=self.directory(job)/'journal.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def save_journal(self,job,value):
        recovery.atomic(self.directory(job)/'journal.json',json.dumps(value).encode())

    def effective_node(self,node_id):
        config=load_config(self.control.config_path)
        return DeleteFirstControl(self.control).node(config,node_id)

    def validate_old(self,job,server):
        old=json.loads(job['spec'])['old'];node=self.effective_node(old['id'])
        if (node['service_id']!=old['service_id'] or node['ip']!=old['ip']
                or node['country']=='ru' or server['id']!=old['service_id']
                or Vdsina.address(server)!=old['ip']
                or server.get('datacenter',{}).get('id')!=old['datacenter_id']):
            raise InfrastructureError('old_service_identity_mismatch')
        if server.get('server-plan',{}).get('id')!=json.loads(job['spec'])['candidate']['plan_id']:
            raise InfrastructureError('old_tariff_changed')

    def latest(self,node):
        return recovery.PRIVATE/'backups'/node['id']/(str(node['service_id'])+'.tar.gz')

    def backup(self,node,config,*,force=False):
        path=self.latest(node)
        if path.exists():
            try:
                manifest,_=recovery.validate_archive(path.read_bytes(),node)
                if not force and timestamp()-manifest['created_at']<config['delete_first']['backup_interval']:
                    return path,manifest
            except (ValueError,KeyError,OSError):
                pass  # A corrupt cache may be replaced by a fresh verified snapshot.
        try:
            data=recovery.capture(self.lifecycle,node,self.settings,self.store)
            manifest,_=recovery.validate_archive(data,node)
            recovery.atomic(path,data)
            return path,manifest
        except Exception:
            if not path.exists():raise
            manifest,_=recovery.validate_archive(path.read_bytes(),node)
            if timestamp()-manifest['created_at']>config['delete_first']['backup_max_age']:raise
            return path,manifest

    def check(self,node_id,config,*,force=False):
        node=self.effective_node(node_id)
        candidates=sorted(config['candidates'],key=lambda row:row['datacenter_id']==node['datacenter_id'])
        candidate=next(row for row in candidates if row['daily_cost'] and
                       Decimal(str(row['daily_cost']))==REQUIRED_DAILY_COST)
        server=self.provider.server(node['service_id'])
        synthetic={'spec':json.dumps({'old':node,'candidate':candidate})}
        self.validate_old(synthetic,server)
        self.provider.quote(candidate,retiring_service_id=node['service_id'])
        path,manifest=self.backup(node,config,force=force)
        if timestamp()-manifest['created_at']>config['delete_first']['backup_max_age']:
            raise InfrastructureError('backup_too_old')
        return {'ready':True,'api_direct':True,'archive_valid':True,'backup_at':manifest['created_at'],
                'panel_clients':manifest['panel_clients'],'account_revision':manifest['account_revision'],
                'old_ip':node['ip'],'old_service_id':node['service_id'],'daily_cost':'0.07'}

    def prepare(self,job,config):
        spec=json.loads(job['spec']);node=spec['old']
        self.check(node['id'],config,force=True)
        # Only freeze writes after a usable archive and independent API are verified.
        marker=self.settings.data_dir/'vpn-publication-maintenance'
        recovery.atomic(marker,('delete-first:'+job['id']).encode(),0o644)
        # Re-snapshot after freezing cabinet writes; the previous check proved access.
        source,_=self.backup(node,config,force=True)
        data=source.read_bytes();manifest,_=recovery.validate_archive(data,node)
        directory=self.directory(job);recovery.atomic(directory/'recovery.tar.gz',data)
        snapshot(self.store,directory/('accounts-'+str(time.time_ns())+'.sqlite3'))
        self.save_journal(job,{'old':node,'archive_sha256':hashlib.sha256(data).hexdigest(),
                               'backup_at':manifest['created_at'],'prepared_at':timestamp()})

    def before_delete(self,job,config):
        spec=json.loads(job['spec']);journal=self.journal(job)
        data=(self.directory(job)/'recovery.tar.gz').read_bytes()
        manifest,_=recovery.validate_archive(data,spec['old'])
        if (hashlib.sha256(data).hexdigest()!=journal.get('archive_sha256')
                or timestamp()-manifest['created_at']>config['delete_first']['backup_max_age']):
            raise InfrastructureError('backup_too_old_or_changed')
        self.validate_old(job,self.provider.server(spec['old']['service_id']))
        price=self.provider.quote(spec['candidate'],retiring_service_id=spec['old']['service_id'])
        from decimal import Decimal
        if Decimal(str(price))!=REQUIRED_DAILY_COST:
            raise InfrastructureError('price_changed_before_deletion')

    def provision(self,job,ip):
        directory=self.directory(job)
        data=(directory/'recovery.tar.gz').read_bytes()
        if hashlib.sha256(data).hexdigest()!=self.journal(job)['archive_sha256']:
            raise InfrastructureError('recovery_archive_changed')
        recovery.restore_panel(self.lifecycle,job,ip,directory,data)
        return self.lifecycle.provision(job,ip,directory)

    def verify(self,job,ip):
        spec=json.loads(job['spec']);config=load_config(self.control.config_path)
        candidate={**spec['old'],'ip':ip,'port':spec.get('vpn_port',spec['old']['port']),'service_id':job['service_id']}
        evidence=Worker(self.control,provider=self.provider).probe(candidate)
        valid=[p for p in evidence['probes'] if p['region']=='ru' and p['observer_ok'] and p['vpn_ok']]
        if len(valid)<config['required_ru_probes']:return False
        details=json.loads((self.directory(job)/'node.json').read_text())
        with self.lifecycle.panel_connection(details,job['service_id']) as panel:
            self.lifecycle.prepare_links(panel,self.store.overview()[0])
        return True

    def publish(self,job,ip):
        directory=self.directory(job);details=json.loads((directory/'node.json').read_text())
        try:return self.lifecycle.publish(job,details,directory)
        finally:
            recovery.atomic(self.settings.data_dir/'vpn-publication-maintenance',('delete-first:'+job['id']).encode(),0o644)

    def recover_publication(self,job):
        directory=self.directory(job)
        if (directory/'publication.json').exists():
            self.lifecycle.recover_directory(directory,self.store)
            if self.journal(job).get('delete_intent'):
                recovery.atomic(self.settings.data_dir/'vpn-publication-maintenance',('delete-first:'+job['id']).encode(),0o644)

    def finish(self,job,ip):
        from decimal import Decimal,ROUND_CEILING
        spec=json.loads(job['spec']);config=json.loads(self.control.config_path.read_text())
        node=next(n for n in config['nodes'] if n['id']==job['node'])
        if node['service_id'] not in (spec['old']['service_id'],job['service_id']):raise InfrastructureError('published_node_changed')
        node.update(ip=ip,service_id=job['service_id'],port=spec.get('vpn_port',spec['old']['port']),
                    datacenter_id=spec['candidate']['datacenter_id'],country=spec['candidate']['country'],native_daily_cost=spec['candidate']['daily_cost'])
        rate=Decimal(str(config['rub_per_unit']))
        config['baseline_daily']=sum(int((Decimal(str(n['native_daily_cost']))*rate*100).to_integral_value(rounding=ROUND_CEILING)) for n in config['nodes'])
        previous=self.control.config_path.stat();recovery.atomic(self.control.config_path,json.dumps(config,indent=2).encode(),previous.st_mode&0o777)
        os.chown(self.control.config_path,previous.st_uid,previous.st_gid)
        with self.control.write() as db:db.execute('DELETE FROM overrides WHERE node=?',(job['node'],))

    def release(self,job):
        marker=self.settings.data_dir/'vpn-publication-maintenance'
        if marker.exists() and marker.read_text()=='delete-first:'+job['id']:marker.unlink()


def main():
    import fcntl
    os.umask(0o077)
    settings=Settings.from_env()
    if settings.role!='primary' or not settings.infrastructure_config:return
    config=load_config(settings.infrastructure_config)
    if not config['delete_first']['enabled']:return
    recovery.PRIVATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (recovery.PRIVATE/'runner.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        control=Infrastructure(settings.data_dir,settings.infrastructure_config);control.initialize()
        provider=Vdsina(config.get('api_host','userapi.vdsina.com'),direct=True)
        ops=Operations(settings,control,provider,lifecycle_module());runner=DeleteFirstRunner(control,provider,ops)
        with connect(control.path,'ro') as db:
            jobs=[dict(r) for r in db.execute('SELECT * FROM jobs WHERE json_extract(spec,\'$.delete_first\')=1')]
            checks={r['node']:dict(r) for r in db.execute('SELECT * FROM replacement_checks')}
        busy={j['node'] for j in jobs if j['status'] in STAGES or (j['status']=='attention' and ops.journal(j).get('delete_intent'))}
        for node in config['nodes']:
            if node['id'] in busy:continue
            requested=checks.get(node['id'])
            due=not ops.latest(ops.effective_node(node['id'])).exists()
            if not due:
                try:
                    manifest,_=recovery.validate_archive(ops.latest(ops.effective_node(node['id'])).read_bytes())
                    due=timestamp()-manifest['created_at']>=config['delete_first']['backup_interval']
                except (ValueError,KeyError,OSError):due=True
            if not due and not (requested and not requested['finished']):continue
            try:report=ops.check(node['id'],config,force=bool(requested and not requested['finished']))
            except Exception as error:report={'ready':False,'error':str(error) if isinstance(error,InfrastructureError) else type(error).__name__}
            with control.write() as db:
                if requested:
                    db.execute('UPDATE replacement_checks SET finished=?,result=? WHERE node=? AND request_id=?',
                               (timestamp(),json.dumps(report),node['id'],requested['request_id']))
                else:
                    db.execute('INSERT INTO replacement_checks(node,request_id,requested,finished,result) VALUES (?,?,?,?,?) '
                               'ON CONFLICT(node) DO UPDATE SET finished=excluded.finished,result=excluded.result',
                               (node['id'],'periodic',timestamp(),timestamp(),json.dumps(report)))
        for job in jobs:
            ops.recover_publication(job)
            if job['status'] in STAGES:runner.advance(job)
            elif job['status']=='ready':ops.release(job)
            elif job['status'] in ('cancelled','expired','recovered') and not ops.journal(job).get('delete_intent'):ops.release(job)


if __name__=='__main__':main()
