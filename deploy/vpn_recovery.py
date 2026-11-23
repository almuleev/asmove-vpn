"""Private, verified x-ui recovery archives and restoration on a new VPS."""
import base64
from contextlib import closing
import hashlib
import io
import inspect
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import time

MAX_ARCHIVE = 64 * 1024 * 1024
PRIVATE = Path('/var/lib/nodeguard-delete-first')


def atomic(path, data, mode=0o600):
    path = Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.new')
    descriptor=os.open(temp,os.O_CREAT|os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW,mode)
    with os.fdopen(descriptor,'wb') as output:
        output.write(data);output.flush();os.fsync(output.fileno())
    temp.chmod(mode);os.replace(temp,path)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent)
    finally:os.close(parent)


def encode_archive(files, manifest):
    manifest={**manifest,'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    with io.BytesIO() as out:
        with tarfile.open(fileobj=out,mode='w:gz') as archive:
            for name,data in {**files,'manifest.json':json.dumps(manifest).encode()}.items():
                item=tarfile.TarInfo(name);item.size=len(data);item.mode=0o600;archive.addfile(item,io.BytesIO(data))
        result=out.getvalue()
    if len(result)>MAX_ARCHIVE:raise ValueError('recovery_archive_too_large')
    return result


def validate_archive(data, node=None):
    if not 0<len(data)<=MAX_ARCHIVE:raise ValueError('invalid_recovery_archive_size')
    files={}
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        total=0
        for item in archive:
            if not item.isfile() or item.name in files or item.name.startswith('/') or '..' in Path(item.name).parts:
                raise ValueError('invalid_recovery_member')
            total+=item.size
            if total>MAX_ARCHIVE:raise ValueError('recovery_archive_expansion_limit')
            files[item.name]=archive.extractfile(item).read()
    manifest=json.loads(files.pop('manifest.json'))
    if manifest.get('version')!=1 or set(files)!=set(manifest['files']):raise ValueError('recovery_manifest_mismatch')
    if any(hashlib.sha256(content).hexdigest()!=manifest['files'][name] for name,content in files.items()):
        raise ValueError('recovery_checksum_mismatch')
    if node and any(manifest['node'][key]!=node[key] for key in ('id','service_id','ip')):
        raise ValueError('recovery_target_mismatch')
    if 'x-ui.db' not in files or 'accounts.sqlite3' not in files:raise ValueError('recovery_database_missing')
    with tempfile.TemporaryDirectory() as directory:
        for name in ('x-ui.db','accounts.sqlite3'):
            path=Path(directory)/name;path.write_bytes(files[name]);path.chmod(0o600)
            with closing(sqlite3.connect(f'file:{path.as_posix()}?mode=ro',uri=True)) as db:
                if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('recovery_database_corrupt')
                required={'users','settings','clients','inbounds','client_inbounds'} if name=='x-ui.db' else {'accounts','state'}
                tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not required<=tables:raise ValueError('recovery_schema_missing')
                if name=='x-ui.db':
                    count=db.execute('SELECT count(*) FROM clients').fetchone()[0]
                    if count!=manifest['panel_clients']:raise ValueError('recovery_client_count_mismatch')
    return manifest,files


CAPTURE = r'''import base64,json,sqlite3,tempfile
from contextlib import closing
from pathlib import Path
with tempfile.TemporaryDirectory(prefix='nodeguard-backup-') as directory:
 p=Path(directory)/'x-ui.db'
 with closing(sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro',uri=True)) as source, closing(sqlite3.connect(str(p))) as target:
  source.backup(target)
 with closing(sqlite3.connect(str(p))) as db:
  if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise RuntimeError('invalid_panel_database')
  count=db.execute('SELECT count(*) FROM clients').fetchone()[0]
 files={'x-ui.db':base64.b64encode(p.read_bytes()).decode()}
 for name,path in [('panel-state.json','/var/lib/access-site-3x-ui.json'),('panel-cert.pem','/root/cert/ip/fullchain.pem'),('panel-key.pem','/root/cert/ip/privkey.pem')]:
  f=Path(path)
  if f.is_file() and f.stat().st_size<1048576:files[name]=base64.b64encode(f.read_bytes()).decode()
 print(json.dumps({'files':files,'clients':count}))
'''


def capture(lifecycle,node,settings,store):
    from app.db import connect
    from app.sync import snapshot
    args=lifecycle.ssh_args(node['ip'],node['service_id'])
    args[args.index('StrictHostKeyChecking=accept-new')]='StrictHostKeyChecking=yes'
    args[args.index('-i')+1]=str(PRIVATE/'backup_ed25519')
    raw=lifecycle.run([*args,'root@'+node['ip'],'nodeguard-recovery-backup'],timeout=90)
    if len(raw)>MAX_ARCHIVE*2:raise ValueError('remote_backup_too_large')
    result=json.loads(raw);files={name:base64.b64decode(value,validate=True) for name,value in result['files'].items()}
    with tempfile.TemporaryDirectory(prefix='nodeguard-cabinet-') as directory:
        path=Path(directory)/'accounts.sqlite3';revision=snapshot(store,path);files['accounts.sqlite3']=path.read_bytes()
    config=json.loads((settings.data_dir/'probes/notifications.json').read_text())
    probe_uuid=config['outbounds'][0]['settings']['vnext'][0]['users'][0]['id']
    manifest={'version':1,'node':node,'created_at':int(time.time()),'account_revision':revision,
              'panel_clients':result['clients'],'probe_uuid':probe_uuid,'inbound':settings.panel.inbound,
              'companion_inbounds':list(settings.panel.companion_inbounds),'vpn_port':int(settings.panel.public_address.rsplit(':',1)[1])}
    data=encode_archive(files,manifest);validate_archive(data,node)
    return data


def backup_program():
    return ("import os,sys\nos.umask(0o077)\n"
            "if os.environ.get('SSH_ORIGINAL_COMMAND')!='nodeguard-recovery-backup':sys.exit(1)\n"+CAPTURE).encode()


def install_backup_endpoint(lifecycle,ip,service_id):
    """Install a dedicated key that can read a snapshot, but cannot execute commands."""
    public=PRIVATE/'backup_ed25519.pub'
    if not public.exists():return
    key=public.read_text().strip()
    request={'program':base64.b64encode(backup_program()).decode(),'key':key}
    program=r'''import base64,json,os,sys
from pathlib import Path
os.umask(0o077)
r=json.load(sys.stdin)
path=Path('/usr/local/lib/nodeguard/vpn-backup.py');path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
path.write_bytes(base64.b64decode(r['program'],validate=True));path.chmod(0o600)
auth=Path('/root/.ssh/authorized_keys');auth.parent.mkdir(mode=0o700,exist_ok=True)
key=r['key'];identity=key.split()[1]
lines=auth.read_text().splitlines() if auth.exists() else []
lines=[line for line in lines if identity not in line.split()]
lines.append('restrict,command="/usr/bin/python3 /usr/local/lib/nodeguard/vpn-backup.py" '+key)
temp=auth.with_name('authorized_keys.nodeguard-new');temp.write_text('\n'.join(lines)+'\n');temp.chmod(0o600);os.replace(temp,auth)
'''
    import shlex
    lifecycle.run([*lifecycle.ssh_args(ip,service_id),'root@'+ip,'python3 -c '+shlex.quote(program)],
                  data=json.dumps(request).encode(),timeout=30)


def adapt_database(db, old, new, port):
    """Retain identities, Reality keys and manual clients; change endpoint bindings only."""
    if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        raise RuntimeError('restore_integrity_failed')
    values = {'webListen': '127.0.0.1', 'webPort': str(port), 'webCertFile': '', 'webKeyFile': '',
              'subListen': '127.0.0.1', 'subCertFile': '', 'subKeyFile': ''}
    for key, value in values.items():
        if db.execute('SELECT 1 FROM settings WHERE key=?', (key,)).fetchone():
            db.execute('UPDATE settings SET value=? WHERE key=?', (value, key))
        else:
            db.execute('INSERT INTO settings(key,value) VALUES (?,?)', (key, value))
    db.execute('UPDATE settings SET value=? WHERE key=? AND value=?', (new, 'webDomain', old))
    for row in db.execute('SELECT id,listen,share_addr,stream_settings FROM inbounds').fetchall():
        stream = json.loads(row[3] or '{}'); changed = False
        tls = stream.get('tlsSettings', {})
        for settings in (tls, tls.get('settings', {})):
            if settings.get('serverName') == old:
                settings['serverName'] = new; changed = True
        for proxy in stream.get('externalProxy', []):
            for field in ('dest', 'address'):
                if proxy.get(field) == old:
                    proxy[field] = new; changed = True
        db.execute('UPDATE inbounds SET listen=?,share_addr=?,stream_settings=? WHERE id=?',
                   (new if row[1] == old else row[1], new if row[2] == old else row[2],
                    json.dumps(stream) if changed else row[3], row[0]))
    db.commit()


def prepare_database(path, content, old, new, port):
    """Checkpoint a restored WAL database before its main file is renamed."""
    for suffix in ('-wal', '-shm'):
        path.with_name(path.name+suffix).unlink(missing_ok=True)
    path.write_bytes(content); path.chmod(0o600)
    with closing(sqlite3.connect(str(path))) as db:
        adapt_database(db, old, new, port)
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')


RESTORE = inspect.getsource(adapt_database) + inspect.getsource(prepare_database) + r'''
import base64,json,os,sqlite3,subprocess,sys
from contextlib import closing
from pathlib import Path
request=json.load(sys.stdin);job=request['job'];digest=request['digest'];port=request['panel_port'];old=request['old_ip'];new=request['new_ip']
marker=Path('/var/lib/nodeguard-restore-'+job+'.json')
saved=None
if marker.exists():
 saved=json.loads(marker.read_text())
 if saved['digest']!=digest:raise RuntimeError('restore_archive_changed')
if not saved or saved.get('version')!=2:
 subprocess.run(['systemctl','stop','x-ui'],check=True)
 path=Path('/etc/x-ui/x-ui.db');temp=path.with_suffix('.restore-new')
 prepare_database(temp,base64.b64decode(request['database'],validate=True),old,new,port)
 for suffix in ('-wal','-shm'):
  Path(str(path)+suffix).unlink(missing_ok=True)
 os.replace(temp,path)
 marker.write_text(json.dumps({'digest':digest,'version':2}));marker.chmod(0o600)
subprocess.run(['systemctl','restart','x-ui'],check=True)
with sqlite3.connect('/etc/x-ui/x-ui.db') as db:
 settings=dict(db.execute('SELECT key,value FROM settings'))
if request.get('panel_state'):
 state=json.loads(base64.b64decode(request['panel_state'],validate=True))
 state.update(panel_port=port,panel_path=settings.get('webBasePath','/'))
 state_path=Path('/var/lib/access-site-3x-ui.json');state_path.write_text(json.dumps(state));state_path.chmod(0o600)
token=subprocess.check_output(['/usr/local/x-ui/x-ui','setting','-getApiToken','-tokenName','access-site-installer'],text=True)
import re
match=re.search(r'(?m)^apiToken: (\S+)',token)
if not match:raise RuntimeError('restored_api_token_missing')
print(json.dumps({'panel_port':port,'panel_path':settings.get('webBasePath','/'),'scheme':'http','token':match[1]}))
'''


def restore_panel(lifecycle,job,ip,directory,data):
    manifest,files=validate_archive(data,json.loads(job['spec'])['old'])
    details=lifecycle.bootstrap_node(job,ip,directory)
    # IP certificates must be reissued for the new address before restored TLS inbounds start.
    lifecycle.ensure_transport_certificate(job,ip)
    request={'job':job['id'],'digest':hashlib.sha256(data).hexdigest(),'database':base64.b64encode(files['x-ui.db']).decode(),
             'old_ip':manifest['node']['ip'],'new_ip':ip,'panel_port':details['panel_port']}
    if 'panel-state.json' in files:
        request['panel_state']=base64.b64encode(files['panel-state.json']).decode()
    # Only code is in argv; the private archive travels over encrypted SSH stdin.
    script='import sys\nsource='+repr(RESTORE)+'\nexec(source)'
    import shlex
    output=lifecycle.run([*lifecycle.ssh_args(ip,job['service_id']),'root@'+ip,
                          'python3 -c '+shlex.quote(script)],data=json.dumps(request).encode(),timeout=90)
    details={**details,**json.loads(output),'inbound':manifest['inbound'],
             'companion_inbounds':manifest['companion_inbounds'],'vpn_port':manifest['vpn_port']}
    lifecycle.save(directory/'node.json',details)
    with lifecycle.panel_connection(details,job['service_id']) as panel:
        for attempt in range(20):
            try:panel.inbound();break
            except Exception:
                if attempt==19:raise
                time.sleep(1)
        record=next(row for row in panel.request('clients/list') if row.get('uuid')==manifest['probe_uuid'])
        details['link']=next(link for link in panel.request('clients/links/'+record['email'])
                             if panel.link_matches(__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(link),manifest['probe_uuid']))
        details['link']=panel.stable_link(details['link'], 'Connection')
    lifecycle.save(directory/'node.json',details)
    return details
