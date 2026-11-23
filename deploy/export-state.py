"""Read-only encrypted recovery export. Never advances replacement jobs."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import sys
import subprocess
import tarfile
import tempfile
import time


def pack_state(files, metadata):
    if any(PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
           or '\\' in name or ':' in name for name in files):
        raise ValueError('Unsafe archive member path')
    files = {**files, 'manifest.json': json.dumps({**metadata,
        'sha256': {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}}).encode()}
    with io.BytesIO() as buffer:
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            for name, content in files.items():
                entry = tarfile.TarInfo(name); entry.size = len(content); entry.mode = 0o600
                archive.addfile(entry, io.BytesIO(content))
        return buffer.getvalue()


def encrypt_bundle(content, recipient, output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('Output already exists; choose a new backup filename')
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent, prefix='.nodeguard-export-') as temporary:
        staged = Path(temporary)/'backup.age'
        subprocess.run(['age', '-r', recipient, '-o', str(staged)], input=content, check=True, capture_output=True, timeout=120)
        staged.chmod(0o600)
        # Same filesystem; link fails atomically if another backup claimed this name.
        os.link(staged, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipient-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise SystemExit('Run as root on the RU controller')
    import fcntl
    import re
    os.umask(0o077)
    if args.output.exists() or args.output.is_symlink():
        raise SystemExit('Output already exists; choose a new backup filename')
    recipient = args.recipient_file.read_text().strip()
    if not re.fullmatch(r'age1[0-9a-z]{20,100}', recipient):
        raise SystemExit('Expected one age public recipient')
    sys.path[:0] = ['/opt/access-site/current', str(Path(__file__).parent)]
    from app.settings import Settings
    from app.infrastructure import Infrastructure, load_config
    from app.vdsina import Vdsina
    from app.delete_first import STAGES
    from app.db import connect
    import vpn_recovery
    spec = importlib.util.spec_from_file_location('runner', Path(__file__).with_name('delete-first.py'))
    runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
    # Parse env as data. No shell execution and no secret output.
    lc = runner.lifecycle_module()
    os.environ.update(lc.environment(Path('/etc/access-site/site.env').read_text()))
    settings = Settings.from_env(); config = load_config(settings.infrastructure_config)
    control = Infrastructure(settings.data_dir, settings.infrastructure_config)
    ops = runner.Operations(settings, control, Vdsina(direct=True), lc)
    node = ops.effective_node('EU1')
    files = {}
    with (vpn_recovery.PRIVATE/'runner.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with connect(control.path, 'ro') as db:
            active = (*STAGES, 'attention')
            if db.execute('SELECT 1 FROM jobs WHERE status IN ('+','.join('?' for _ in active)+')', active).fetchone():
                raise SystemExit('A replacement is active. Finish it before exporting')
        archive, manifest = ops.backup(node, config, force=True)
        checked, payload = vpn_recovery.validate_archive(archive.read_bytes(), node)
        files['vpn-recovery.tar.gz'] = archive.read_bytes()
        files['accounts.sqlite3'] = payload['accounts.sqlite3']
        for path in Path('/etc/access-site').iterdir():
            if path.is_file() and not path.is_symlink() and path.suffix in ('.env', '.json'):
                files['etc-access-site/'+path.name] = path.read_bytes()
        files['infrastructure.json'] = settings.infrastructure_config.read_bytes()
        for path in lc.CONTROL.iterdir():
            if path.is_file() and not path.is_symlink():
                files['control/'+path.name] = path.read_bytes()
        metadata = {'version': 1, 'created_at': int(time.time()),
                    'account_revision': checked['account_revision'], 'node': node}
    encrypt_bundle(pack_state(files, metadata), recipient, args.output)
    print(json.dumps({'exported': str(args.output), 'encrypted': True, 'account_revision': manifest['account_revision']}))


if __name__ == '__main__':
    main()
