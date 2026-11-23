"""Read-only VDSina catalog. Never orders, edits or deletes services."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.vdsina import Vdsina, ProviderError


def read_token(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024:
        raise ValueError('Expected a regular token file, at most 1 KiB')
    if os.name == 'posix' and (path.stat().st_uid != os.geteuid() or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ValueError('Token must belong to the current user, mode 0600 or 0400')
    token = path.read_text().strip()
    if not 16 <= len(token) <= 512 or any(c.isspace() for c in token):
        raise ValueError('Invalid token file')
    return token


def catalog(api, resource, group=None):
    endpoints = {'groups': 'server-group', 'plans': 'server-plan/' + str(group),
                 'datacenters': 'datacenter', 'templates': 'template', 'keys': 'ssh-key'}
    if resource == 'plans' and (type(group) is not int or group <= 0):
        raise ValueError('--group must be a positive group ID')
    rows = api.request('GET', endpoints[resource]) or []
    # Do not print raw server/account objects: they may contain passwords.
    allowed = {'id', 'name', 'country', 'active', 'enable', 'cost', 'period', 'min_money',
               'has_params', 'server-plan', 'ssh-key', 'limits', 'data'}
    if resource == 'keys':
        allowed = {'id', 'name'}
    return [{k: v for k, v in row.items() if k in allowed} for row in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('resource', choices=['groups', 'plans', 'datacenters', 'templates', 'keys'])
    parser.add_argument('--group', type=int)
    parser.add_argument('--token-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        os.environ['VDSINA_API_TOKEN'] = read_token(args.token_file)
        print(json.dumps(catalog(Vdsina(direct=True), args.resource, args.group), ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, ProviderError) as error:
        print('Catalog unavailable: ' + (str(error) if isinstance(error, (ValueError, ProviderError)) else type(error).__name__), file=sys.stderr)
        return 1
    finally:
        os.environ.pop('VDSINA_API_TOKEN', None)


if __name__ == '__main__':
    raise SystemExit(main())
