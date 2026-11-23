"""Build an optional static cabinet without network access or deployment."""
import argparse
import ipaddress
from pathlib import Path
import re
from urllib.parse import urlsplit
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]


def origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment
            or not re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?', parsed.netloc)):
        raise ValueError('Expected an HTTPS origin without a path or credentials')
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if '.' not in parsed.hostname:
            raise ValueError('Expected a DNS name or public IP')
    else:
        if not address.is_global:
            raise ValueError('Expected a public IP')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('Invalid port')
    return value


def build(output, api_origin):
    api_origin = origin(api_origin)
    source = ROOT / 'launcher/dist'
    with ZipFile(output, 'x', compression=ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob('*')):
            if path.is_file():
                content = path.read_bytes()
                if path.suffix == '.html' or path.name == '_headers':
                    content = content.replace(b'https://controller.example', api_origin.encode())
                archive.writestr(path.relative_to(source).as_posix(), content)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api-origin', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.output, args.api_origin)
    except (ValueError, FileExistsError) as error:
        parser.exit(1, str(error) + '\n')
