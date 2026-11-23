"""Offline source/artifact checks. Never contacts a server or prints matched secrets."""
import argparse
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {'.git', '.venv', '.local', '.build', '__pycache__'}


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links, self.ids = [], set()
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.ids.add(attrs['id'])
        for name in ('href', 'src'):
            if attrs.get(name):
                self.links.append(attrs[name])


def check(deny=()):
    problems = []
    files = [p for p in ROOT.rglob('*') if not any(part in IGNORED for part in p.relative_to(ROOT).parts) and p.is_file()]
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.is_symlink():
            problems.append((relative, 'symlink'))
        if path.suffix in {'.db', '.sqlite3', '.pem', '.key', '.age', '.agekey', '.zip', '.tar', '.gz', '.env'}:
            problems.append((relative, 'private/runtime extension'))
        text = path.read_text(encoding='utf-8')
        if any(value and value in text for value in deny):
            problems.append((relative, 'private source binding'))
        patterns = [r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----', r'gh[pousr]_[A-Za-z0-9]{30,}',
                    r'https://[^\s"<>]+/sub/[0-9a-f]{32}/[0-9a-f]{64}', r'vless://[0-9a-f-]{36}@']
        if any(re.search(pattern, text) for pattern in patterns):
            problems.append((relative, 'credential pattern'))
        if path.suffix == '.md':
            # Check prose links; code examples may contain placeholders intentionally.
            prose = re.sub(r'```.*?```', '', text, flags=re.S)
            for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', prose):
                parsed = urlsplit(target)
                if parsed.scheme or not parsed.path:
                    continue
                resolved = (path.parent / unquote(parsed.path)).resolve()
                if not resolved.is_relative_to(ROOT) or not resolved.exists():
                    problems.append((relative, 'broken local Markdown link'))
    artifact = ROOT / '.build/pages'
    html_files = list(artifact.rglob('*.html'))
    docs = {p.resolve(): Document(p.read_text(encoding='utf-8')) for p in html_files}
    if not html_files:
        problems.append(('.build/pages', 'build is missing'))
    for path, document in docs.items():
        for link in document.links:
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc:
                continue
            resolved = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
            if not resolved.is_relative_to(artifact.resolve()) or not resolved.exists():
                problems.append((path.name, 'broken artifact link'))
            elif parsed.fragment and resolved in docs and unquote(parsed.fragment) not in docs[resolved].ids:
                problems.append((path.name, 'broken artifact fragment'))
    for path in artifact.rglob('*'):
        if path.is_file() and path.suffix not in {'.html', '.css'} and path.name != '.nojekyll':
            problems.append((path.name, 'unexpected Pages file'))
    for name, reason in problems:
        print(name + ': ' + reason)
    if problems:
        raise SystemExit(f'FAILED: {len(problems)} findings (matched values suppressed)')
    print(f'OK: {len(files)} source files, {len(html_files)} HTML pages, local links/fragments and credential patterns')
    print('External links, VPS behavior and unknown secret formats are not certified by this check.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deny-list', type=Path, help='Private local file, one original binding per line')
    args = parser.parse_args()
    check(args.deny_list.read_text(encoding='utf-8').splitlines() if args.deny_list else ())
