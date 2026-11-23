"""Build a Pages-only marketing/documentation artifact; no network or deployment."""
import argparse
import html
from pathlib import Path
import re
import shutil

import markdown
from markdown.extensions.toc import slugify_unicode

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / '.build/pages'


def build(repository=None):
    if repository and not re.fullmatch(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Expected https://github.com/OWNER/REPO')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    # Only generated files in a resolved, fixed output directory may be replaced.
    assert OUTPUT.resolve().is_relative_to((ROOT / '.build').resolve())
    for path in OUTPUT.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in output')
    for path in list(OUTPUT.iterdir()):
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    for name in ['site.css']:
        shutil.copyfile(ROOT / 'site' / name, OUTPUT / name)
    landing = (ROOT / 'site/index.html').read_text(encoding='utf-8')
    landing = landing.replace('{{REPOSITORY}}', repository or 'README.html')
    landing = landing.replace('{{ISSUES}}', repository + '/issues/new/choose' if repository else 'CONTRIBUTING.html')
    (OUTPUT / 'index.html').write_text(landing, encoding='utf-8')
    (OUTPUT / '.nojekyll').write_text('')
    docs = list((ROOT / 'docs').glob('*.md'))
    docs += [ROOT / p for p in ['README.md', 'README.en.md', 'CONTRIBUTING.md', 'SECURITY.md', 'NOTICE.md', 'CHANGELOG.md']]
    for source in docs:
        rel = source.relative_to(ROOT).with_suffix('.html')
        destination = OUTPUT / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        prefix = '../' * (len(rel.parts) - 1)
        content = markdown.markdown(source.read_text(encoding='utf-8'), extensions=['tables', 'fenced_code', 'toc'],
                                    extension_configs={'toc': {'slugify': slugify_unicode}})
        # Map repository docs to published HTML. Raw source links go to a real repo
        # when configured, otherwise to the exported source reference document.
        def rewrite(match):
            target = match[1]
            if target.startswith(('https://', 'http://', '#', 'mailto:')):
                return match[0]
            local, separator, fragment = target.partition('#')
            candidate = (source.parent / local).resolve()
            if candidate.suffix == '.md' and candidate in {item.resolve() for item in docs}:
                target = local[:-3] + '.html' + (separator + fragment if separator else '')
            elif candidate.exists() and candidate.is_relative_to(ROOT):
                target = repository + '/blob/main/' + candidate.relative_to(ROOT).as_posix() if repository else prefix + 'source.html'
            return 'href="' + html.escape(target, quote=True) + '"'
        content = re.sub(r'href="([^"]+)"', rewrite, content)
        title = html.escape(source.stem)
        destination.write_text(f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} · ASMove VPN</title><link rel="stylesheet" href="{prefix}site.css"></head><body><header class="header wrap"><a class="brand" href="{prefix}index.html">ASMove VPN</a><nav><a href="{prefix}docs/QUICKSTART.html">Установка</a><a href="{prefix}README.html">README</a></nav></header><main class="document wrap">{content}</main><footer class="wrap"><a href="{prefix}index.html">На главную</a><a href="{prefix}SECURITY.html">Безопасность</a></footer></body></html>''', encoding='utf-8')
    (OUTPUT / 'source.html').write_text('''<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Исходники</title><link rel="stylesheet" href="site.css"></head><body><main class="document wrap"><h1>Исходники проекта</h1><p>Это локальная сборка до публикации GitHub-репозитория. Файлы находятся в локальной папке проекта. Для внешних ссылок пересоберите страницу с --repository https://github.com/OWNER/REPO после выбора настоящего адреса.</p><a href="index.html">На главную</a></main></body></html>''', encoding='utf-8')
    print('Pages artifact: ' + str(OUTPUT))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository')
    args = parser.parse_args()
    build(args.repository)
