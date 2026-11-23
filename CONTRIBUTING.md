# Участие в разработке

## Сообщить об ошибке

После публикации откройте вкладку Issues этого нового репозитория → New issue →
Bug report. До публикации используйте локальный [шаблон](.github/ISSUE_TEMPLATE/bug_report.md).
Укажите версию/commit, ОС, этап, ожидаемое и фактическое поведение и минимальные
обезличенные шаги. Не прикладывайте базы, env, VPN URI, URL подписки, коды, IP
пользователей или полный приватный журнал. Для уязвимостей — [SECURITY](SECURITY.md).

## Изменения

Создайте ветку, воспроизведите проблему на mock/фикстурах, сохраните защитные gates.
Для изменений миграции проверяйте неизменность личности и поведения при потере
ответа провайдера. Не пишите тест, который арендует или удаляет VPS.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt -c requirements-constraints.txt
python -m pip check
python -m unittest discover -s tests
node --test launcher/test.mjs
python tools/build_site.py
python tools/check_public.py
```

Целевая среда CI — Ubuntu 24.04 / Python 3.12 / Node 22. `age` нужен для полного
теста шифрования; без него один тест явно пропускается. На Windows активация:
`.venv\Scripts\Activate.ps1`. Bash syntax проверяйте Git Bash или Linux.
Укажите проверенные среды в PR. Вклад распространяется под MIT проекта;
чужой код можно добавлять только с совместимой лицензией и уведомлением.
