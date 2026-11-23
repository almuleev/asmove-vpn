# Публикация отдельного проекта

В этой работе нет remote/push, создания GitHub-репозитория и публикации Pages.
Финальный локальный commit предназначен для проверки владельцем.

## Перед публичным запуском

Прочитайте README, NOTICE, SECURITY, AUDIT и VALIDATION. Проверьте тариф и схему
.com API в своём аккаунте без аренды ради документации. Для stable-статуса нужна
отдельно разрешённая приёмка чистых собственных VPS и устройств; до неё сохраняйте
пометку предварительной версии. Выберите публичный GitHub owner/repo и включите
private vulnerability reporting. Точные внешние ссылки issues/repo появятся после
указания реального нового адреса — чужие или вымышленные URL не используются.

## Репозиторий

В GitHub → New repository: новое имя `vpn-node-guard`, Public, без автосоздания
README/license/gitignore (они уже есть). Не используйте исходный backend/Pages repo.
После отдельного решения о публикации, из новой локальной папки:

```bash
git remote add origin https://github.com/REPLACE_OWNER/vpn-node-guard.git
git push -u origin main
```

Замените OWNER своим логином/организацией. Force-push не требуется. Перед push
проверьте `git ls-files`, `git status`, результаты `python tools/check_public.py`.
Не добавляйте .venv/.local/.build, архив исходников или приватные конфиги.

## Публичная страница проекта

Локально:

```bash
python tools/build_site.py --repository https://github.com/REPLACE_OWNER/vpn-node-guard
python tools/check_public.py
python -m http.server 8787 --bind 127.0.0.1 --directory .build/pages
```

Откройте `http://127.0.0.1:8787/` на своём компьютере. Без `--repository` сборка
также работает: ссылки ведут на локальные инструкции участия, нет выдуманного GitHub.
Страница, документация и assets используют относительные пути и работают под
`/vpn-node-guard/`. Приватных интеграций, аналитики и внешних шрифтов нет.

В новом GitHub repo Settings → Pages → Source: GitHub Actions. Подготовлен workflow
`publish-pages.yml`: запускается только вручную (Actions → Publish Pages → Run
workflow), собирает **только .build/pages**, затем использует environment github-pages.
В Settings → Environments можно назначить required reviewer для этого environment.
В этой локальной работе workflow не запускался. Проверьте URL успешного deployment,
мобильную ширину, установочную ссылку и настройки HTTPS. Первое открытие и uptime
Pages здесь не проверялись. Git push backend сам по себе ничего не публикует.

## Необязательный отдельный статический кабинет

Основной кабинет уже работает на `https://RU_IP/`. Для статического кабинета нужен
**отдельный** Pages origin/репозиторий; рекламная страница не превращается в кабинет.
На RU `SITE_PORTAL_ORIGIN` должен быть origin без path, например `https://OWNER.github.io`.
После изменения своего site.env перезапустите access-site.service и проверьте CORS.
Сборка на машине с исходниками, без сетевых действий:

```bash
python deploy/build-portal.py --api-origin https://REPLACE_RU_HOST --output portal.zip
```

Имя host должно быть lowercase, без завершающего `/`. Выходной ZIP должен отсутствовать.
Содержимое ZIP — единственный источник статического кабинета; удалите прежние файлы
в **новом** кабинете перед загрузкой, не публикуйте backend/.git/секреты.
`launcher/dist` содержит безопасный placeholder и сам по себе к RU не подключается.
GitHub Pages игнорирует `_headers`; для connect-src добавлен meta CSP.
Проверьте вход, подписку, отчёт о проблеме и /admin redirect на своём origin.
