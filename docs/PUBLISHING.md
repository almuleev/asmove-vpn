# Публикация ASMove VPN

Репозиторий: https://github.com/almuleev/asmove-vpn.
Сайт проекта: https://almuleev.github.io/asmove-vpn/.
Кабинет каждого владельца находится на его собственном RU, не на сайте проекта.

## Изменения кода

Перед push выполните тесты, сборку и поиск секретов по CONTRIBUTING.md. Коммитьте
только исходники. .local/.venv/.build, токены, базы, конфиги установки и архивы
не должны попадать в Git. Push в main запускает проверки GitHub Actions.

```bash
git status
git add .
git commit -m "Describe the change"
git push origin main
```

Не используйте force-push. Обычное обновление исходников не меняет работающие VPS.

## Страница проекта

Локальная сборка:

```bash
python tools/build_site.py --repository https://github.com/almuleev/asmove-vpn
python tools/check_public.py
python -m http.server 8787 --bind 127.0.0.1 --directory .build/pages
```

Откройте http://127.0.0.1:8787/. Страница работает и под /asmove-vpn/ благодаря
относительным ссылкам. После проверки: GitHub → Actions → Publish Pages → Run
workflow. Он публикует только .build/pages через environment github-pages.
Backend и пользовательские данные в Pages не входят. HTTPS включается на GitHub.

Основной CI ставит age и проверяет шифрование на Linux. Live-заказы VPS в CI запрещены.
Сохраняйте preview-статус до проверки чистых VPS, устройств и сертификатов.

## Необязательный статический кабинет владельца

Основной кабинет доступен на https://ВАШ_RU_IP/. Для вынесенного кабинета нужен
свой отдельный Pages origin и настройка SITE_PORTAL_ORIGIN на RU, затем restart
access-site.service и проверка CORS. Сборка без сетевых действий:

```bash
python deploy/build-portal.py --api-origin https://REPLACE_RU_HOST --output portal.zip
```

Замените host lowercase-адресом своего RU без завершающего /. Имя ZIP должно быть
новым. Опубликуйте только содержимое ZIP в собственном кабинете. Не заменяйте им
лендинг ASMove VPN и не добавляйте backend/.git/секреты. GitHub Pages игнорирует
_headers: connect-src также задан в meta CSP. Проверьте вход, подписку и redirect
/admin на свой RU. Новичку отдельный Pages-кабинет для первого запуска не нужен.
