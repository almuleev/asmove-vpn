# Эксплуатация и восстановление

Все команды — **на своём RU от root**, если указано EU — на своём EU.
Не выполняйте bootstrap поверх рабочей установки.

## Наблюдение и службы

```bash
/usr/local/sbin/access-site status
/usr/local/sbin/access-site check-panel
systemctl status access-site.service --no-pager
systemctl list-timers 'access-site-*' 'nodeguard-*'
journalctl -u access-site-infrastructure.service -n 50 --no-pager
journalctl -u access-site-delete-first.service -n 50 --no-pager
```

Эти команды читают статус. `infrastructure-tick` и запуск исполнителя могут
продолжить подтверждённую замену — не используйте их как read-only диагностику.
Nginx обслуживает HTTPS, приложение слушает loopback 8016 под access-site;
root SSH-туннель ведёт к loopback-панели EU. Таймер infrastructure проверяет VPN,
delete-first выполняет подтверждённые jobs, backup сохраняет основную базу.
Сертификаты обновляются отдельно. Ошибка уведомлений не блокирует админку.

## Замена EU при живом RU

1. В `/admin/infrastructure` проверьте свежесть наблюдений. Посмотрите состояние
   EU/провайдера, время, сертификат и конфигурацию: ошибка не обязательно блокировка.
2. Запросите проверку готовности замены/архива. Нужен свежий проверенный архив
   полной x-ui базы и согласованный снимок кабинета. Если backup недоступен,
   обычная безопасная замена останавливается; не обходите эту проверку.
3. Подготовьте заявку. Сверьте IP и service ID с собственным кабинетом провайдера.
4. Введите **точный IP удаляемого узла** и подтвердите ожидаемый простой.
5. Следите за той же заявкой: preparing → deleting → waiting_delete → ordering →
   provisioning → verifying → publishing → ready. Возможны uncertain/attention.
6. После ready обновите подписку на устройстве и переподключитесь. Прямую ссылку
   импортируйте заново. Проверьте доступ и отзыв на основном и дополнительных входах.

Старый VPS удаляется до нового заказа. Подписи URL не зависят от IP EU, а от
SITE_ACCESS_KEY, account ID и auth_version. Сохраняются UUID, хэши, access_index,
auth_version, сроки, данные x-ui и ручные клиенты из проверенного архива. При смене
самого RU origin прежний URL подписки уже не гарантирован. Смена кода/отзыв по
правилам авторизации может намеренно сделать прежний URL недействительным.

При недостатке средств/нет тарифа — attention; после удаления простой продолжается.
При timeout — сверка инвентаря по текущему job, не новый заказ. Не нажимайте DELETE
вручную параллельно исполнителю. Приватный журнал:
`/var/lib/nodeguard-delete-first/jobs/JOB_ID/`; он может содержать секреты панели.
Перед повтором после attention изучите причину и используйте продолжение той же
заявки, сохраняя журнал. Не редактируйте SQL/jobs ради обхода неизвестного результата.

## Данные и секреты

| Путь | Значение |
| --- | --- |
| /opt/access-site/current | Активный релиз и venv, без deploy |
| /etc/access-site/site.env | SITE_ACCESS_KEY, сеансы, хэш админа, подключение панели |
| /etc/access-site/infrastructure.env | Токен VDSina, root 0600 |
| /var/lib/access-site/data/accounts.sqlite3 | Основная база пользователей |
| /var/lib/access-site/data/local.sqlite3 | Сеансы/локальная авторизация |
| /var/lib/access-site/infrastructure.json | Конфигурация; актуальный адрес также может быть в overrides БД |
| /opt/nodeguard-control/deploy | Root-owned исполнители |
| /var/lib/access-site/control | Приватный SSH key и pinned known_hosts, только root |
| /var/lib/nodeguard-delete-first | Архивы, journal, recovery state |
| EU: /etc/x-ui/x-ui.db | База 3x-ui |
| EU: /etc/nodeguard-vpn-tls | Ключ и цепочка сертификата IP |

`SITE_ACCESS_KEY` не меняйте на живой базе. Коды в vault зашифрованы ключом,
производным от него; хэши используются для входа. Подписки и VPN URI — секреты
доступа. Для отзыва пользователя используйте админку. При утечке provider token
отзовите его у провайдера и замените env; при утечке SSH key создайте новую пару,
удалите старую из authorized_keys EU/аккаунта и обновите ssh_key_id кандидата.
Простое удаление ключа из списка VDSina может не удалить его с уже созданного VPS.
Пароль RU-админа меняйте через генерацию нового Argon2 хэша штатным `app.cli credentials`
в закрытом файле, перенося **только SITE_ADMIN_HASH**, сохраняя остальные значения;
после изменения перезапустите приложение и проверьте выход старых сеансов.
Это ручная операция; мастера ротации секретов нет.

## Резервные копии

```bash
/usr/local/sbin/access-site backup
```

Локальные копии accounts в `/var/lib/access-site/data/backups`, retention 14 дней.
Они не защищают от потери RU. Не копируйте горячий SQLite отдельно от WAL.
Для внешнего экспорта на отдельной доверенной машине создайте age-ключ:

```bash
umask 077
age-keygen -o nodeguard-backup.agekey
age-keygen -y nodeguard-backup.agekey > backup-recipient.txt
```

На RU передайте **только публичный** recipient. Затем на RU:

```bash
cd /opt/nodeguard-src
/opt/access-site/current/venv/bin/python deploy/export-state.py --recipient-file /root/backup-recipient.txt --output /root/nodeguard-backup-UNIQUE.tar.age
```

Замените UNIQUE на новое имя; существующий файл не перезаписывается. Export
отклоняется при активной замене, сам jobs не выполняет. В архив входят env,
основная база, архив x-ui, инфраструктура и служебные ключи. Перенесите `.age`
на отдельное хранилище, приватный age-key держите вне RU. Проверьте расшифрование.
Автоматическая доставка во внешнее хранилище не реализована в этом проекте.

## Потеря RU: восстановление на двух чистых узлах

Расшифруйте архив в закрытый staging **на доверенной машине** с приватным ключом;
проверьте manifest SHA256 и перенесите staging на новый RU по защищённому SSH.
Не распаковывайте поверх `/`. Пример локальной расшифровки:

```bash
umask 077
mkdir nodeguard-restore
age -d -i /PRIVATE/PATH/nodeguard-backup.agekey -o nodeguard-restore/backup.tar /PRIVATE/PATH/backup.tar.age
tar -xzf nodeguard-restore/backup.tar -C nodeguard-restore
```

В извлечённом `etc-access-site/site.env` сохраните **только исходный SITE_ACCESS_KEY**
в отдельный root-owned файл `/root/original-site-access-key` (64 hex, режим 0600),
без `SITE_ACCESS_KEY=` и кавычек. Не переносите весь старый env поверх нового.
На новом RU с проверенными исходниками:

```bash
cd /opt/nodeguard-src
bash deploy/bootstrap-host.sh REPLACE_NEW_RU_IPV4 '' /root/original-site-access-key
/usr/local/sbin/access-site restore /root/nodeguard-restore/accounts.sqlite3
```

При необходимости восстановите transport policy до EU. Подготовьте новый EU и
ключ RU по INSTALL. В bootstrap JSON новые IP/service ID/SSH fingerprint и
`recovery_archive_file` с путём к извлечённому `vpn-recovery.tar.gz`.
Повторите `--check`, затем реальный bootstrap-vpn. Проверяется совпадение базы/ключа
кабинета с архивом x-ui; сертификат выдаётся для нового IP **до запуска**
восстановленной базы. Старый сертификат переносить как действующий нельзя.

Проверьте устройства и отзыв. Админский пароль RU новый, сеансы создаются заново.
Новый origin RU потребует новых URL подписок/обновления опционального Pages.
Эта процедура ещё не проверена на реальных чистых VPS в рамках нового проекта.

## Уведомления и Relay

Telegram: создайте собственного бота у BotFather, разрешите ему диалог с владельцем;
заполните приватную копию `deploy/telegram.env.example` токеном и chat ID.
ntfy: приватная копия `deploy/ntfy.env.example`, HTTPS topic/token своего сервера.
Публичная непредсказуемая тема ntfy не равна авторизации: знание URL даёт доступ.
Пути файлов укажите при первичном bootstrap. Позднее файлы можно установить в
`/etc/access-site/telegram.env` и `ntfy.env`, root 0600, включить соответствующие
таймеры; SSH SOCKS Telegram требует конфигурации notification-targets из bootstrap.
Интерактивного мастера добавления уведомлений после bootstrap пока нет.
Нельзя публиковать токены/URL темы. Для отзыва токена Telegram используйте BotFather,
ntfy — настройки собственного сервера.

Relay по умолчанию отключён. Его `tcp-relay.json` требует явных аккаунтов и точных
IP источников; отдельная настройка не входит в маршрут новичка. Не включайте
его всем, не подставляйте чужие whitelist и не удаляйте проверки личности.

## Обновление, откат, удаление

Перед обновлением: внешний export, отсутствие незавершённых jobs и чтение diff.
Обновите исходники до выбранного commit и запустите `bash deploy/update.sh`.
Автоматический откат скрипта касается сбоя запуска web-релиза. Он не делает
транзакцию всех root-исполнителей и units; их обновление проверяйте отдельно.
Для отката кода выбирайте предыдущий `/opt/access-site/releases/...` и штатное
атомарное переключение current; не откатывайте живую БД старым файлом ради UI.
Сначала остановите исполнителей при неясном состоянии, сохранив журнал заказа.

Удаление сервиса **не отменяет аренду VPS**. До удаления ПО завершите/разберите
текущие jobs, сохраните export и отключите таймеры замены/наблюдения/уведомлений.
Проверьте список `systemctl list-unit-files 'access-site-*' 'nodeguard-*'`, остановите
найденные units, затем удаляйте только их файлы и Nginx site `access-site.conf`.
Сделайте `systemctl daemon-reload`, `nginx -t`, reload Nginx. На EU остановите x-ui
и nodeguard-vpn-tls.timer перед удалением их файлов. Точный список путей приведён
выше; не удаляйте системный Nginx/Python/Certbot других сайтов.
Полного автоматического uninstall нет. VPS отменяются вручную в своём кабинете
провайдера после проверки резервной копии. Эта локальная работа их не отменяет.
