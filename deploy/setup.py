"""Interactive first installation on a clean RU server. Never rents or deletes VPS."""
import base64
from decimal import Decimal
from getpass import getpass
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def choose(label, rows):
    if not rows:
        raise ValueError('Нет совместимых вариантов: ' + label)
    print('\n' + label)
    for index, row in enumerate(rows, 1):
        print(f"{index}. {row.get('name', row['id'])} (ID {row['id']})")
    while True:
        value = input('Номер варианта [1]: ').strip() or '1'
        if value.isdigit() and 1 <= int(value) <= len(rows):
            return rows[int(value)-1]
        print('Введите номер из списка.')


def same_key(value, public_key):
    if not isinstance(value, str):
        return False
    if not value.startswith('ssh-'):
        try:
            value = base64.b64decode(value, validate=True).decode()
        except (ValueError, UnicodeError):
            return False
    return value.split()[:2] == public_key.split()[:2]


def discover(api, ip, public_key, select=choose):
    """Derive account-specific IDs using GET only. No order, deletion or key write."""
    from app.vdsina import Vdsina
    matches = []
    for row in api.servers():
        details = api.server(row['id'])
        if Vdsina.address(details) == ip:
            matches.append(details)
    if len(matches) != 1 or matches[0].get('status') != 'active':
        raise ValueError('В API не найден ровно один активный VPS с этим IP')
    server = matches[0]
    old_plan = server.get('server-plan', {})
    old_dc = server.get('datacenter', {})
    if not isinstance(old_plan, dict) or not isinstance(old_dc, dict):
        raise ValueError('API не вернул ID тарифа и площадки текущего EU')
    offers = []
    for group in api.request('GET', 'server-group') or []:
        for plan in api.request('GET', 'server-plan/' + str(group['id'])) or []:
            if (plan['id'] == old_plan.get('id') and plan.get('active') and plan.get('enable')
                    and not plan.get('has_params') and plan.get('period') == 'day'
                    and Decimal(str(plan.get('cost', 0))) == Decimal('0.07')):
                offers.append((group['id'], plan))
    if len(offers) != 1:
        raise ValueError('Тариф текущего EU должен быть фиксированным USD 0.07/day')
    group_id, plan = offers[0]
    keys = [row for row in api.request('GET', 'ssh-key') or [] if same_key(row.get('data'), public_key)]
    if not keys:
        raise ValueError('Добавьте показанный публичный ключ этого RU в SSH Keys VDSina и повторите мастер')
    dc_rows = [row for row in api.request('GET', 'datacenter') or []
               if row.get('active') and row.get('country') and row['country'].lower() != 'ru']
    current_dc = next((row for row in dc_rows if row['id'] == old_dc.get('id')), None)
    if not current_dc:
        raise ValueError('Текущий EU должен находиться на зарубежной активной площадке')
    templates = [row for row in api.request('GET', 'template') or []
                 if row.get('active') and row.get('ssh-key') and plan['id'] in row.get('server-plan', [])
                 and 'ubuntu' in row.get('name', '').lower() and '24.04' in row.get('name', '')]
    template = select('Чистая Ubuntu 24.04 для будущих серверов', templates)
    dc = select('Площадка для будущих замен', dc_rows)
    candidate = dict(plan_id=plan['id'], group_id=group_id, template_id=template['id'],
                     ssh_key_id=keys[0]['id'], datacenter_id=dc['id'], country=dc['country'].lower(), daily_cost='0.07')
    api.quote(candidate, retiring_service_id=server['id'])
    return dict(eu_ip=ip, eu_service_id=server['id'], datacenter_id=current_dc['id'],
                country=current_dc['country'].lower(), candidates=[candidate])


def main():
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Запустите мастер от root на своём новом RU с Ubuntu 24.04')
    os.umask(0o077)
    print('ASMove VPN. Первые RU и EU создаются вами вручную; мастер ничего не арендует.')
    print('Нужны два чистых Ubuntu 24.04 amd64 и тариф EU VDSina.com USD 0.07/сутки.')
    env = Path('/etc/access-site/site.env')
    config_file = Path('/root/asmove-bootstrap.local.json')
    if config_file.exists():
        print('Найден сохранённый конфиг. Продолжаем ту же установку без смены цели.')
    else:
        marker = Path('/root/asmove-setup-started')
        if env.exists() and not marker.exists():
            raise ValueError('Уже есть установка без маркера этого мастера. Используйте update.sh, не bootstrap')
        if not env.exists():
            marker.touch(mode=0o600, exist_ok=True)
            authority = input('Публичный IPv4 российского сервера: ').strip()
            subprocess.run(['bash', str(ROOT/'deploy/bootstrap-host.sh'), authority], check=True)
        key = Path('/var/lib/access-site/control/id_ed25519.pub').read_text().strip()
        print('\nПубличный SSH-ключ RU (его можно копировать):\n' + key)
        print('Добавьте его в VDSina → SSH Keys и в /root/.ssh/authorized_keys первого EU через консоль провайдера.')
        input('Когда ключ добавлен, нажмите Enter. ')
        ip = input('Публичный IPv4 зарубежного EU: ').strip()
        import ipaddress
        if not ipaddress.IPv4Address(ip).is_global:
            raise ValueError('Нужен публичный IPv4 EU')
        print('В web-консоли EU выполните: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256')
        host_fingerprint = input('Полученный отпечаток SHA256:...: ').strip()
        token = getpass('API-токен VDSina.com (ввод скрыт): ').strip()
        if not 16 <= len(token) <= 512 or any(c.isspace() for c in token):
            raise ValueError('Некорректный токен')
        from app.vdsina import Vdsina
        os.environ['VDSINA_API_TOKEN'] = token
        try:
            config = discover(Vdsina(direct=True), ip, key)
        finally:
            os.environ.pop('VDSINA_API_TOKEN', None)
        token_file = Path('/root/asmove-vdsina.token')
        if token_file.exists() or token_file.is_symlink():
            raise ValueError('Файл токена уже существует; проверьте предыдущую установку')
        with token_file.open('x') as file:
            file.write(token+'\n')
        token_file.chmod(0o600)
        print('Автозамена удаляет старый VPS и создаёт новый. Возможен длительный простой и расходы.')
        automatic = input('Разрешить автозамену после устойчивого сбоя? Введите ДА или оставьте пустым: ').strip() == 'ДА'
        config.update(eu_host_fingerprint=host_fingerprint, vdsina_token_file=str(token_file),
                      telegram_env_file=None, ntfy_env_file=None, recovery_archive_file=None,
                      automation={'enabled': automatic})
        with config_file.open('x') as file:
            json.dump(config, file, indent=2)
        config_file.chmod(0o600)
    python = '/opt/access-site/current/venv/bin/python'
    # Discovery has no dependency on third-party packages; installation uses the
    # pinned runtime just installed by bootstrap-host.
    subprocess.run([python, str(ROOT/'deploy/bootstrap-vpn.py'), str(config_file), '--check'], check=True)
    subprocess.run([python, str(ROOT/'deploy/bootstrap-vpn.py'), str(config_file)], check=True)
    print('Готово. Адрес кабинета есть в выводе установки. Пароль: /etc/access-site/initial-admin.txt')
    print('Создайте пользователя в /admin; правила автозамены доступны в /admin/infrastructure.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Remote output and raw provider payloads must not enter a public log.
        print('Мастер остановлен: '+(str(error) if isinstance(error, ValueError) else type(error).__name__)
              +'. Сохранённый конфиг не удаляйте. Исправьте причину и повторите ту же команду.', file=sys.stderr)
        raise SystemExit(1)
