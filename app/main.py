import base64
import hmac
import ipaddress
import logging
import re
import sqlite3
from threading import Lock
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import admin_relay, infrastructure, problem_reports, reserve, password_vault
from .access_term import MOSCOW, access_date, expired, next_month, noon

from .auth import ACCESS_PATTERN, HASH_SLOTS, LOGIN_COOKIE, LOGIN_PATTERN, SESSION_COOKIE, TOKEN_PATTERN, WINDOW
from .auth import Auth, access_index, access_secret, make_user_password, token, verify
from .db import DEFAULT_PLATFORM, PLATFORMS, CodeAlreadyIssued, Store, account_comment, connect, now
from .settings import Settings
from .subscriptions import authorized as subscription_authorized, subscription_url
from .sync import sync_health
from .xui import Panel, PanelError, PanelGroup


ROOT = Path(__file__).parent
MAX_FORM = 32768
MAX_CONFIG = 8192
CABINET_API = "/api/cabinet"
PANEL_FAILURE = "3x-ui не подтвердил операцию. Проверьте панель и повторите попытку."
ACTIONS = {
    "create": "Пользователь добавлен",
    "config": "Ссылка обновлена",
    "password": "Пароль обновлён",
    "revoke": "Доступ отозван",
    "enable": "Доступ восстановлен",
    "delete": "Пользователь удалён",
    "reserve": "Настройка запасного подключения изменена",
    "access": "Срок доступа изменён",
}
logger = logging.getLogger("access_site")


async def read_form(request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/x-www-form-urlencoded":
        raise HTTPException(415)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_FORM:
            raise HTTPException(413)
        body.extend(chunk)
    try:
        fields = parse_qsl(body.decode("ascii"), keep_blank_values=True, errors="strict", max_num_fields=8)
        if len(dict(fields)) == len(fields):
            return dict(fields)
    except ValueError:
        pass
    raise HTTPException(400)


def datetime_iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def datetime_moscow(value):
    return datetime.fromtimestamp(value, MOSCOW).strftime("%d.%m.%Y, %H:%M МСК")


def set_cookie(response, name, value, ttl):
    response.set_cookie(name, value, max_age=ttl, secure=True, httponly=True, samesite="strict")


def clear_cookie(response, name):
    set_cookie(response, name, "", 0)


def create_app(settings=None):
    settings = settings or Settings.from_env()
    store = Store(settings.data_dir)
    auth = Auth(settings, store)
    panel = (PanelGroup(settings.panel, settings.data_dir) if settings.panel and settings.role == "primary"
             else Panel(settings.panel) if settings.panel else None)
    primary = settings.role == "primary"
    can_relay = bool(not primary and settings.admin_relay_key and settings.admin_primary_origin)
    reserve_links = reserve.ReserveLinks(store, panel) if panel and settings.reserve_export else None
    temporary_relay_key = hmac.digest(settings.access_key, b"temporary-reserve-relay-v1", "sha256").hex()
    admin_write_lock = Lock()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
    templates = Jinja2Templates(directory=ROOT / "templates")
    templates.env.filters["iso_time"] = datetime_iso
    templates.env.filters["moscow_time"] = datetime_moscow
    templates.env.filters["access_date"] = access_date
    templates.env.globals["actions"] = ACTIONS
    templates.env.globals["platforms"] = PLATFORMS

    def page(request, name, status=200, **context):
        return templates.TemplateResponse(request=request, name=name, context=context, status_code=status)

    def cleanup_client(account_id):
        try:
            panel.remove(account_id)
        except PanelError as exc:
            logger.error("panel_cleanup_failed reason=%s", exc)

    def issue_client(account_id, login, platform, access_until):
        try:
            return panel.issue(account_id, access_until or 0, comment=account_comment(login, platform), platform=platform)
        except PanelError:
            cleanup_client(account_id)
            raise

    def account_overview():
        users, audit, revision = store.overview()
        timestamp = now()
        accounts = [
            {"id": user["id"], "login": user["login"], "enabled": user["enabled"], "platform": user["platform"],
             "config_at": user["config_at"], "managed": bool(panel and panel.manages(user)),
             "reserve_enabled": user["reserve_enabled"], "access_until": user["access_until"],
             "expired": expired(user, timestamp)}
            for user in users
        ]
        return accounts, [dict(event) for event in audit], revision

    @app.middleware("http")
    async def protect_response(request, call_next):
        origin = f'{request.scope["scheme"]}://{request.headers.get("host", "")}'
        api = request.url.path.startswith(CABINET_API + "/")
        allowed = api and settings.portal_origin and request.headers.get("origin") == settings.portal_origin
        if origin != settings.origin:
            response = page(request, "error.html", 400, message="Откройте HTTPS-адрес кабинета.")
        elif api and not allowed:
            response = JSONResponse({"error": "Доступ к API закрыт."}, status_code=403)
        elif allowed and request.method == "OPTIONS":
            response = JSONResponse(None, status_code=200, headers={
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Access-Control-Max-Age": "600",
            })
        else:
            try:
                response = await call_next(request)
            except Exception as exc:
                # Never send exception messages, tracebacks, URLs, headers or form data to logs.
                logger.error("request_failed type=%s", type(exc).__name__)
                message = "Сервис временно недоступен."
                response = JSONResponse({"error": message}, status_code=503) if api else page(request, "error.html", 503, message=message)
        response.headers.update({
            "Cache-Control": "no-store",
            "Referrer-Policy": "same-origin",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            ),
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        })
        if request.url.path.startswith('/static/guides/') and request.url.path.endswith('.svg'):
            # Guide SVGs embed their original PNG; no scripts or remote resources.
            response.headers['Content-Security-Policy'] = "default-src 'none'; img-src data:;"
        if request.method == "GET" and request.url.path == "/health" and settings.launcher_origin:
            response.headers.add_vary_header("Origin")
            if request.headers.get("origin") == settings.launcher_origin:
                response.headers["Access-Control-Allow-Origin"] = settings.launcher_origin
        if api:
            response.headers.add_vary_header("Origin")
            if allowed:
                response.headers["Access-Control-Allow-Origin"] = settings.portal_origin
        return response

    @app.exception_handler(HTTPException)
    async def error_page(request, exc):
        messages = {
            400: "Проверьте введённые данные.",
            403: "Действие недоступно. Обновите страницу и войдите снова при необходимости.",
            404: "Страница или пользователь не найдены.",
            409: "Действие доступно только на основном сервере.",
            413: "Слишком большой запрос.",
            415: "Неподдерживаемый формат запроса.",
        }
        message = exc.detail if isinstance(exc.detail, dict) else {"error": messages.get(exc.status_code, "Ошибка запроса.")}
        if request.url.path.startswith(CABINET_API + "/"):
            return JSONResponse(message, status_code=exc.status_code, headers=exc.headers)
        return page(request, "error.html", exc.status_code, message=message["error"])

    def require_csrf(request, form, context, value):
        origin = request.headers.get("origin")
        supplied = form.get("csrf", "")
        if (
            (origin is not None and origin != settings.origin)
            or not TOKEN_PATTERN.fullmatch(value)
            or not re.fullmatch(r"[a-f0-9]{64}", supplied)
            or not hmac.compare_digest(supplied, auth.sign(context, value))
        ):
            raise HTTPException(403)

    if settings.infrastructure_config:
        infrastructure.register_routes(app, settings, auth, page, read_form, require_csrf)

    def login_page(request, kind, status=200, error=None):
        nonce = request.cookies.get(LOGIN_COOKIE, "")
        if not TOKEN_PATTERN.fullmatch(nonce):
            nonce = token()
        response = page(request, "login.html", status, admin=kind == "admin", error=error,
                        csrf=auth.sign(f"login-{kind}", nonce))
        set_cookie(response, LOGIN_COOKIE, nonce, 900)
        return response

    @app.get("/")
    def index(request: Request):
        if settings.emergency_until is not None and now() >= settings.emergency_until:
            return page(request, "error.html", 503, message="Время работы временного резерва истекло.")
        session = request.cookies.get(SESSION_COOKIE, "")
        kind, account = auth.get_session(session)
        if kind == "admin":
            return RedirectResponse("/admin", 303)
        if kind is None:
            return login_page(request, "user")
        return cabinet(request, account, session)

    def reserve_access(account, issue=False):
        try:
            if reserve_links:
                if settings.emergency_until is not None:
                    account = dict(account)
                    current = account["access_until"]
                    account["access_until"] = min(current, settings.emergency_until) if current else settings.emergency_until
                return reserve_links.issue(account) if issue else reserve_links.status(account)
            if settings.emergency_controller:
                try:
                    try:
                        lease = admin_relay.exchange(settings.emergency_controller, None, "/status", timeout=4)
                    except admin_relay.RelayError:
                        lease = admin_relay.exchange(settings.emergency_controller, None, "/status", timeout=5)
                    if not isinstance(lease, dict):
                        raise ValueError
                    status = lease.get("status")
                    if status in ("idle", "ordering", "uncertain", "provision", "rejected", "cleaning", "finished"):
                        return {"inactive": True}
                    until = lease.get("until")
                    if status != "ready" or type(until) is not int:
                        raise ValueError
                    if until <= now() * 1000:
                        return {"inactive": True}
                    address = lease.get("url")
                    if not isinstance(address, str):
                        raise ValueError
                    url = urlsplit(address)
                    host = ipaddress.IPv4Address(url.hostname)
                    if not host.is_global or address != f"https://{host}/":
                        raise ValueError
                except (admin_relay.RelayError, ValueError, TypeError):
                    logger.warning("reserve_controller_status_unavailable")
                    return {"unavailable": True}
                return admin_relay.exchange(
                    f"https://{host}", temporary_relay_key, reserve.PATH,
                    {"account_id": account["id"], "auth_version": account["auth_version"],
                     "action": "issue" if issue else "status"}, timeout=20 if issue else 3,
                )
            if settings.reserve_origin:
                return admin_relay.exchange(
                    settings.reserve_origin, settings.admin_relay_key, reserve.PATH,
                    {"account_id": account["id"], "auth_version": account["auth_version"],
                     "action": "issue" if issue else "status"},
                    timeout=20 if issue else 3,
                )
        except (PanelError, admin_relay.RelayError):
            logger.warning("reserve_request_failed")
        return {"unavailable": True}

    def cabinet(request, account, session, *, report=None, status=200):
        return page(request, "cabinet.html", status, account=account,
                    subscription=subscription_url(settings, account) if account["config"] else None,
                    emergency_until=settings.emergency_until, reserve_available=False,
                    report=report, report_next=problem_reports.status(settings, account)["next_at"],
                    csrf=auth.sign("session", session))

    def report_problem(account):
        try:
            return problem_reports.enqueue(settings, account)
        except (OSError, sqlite3.Error):
            raise HTTPException(503, {"error": "Не удалось сохранить сообщение. Повторите попытку."}) from None

    @app.post("/report-problem")
    async def problem_post(request: Request):
        form = await read_form(request)
        def accept():
            session = request.cookies.get(SESSION_COOKIE, "")
            kind, account = auth.get_session(session)
            if kind != "user":
                raise HTTPException(403)
            require_csrf(request, form, "session", session)
            result = report_problem(account)
            return cabinet(request, account, session, report=result)
        return await run_in_threadpool(accept)

    @app.post("/reserve")
    def reserve_post():
        raise HTTPException(410, {"error": "Запрос запасной ссылки отключён. Используйте кнопку «Сообщить о проблеме»."})

    def reserve_from_peer(form):
        account = store.account("id", form.get("account_id", ""))
        if (not account or not account["enabled"] or not account["reserve_enabled"] or expired(account, now())
                or account["auth_version"] != form.get("auth_version")):
            return {"unavailable": True}
        return reserve_access(account, issue=form["action"] == "issue")

    @app.post(reserve.PATH)
    async def reserve_peer(request: Request):
        if not reserve_links:
            raise HTTPException(404)
        if settings.emergency_until is not None:
            if now() >= settings.emergency_until:
                raise HTTPException(404)
            supplied = request.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied.encode(), f"Bearer {temporary_relay_key}".encode()):
                raise HTTPException(403)
        elif settings.admin_primary_origin:
            require_peer(request)
        else:
            raise HTTPException(404)
        form = await read_form(request)
        if form.get("action") not in {"issue", "status"}:
            raise HTTPException(400)
        return await run_in_threadpool(reserve_from_peer, form)

    @app.get("/admin/login")
    def admin_login(request: Request):
        return login_page(request, "admin")

    def password_identity(request, form, kind):
        if kind == "user" and settings.emergency_until is not None and now() >= settings.emergency_until:
            raise HTTPException(503, {"error": "Время работы временного резерва истекло."})
        ip = request.client.host if request.client else "unknown"
        if request.url.path == CABINET_API + "/login" and settings.emergency_until is not None:
            forwarded = request.headers.get("X-Portal-Client-IP", "")
            signature = request.headers.get("X-Portal-Client-Signature", "")
            if len(forwarded) <= 45 and re.fullmatch(r"[a-f0-9]{64}", signature):
                expected = hmac.digest(settings.access_key, f"portal-proxy-ip-v1:{forwarded}".encode(), "sha256").hex()
                if hmac.compare_digest(signature, expected):
                    ip = forwarded
        if not auth.allow_attempt(kind, ip):
            raise HTTPException(429, {"error": "Слишком много попыток. Повторите через несколько минут."},
                                {"Retry-After": str(WINDOW)})
        password = form.get("password", "")
        account = None
        if kind == "user":
            password = password.strip()
            if not ACCESS_PATTERN.fullmatch(password):
                raise HTTPException(401, {"error": "Для входа в кабинет нужен пароль из 6 символов, выданный администратором."})
            account = store.account("access_index", access_index(settings.access_key, password))
            encoded = account["password_hash"] if account and account["enabled"] else auth.dummy_hash
            password = access_secret(settings.access_key, password)
        else:
            if not 1 <= len(password) <= 256:
                raise HTTPException(401, {"error": "Неверный пароль."})
            encoded = settings.admin_hash
        if not HASH_SLOTS.acquire(blocking=False):
            raise HTTPException(429, {"error": "Сервис занят. Повторите через несколько секунд."}, {"Retry-After": "3"})
        try:
            valid_password = verify(encoded, password)
        finally:
            HASH_SLOTS.release()
        if not valid_password or (kind == "user" and (account is None or not account["enabled"])):
            raise HTTPException(401, {"error": "Неверный пароль."})
        if kind == "user" and expired(account, now()):
            raise HTTPException(403, {"error": "Срок доступа истёк. Обратитесь к администратору для продления."})
        if kind == "user" and primary:
            password_vault.remember(store, settings.access_key, form.get("password", "").strip())
        return ("admin", auth.admin_version) if kind == "admin" else (account["id"], account["auth_version"])

    def authenticate(request, form, kind):
        require_csrf(request, form, f"login-{kind}", request.cookies.get(LOGIN_COOKIE, ""))
        try:
            subject, version = password_identity(request, form, kind)
        except HTTPException as exc:
            if exc.status_code == 503:
                return page(request, "error.html", 503, message=exc.detail["error"])
            response = login_page(request, kind, exc.status_code, exc.detail["error"])
            if exc.headers:
                response.headers.update(exc.headers)
            return response
        ttl = 1800 if kind == "admin" else 28800
        session = auth.create_session(subject, version, ttl, request.cookies.get(SESSION_COOKIE, ""))
        response = RedirectResponse("/admin" if kind == "admin" else "/", 303)
        set_cookie(response, SESSION_COOKIE, session, ttl)
        clear_cookie(response, LOGIN_COOKIE)
        return response

    @app.post("/login")
    async def user_login(request: Request):
        return await run_in_threadpool(authenticate, request, await read_form(request), "user")

    @app.post("/admin/login")
    async def admin_login_post(request: Request):
        return await run_in_threadpool(authenticate, request, await read_form(request), "admin")

    def portal_account(request):
        if settings.emergency_until is not None and now() >= settings.emergency_until:
            raise HTTPException(503, {"error": "Время работы временного резерва истекло."})
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            session = header.removeprefix("Bearer ")
            kind, account = auth.get_session(session)
            if kind == "user":
                return session, account
        raise HTTPException(401, {"error": "Войдите в кабинет повторно."})

    def portal_view(account):
        deadline = account["access_until"]
        return {
            "deadline": access_date(deadline).strftime("%d.%m.%Y") + " в 12:00 МСК" if deadline else "Бессрочно",
            "platform": account["platform"], "config": account["config"], "config_at": account["config_at"],
            "subscription": subscription_url(settings, account) if account["config"] else None,
            "temporary": bool(settings.emergency_until), "reserve_enabled": False,
            "problem_report": problem_reports.status(settings, account),
        }

    def open_portal(request, form):
        subject, version = password_identity(request, form, "user")
        return {"session": auth.create_session(subject, version, 28800, "")}

    @app.post(CABINET_API + "/login")
    async def portal_login(request: Request):
        return await run_in_threadpool(open_portal, request, await read_form(request))

    @app.get(CABINET_API + "/account")
    def portal_profile(request: Request):
        _, account = portal_account(request)
        return portal_view(account)

    @app.get("/sub/{account_id}/{signature}")
    def vpn_subscription(account_id: str, signature: str):
        if not re.fullmatch(r"[a-f0-9]{32}", account_id):
            raise HTTPException(404)
        account = store.account("id", account_id)
        if (not subscription_authorized(settings, account, signature) or not account["enabled"]
                or expired(account, now()) or not account["config"]
                or (settings.emergency_until is not None and now() >= settings.emergency_until)):
            raise HTTPException(404)
        links = [account["config"]]
        if isinstance(panel, PanelGroup) and panel.manages(account):
            links.extend(panel.additional_links(account))
        encoded = base64.b64encode(("\n".join(dict.fromkeys(links)) + "\n").encode())
        headers = {"Profile-Update-Interval": "1", "Content-Disposition": 'inline; filename="nodeguard.txt"'}
        if account["access_until"]:
            headers["Subscription-Userinfo"] = "expire=" + str(account["access_until"])
        return Response(encoded, media_type="text/plain", headers=headers)

    @app.post(CABINET_API + "/report-problem")
    def portal_problem(request: Request):
        _, account = portal_account(request)
        return report_problem(account)

    @app.post(CABINET_API + "/reserve")
    def portal_reserve(request: Request):
        portal_account(request)
        raise HTTPException(410, {"error": "Запрос запасной ссылки отключён. Используйте кнопку «Сообщить о проблеме»."})

    @app.post(CABINET_API + "/logout")
    def portal_logout(request: Request):
        session, _ = portal_account(request)
        auth.remove_session(session)
        return {"status": "ok"}

    def logout_session(request, form):
        session = request.cookies.get(SESSION_COOKIE, "")
        require_csrf(request, form, "session", session)
        auth.remove_session(session)
        response = RedirectResponse("/", 303)
        clear_cookie(response, SESSION_COOKIE)
        return response

    @app.post("/logout")
    async def logout(request: Request):
        return await run_in_threadpool(logout_session, request, await read_form(request))

    @app.get("/admin")
    def admin_panel(request: Request):
        session = request.cookies.get(SESSION_COOKIE, "")
        kind, _ = auth.get_session(session)
        if kind is None:
            return RedirectResponse("/admin/login", 303)
        if kind != "admin":
            raise HTTPException(403)
        accounts, audit, revision = account_overview()
        can_manage = primary
        if can_relay:
            try:
                overview = admin_relay.request(settings)
                accounts, audit = overview["users"], overview["audit"]
                can_manage = True
            except (admin_relay.RelayError, KeyError, TypeError):
                logger.warning("admin_relay_overview_unavailable")
        sync, stale, pending = sync_health(store, settings.role, revision, settings.stale_after)
        return page(request, "admin.html", users=accounts, audit=audit, revision=revision, sync=sync,
                    stale=stale, pending=pending, primary=primary, can_manage=can_manage,
                    infrastructure_enabled=bool(settings.infrastructure_config and primary),
                    replication_enabled=settings.replication_enabled,
                    csrf=auth.sign("session", session))

    def admin_mutation(request, form, action, account_id=None):
        session = request.cookies.get(SESSION_COOKIE, "")
        kind, _ = auth.get_session(session)
        if kind != "admin":
            raise HTTPException(403)
        require_csrf(request, form, "session", session)
        if not primary and not can_relay:
            raise HTTPException(409)
        if action == "show-password":
            if not primary:
                raise HTTPException(409)
            account = store.account("id", account_id)
            if account is None:
                raise HTTPException(404)
            password = password_vault.retrieve(store, settings.access_key, account)
            if password is None:
                return page(request, "error.html", 409, message="Ранее пароль сохранялся только в виде хэша. Он станет доступен после следующего успешного входа пользователя. Действующий пароль не изменён.")
            return page(request, "password.html", password=password, message="Текущий пароль пользователя", current=True)
        login = form.get("login", "").strip().lower()
        config = form.get("config", "").strip()
        platform = form.get("platform", DEFAULT_PLATFORM)
        reserve_enabled = form.get("reserve_enabled") == "1"
        until_date = form.get("access_date", "")
        if primary:
            result = mutate_account(action, account_id, login, config, platform, reserve_enabled, until_date)
        else:
            try:
                result = admin_relay.request(settings, {
                    "action": action, "account_id": account_id or "", "login": login, "config": config,
                    "platform": platform, "reserve_enabled": "1" if reserve_enabled else "0",
                    "access_date": until_date,
                })
            except admin_relay.RelayError:
                logger.warning("admin_relay_mutation_unavailable")
                return page(request, "error.html", 503,
                            message="Основной сервер не подтвердил операцию. Проверьте состояние учётной записи.")
        status = result["status"]
        if "password" in result:
            return page(request, "password.html", password=result["password"], message=ACTIONS[action])
        if "message" in result:
            return page(request, "error.html", status, message=result["message"])
        if status == 303:
            if action in {"access", "extend"}:
                return RedirectResponse(f"/admin?user={account_id}#user-{account_id}", 303)
            return RedirectResponse("/admin", 303)
        raise HTTPException(status)

    def mutate_account(action, account_id, login, config, platform, reserve_enabled, until_date):
        if action == "reserve":
            return {"status": 410, "message": "Настройка запасного подключения больше не используется."}
        if action not in ACTIONS and action != "extend":
            return {"status": 404}
        if action == "create" and account_id is not None:
            return {"status": 404}
        if action != "create" and not re.fullmatch(r"[a-f0-9]{32}", account_id or ""):
            return {"status": 404}
        if action == "create" and (not LOGIN_PATTERN.fullmatch(login) or login == "admin"):
            return {"status": 400, "message": "Имя должно содержать от 3 до 32 латинских букв, цифр, точек, дефисов или знаков подчёркивания. Начните с буквы или цифры."}
        if action == "create" and platform not in PLATFORMS:
            return {"status": 400, "message": "Выберите систему устройства из списка."}
        if action == "config" and (
            len(config.encode()) > MAX_CONFIG
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:[^\s\x00-\x1f\x7f]+", config)
        ):
            return {"status": 400, "message": "Введите конфигурационную ссылку без пробелов, до 8 КБ."}
        deadline = None
        if action == "access":
            try:
                if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", until_date):
                    raise ValueError
                day = date.fromisoformat(until_date)
                deadline = noon(day), day.day
                if deadline[0] <= 0:
                    raise ValueError
            except (ValueError, OverflowError, OSError):
                return {"status": 400, "message": "Укажите корректную дату окончания доступа."}
        with admin_write_lock:
            if (settings.data_dir / "vpn-publication-maintenance").exists():
                return {"status": 503, "message": "Обновляем VPN-узел. Повторите операцию через минуту."}
            return change_account(action, account_id, login, config, platform, reserve_enabled, deadline)

    def change_account(action, account_id, login, config, platform, reserve_enabled, deadline):
        provisioned_id = None
        saved = False
        try:
            if action in {"create", "password"}:
                access_until = access_day = None
                if action == "create":
                    timestamp = now()
                    access_day = access_date(timestamp).day
                    access_until = next_month(timestamp, access_day)
                if action == "create" and panel:
                    if store.account("login", login):
                        return {"status": 409, "message": "Это имя уже используется."}
                    account_id = uuid4().hex
                    config = issue_client(account_id, login, platform, access_until)
                    provisioned_id = account_id
                for _ in range(10):
                    password, index, encoded = make_user_password(settings.access_key)
                    password_vault.remember(store, settings.access_key, password)
                    try:
                        store.change(action, account_id=account_id, login=login,
                                     access_index=index, password_hash=encoded,
                                     config=config if provisioned_id else None, platform=platform,
                                     reserve_enabled=reserve_enabled, access_until=access_until, access_day=access_day)
                    except CodeAlreadyIssued:
                        continue
                    saved = True
                    return {"status": 200, "password": password}
                raise RuntimeError("Could not allocate an unused password")
            if action in {"access", "extend"}:
                account = store.account("id", account_id)
                if account is None:
                    raise LookupError
                if action == "extend":
                    base = account["access_until"] or now()
                    day = account["access_day"] or access_date(base).day
                    try:
                        deadline = next_month(base, day), day
                    except ValueError:
                        return {"status": 400, "message": "Следующий месяц выходит за допустимый диапазон дат."}
                access_until, day = deadline
                if action == "access" and access_until == account["access_until"]:
                    return {"status": 303}
                if panel and account["enabled"] and panel.manages(account):
                    enabled = access_until > now()
                    if not panel.set_expiry(account_id, access_until, enabled=enabled) and enabled:
                        issue_client(account_id, account["login"], account["platform"], access_until)
                store.change("access", account_id=account_id, access_until=access_until, access_day=day)
                return {"status": 303}
            if panel and action in {"config", "enable", "revoke", "delete"}:
                account = store.account("id", account_id)
                if account and panel.manages(account):
                    if action == "config":
                        return {"status": 409, "message": "Эта ссылка управляется через 3x-ui."}
                    if action == "enable" and not expired(account, now()):
                        platform = account["platform"]
                        panel.issue(account_id, account["access_until"] or 0,
                                    comment=account_comment(account["login"], platform), platform=platform)
                    elif action in {"revoke", "delete"}:
                        panel.remove(account_id)
            store.change(action, account_id=account_id, config=config, reserve_enabled=reserve_enabled)
        except PanelError as exc:
            logger.error("panel_request_failed reason=%s", exc)
            return {"status": 503, "message": PANEL_FAILURE}
        except LookupError:
            return {"status": 404}
        except sqlite3.IntegrityError:
            if action != "create":
                raise
            return {"status": 409, "message": "Это имя уже используется."}
        finally:
            if provisioned_id and not saved:
                cleanup_client(provisioned_id)
        return {"status": 303}

    def require_relay(request):
        if not primary:
            raise HTTPException(404)
        require_peer(request)

    def require_peer(request):
        if not settings.admin_relay_key:
            raise HTTPException(404)
        if settings.admin_peer_ip and (request.client is None or request.client.host != settings.admin_peer_ip):
            raise HTTPException(403)
        supplied = request.headers.get("authorization", "").encode("utf-8")
        expected = f"Bearer {settings.admin_relay_key}".encode("ascii")
        if not hmac.compare_digest(supplied, expected):
            raise HTTPException(403)

    @app.get(admin_relay.PATH)
    def relay_overview(request: Request):
        require_relay(request)
        users, audit, _ = account_overview()
        return {"users": users, "audit": audit}

    @app.post(admin_relay.PATH)
    async def relay_mutation(request: Request):
        require_relay(request)
        form = await read_form(request)
        return await run_in_threadpool(mutate_account, form.get("action", ""), form.get("account_id") or None,
                                       form.get("login", ""), form.get("config", ""),
                                       form.get("platform", DEFAULT_PLATFORM), form.get("reserve_enabled") == "1",
                                       form.get("access_date", ""))

    @app.post("/admin/users")
    async def create_user(request: Request):
        return await run_in_threadpool(admin_mutation, request, await read_form(request), "create")

    @app.post("/admin/users/{account_id}/{action}")
    async def update_user(request: Request, account_id: str, action: str):
        if action == "create":
            raise HTTPException(404)
        return await run_in_threadpool(admin_mutation, request, await read_form(request), action, account_id)

    @app.get(CABINET_API + "/health")
    @app.get("/health")
    def health():
        if settings.emergency_until is not None and now() >= settings.emergency_until:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        try:
            with connect(store.data, "ro") as connection:
                state = connection.execute("SELECT change_id, access_key_id FROM state").fetchone()
                connection.execute("SELECT id FROM accounts LIMIT 1").fetchone()
            with connect(store.local, "ro") as connection:
                connection.execute("SELECT token_hash FROM sessions LIMIT 1").fetchone()
            if state and state["change_id"] and state["access_key_id"] == settings.access_key_id:
                return JSONResponse({"status": "ok"})
        except sqlite3.Error as exc:
            logger.error("health_failed sqlite=%s", getattr(exc, "sqlite_errorname", "SQLITE_ERROR"))
        return JSONResponse({"status": "unavailable"}, status_code=503)

    return app
