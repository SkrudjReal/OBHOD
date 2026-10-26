from __future__ import annotations

import logging
from typing import Any

from . import inline, xscreens
from .inline import InlineError
from .scan import DEFAULT_CANDIDATES, ScanError, ScanResult, best_candidate, scan_targets
from .xray import (
    NETWORKS,
    XRAY_VERSION,
    PROTOCOLS,
    SECURITIES,
    XrayError,
    XrayInbound,
    XrayState,
    gen_short_id,
    link_for,
    new_inbound,
    valid_email,
    valid_short_id,
    x25519_keypair,
)
from .xrayrpc import DEFAULT_VERSION, CoreState, XrayControl, XrayError as RpcError
from .validate import ValidationError

log = logging.getLogger("obhod.xray")

SCAN_LIMIT = 24
FIELD_NAMES = frozenset(inline.FIELDS)
LEVELS = ("debug", "info", "warning", "error")


class PanelError(Exception):
    pass


class XrayPanel:
    def __init__(self, bot: Any, control: XrayControl | None = None) -> None:
        self.bot = bot
        self.control = control or XrayControl()
        self.core: dict[str, Any] = dict(bot.state.xray.last_core)
        self.draft: dict[str, str] = {}
        self.results: list[ScanResult] = [ScanResult.from_dict(item) for item in bot.state.xray.scan_results]

    @property
    def state(self) -> XrayState:
        return self.bot.state.xray

    def save(self) -> None:
        self.state.last_core = dict(self.core)
        self.state.scan_results = [item.to_dict() for item in self.results]
        self.bot.save()

    def view(self, notice: str = "", error: str = "") -> xscreens.XrayView:
        item = xscreens.XrayView(state=self.state, core=dict(self.core), notice=notice, error=error)
        item.draft = dict(self.draft)
        return item

    async def render(self, chat_id: int, msg_id: int, rich: Any) -> None:
        await self.bot.render(chat_id, msg_id, rich)

    async def send(self, chat_id: int, rich: Any) -> None:
        await self.bot.send(chat_id, rich)

    def address_of(self, inbound: XrayInbound) -> str:
        host = self.bot.state.opts.host or self.bot.state.ssh.host
        return f"{host}:{int(inbound.port)}"

    def links_of(self, inbound: XrayInbound) -> list[tuple[str, str]]:
        address = self.bot.state.opts.host or self.bot.state.ssh.host
        out: list[tuple[str, str]] = []
        for client in inbound.clients:
            try:
                out.append((client.email, link_for(inbound, client, address, inbound.port)))
            except XrayError as exc:
                log.warning("link failed: %s", exc)
        return out

    def link_of(self, inbound: XrayInbound, email: str) -> str:
        client = inbound.client(email)
        if client is None:
            return ""
        address = self.bot.state.opts.host or self.bot.state.ssh.host
        try:
            return link_for(inbound, client, address, inbound.port)
        except XrayError:
            return ""

    def require_ssh(self) -> None:
        if not self.bot.state.ssh.is_ready():
            raise PanelError("сначала заполните доступ по ssh в разделе SSH")

    def next_port(self) -> int:
        used = set(self.state.ports())
        for port in (443, 8443, 2053, 2083, 2087, 2096, 24443, 30443):
            if port not in used:
                return port
        port = 30000
        while port in used:
            port += 1
        return port

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        parts = data.split(":")
        head = parts[1] if len(parts) > 1 else "home"
        arg1 = parts[2] if len(parts) > 2 else ""
        arg2 = parts[3] if len(parts) > 3 else ""
        if head == "home":
            await self.render(chat_id, msg_id, xscreens.home(self.view()))
            return
        if head == "check":
            await self.check(chat_id, msg_id)
            return
        if head == "new":
            if not arg1:
                await self.render(chat_id, msg_id, xscreens.new_menu(self.view()))
                return
            await self.create_quick(chat_id, msg_id, arg1, arg2 or "reality", parts[4] if len(parts) > 4 else "")
            return
        if head == "custom":
            self.draft = {"protocol": "vless", "network": "tcp", "security": "reality", "port": str(self.next_port())}
            await self.render(chat_id, msg_id, xscreens.custom_menu(self.view()))
            return
        if head == "cyc":
            self.cycle(arg1)
            await self.render(chat_id, msg_id, xscreens.custom_menu(self.view()))
            return
        if head == "create":
            await self.create_custom(chat_id, msg_id)
            return
        if head == "in":
            await self.open_inbound(chat_id, msg_id, arg1)
            return
        if head == "edit":
            await self.render(chat_id, msg_id, xscreens.input_screen(self.view(), arg2, arg1, f"xr:in:{arg1}"))
            return
        if head == "toggle":
            await self.toggle(chat_id, msg_id, arg1)
            return
        if head == "keys":
            await self.regen_keys(chat_id, msg_id, arg1)
            return
        if head == "del":
            await self.render(
                chat_id,
                msg_id,
                xscreens.confirm_screen(self.view(), "Удаление инбаунда", f"инбаунд {arg1} будет удален из конфигурации", f"xr:del2:{arg1}"),
            )
            return
        if head == "del2":
            await self.delete_inbound(chat_id, msg_id, arg1)
            return
        if head == "cladd":
            await self.render(chat_id, msg_id, xscreens.input_screen(self.view(), "xr_client_email", arg1, f"xr:in:{arg1}"))
            return
        if head == "cl":
            await self.open_client(chat_id, msg_id, arg1, ":".join(parts[3:]))
            return
        if head == "cldel":
            await self.delete_client(chat_id, msg_id, arg1, ":".join(parts[3:]))
            return
        if head == "link":
            await self.show_links(chat_id, msg_id, arg1)
            return
        if head == "core":
            await self.core_action(chat_id, msg_id, arg1, arg2)
            return
        if head == "logs":
            await self.logs(chat_id, msg_id, arg1)
            return
        if head == "scan":
            await self.scan_action(chat_id, msg_id, arg1, arg2)
            return
        await self.render(chat_id, msg_id, xscreens.home(self.view(notice="неизвестное действие xray")))

    def cycle(self, key: str) -> None:
        options = {
            "protocol": PROTOCOLS,
            "network": NETWORKS,
            "security": SECURITIES,
        }
        values = options.get(key)
        if not values:
            return
        current = self.draft.get(key, values[0])
        index = values.index(current) if current in values else 0
        self.draft[key] = values[(index + 1) % len(values)]

    async def create_quick(self, chat_id: int, msg_id: int, protocol: str, security: str, network: str = "") -> None:
        if protocol not in PROTOCOLS:
            raise PanelError(f"протокол {protocol} не поддерживается")
        if security not in SECURITIES:
            raise PanelError(f"безопасность {security} не поддерживается")
        net = network or "tcp"
        if net not in NETWORKS:
            raise PanelError(f"сеть {net} не поддерживается")
        try:
            inbound = new_inbound(protocol, self.next_port(), net, security)
            self.state.add(inbound)
        except XrayError as exc:
            raise PanelError(str(exc)) from None
        if not inbound.clients:
            inbound.make_client("owner")
        self.save()
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice="инбаунд создан"), inbound))

    async def create_custom(self, chat_id: int, msg_id: int) -> None:
        draft = dict(self.draft)
        protocol = draft.get("protocol", "vless")
        network = draft.get("network", "tcp")
        security = draft.get("security", "reality")
        port = int(draft.get("port") or self.next_port())
        try:
            inbound = new_inbound(protocol, port, network, security)
            self.state.add(inbound)
        except (XrayError, ValueError) as exc:
            raise PanelError(str(exc)) from None
        inbound.make_client("owner")
        self.draft = {}
        self.save()
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice="инбаунд создан"), inbound))

    def get(self, ident: str) -> XrayInbound:
        item = self.state.inbound(ident)
        if item is None:
            raise PanelError(f"инбаунд {ident} не найден")
        return item

    async def open_inbound(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(), inbound))

    async def toggle(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        inbound.enable = not inbound.enable
        self.save()
        await self.render(
            chat_id,
            msg_id,
            xscreens.inbound_screen(self.view(notice="инбаунд включен" if inbound.enable else "инбаунд выключен"), inbound),
        )

    async def regen_keys(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        if inbound.security != "reality":
            await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(error="ключи reality нужны только для reality"), inbound))
            return
        private = ""
        public = ""
        if self.core.get("installed"):
            try:
                private, public = await self.control.x25519(self.bot.state.ssh)
            except RpcError as exc:
                log.warning("remote x25519 failed: %s", exc.message)
        if not private or not public:
            private, public = x25519_keypair()
        inbound.private_key = private
        inbound.public_key = public
        inbound.short_ids = [gen_short_id()]
        self.save()
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice="ключи reality обновлены"), inbound))

    async def delete_inbound(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        remark = inbound.remark
        self.state.remove(ident)
        self.save()
        await self.render(chat_id, msg_id, xscreens.home(self.view(notice=f"инбаунд {remark} удален")))

    async def open_client(self, chat_id: int, msg_id: int, ident: str, email: str) -> None:
        inbound = self.get(ident)
        clean = email.split(":")[-1].strip()
        link = self.link_of(inbound, clean)
        await self.render(chat_id, msg_id, xscreens.client_screen(self.view(), inbound, clean, link))

    async def delete_client(self, chat_id: int, msg_id: int, ident: str, email: str) -> None:
        inbound = self.get(ident)
        clean = email.split(":")[-1].strip()
        if not inbound.remove_client(clean):
            raise PanelError(f"клиент {clean} не найден")
        self.save()
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice=f"клиент {clean} удален"), inbound))

    async def show_links(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        links = self.links_of(inbound)
        await self.render(chat_id, msg_id, xscreens.links_screen(self.view(), inbound, self.address_of(inbound), links))

    async def check(self, chat_id: int, msg_id: int) -> None:
        self.require_ssh()
        await self.render(chat_id, msg_id, xscreens.busy_screen("чтение состояния ядра"))
        try:
            state = await self.control.probe(self.bot.state.ssh)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message)))
            return
        self.core = state_report(state)
        self.save()
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice="состояние ядра прочитано")))

    async def core_action(self, chat_id: int, msg_id: int, action: str, extra: str) -> None:
        if action in {"", "open"}:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view()))
            return
        self.require_ssh()
        if action == "purge":
            await self.render(
                chat_id,
                msg_id,
                xscreens.confirm_screen(self.view(), "Удаление ядра", "ядро, конфигурация и служба будут удалены", "xr:core:purge2"),
                )
            return
        if action == "install":
            await self.install_core(chat_id, msg_id)
            return
        if action == "apply":
            await self.apply(chat_id, msg_id)
            return
        if action == "restart":
            await self.run_core(chat_id, msg_id, "перезапуск ядра", self.control.restart)
            return
        if action == "stop":
            await self.run_core(chat_id, msg_id, "остановка ядра", self.control.stop)
            return
        if action == "ver":
            choice = extra if extra else XRAY_VERSION
            if choice.lower() != "latest" and choice != XRAY_VERSION:
                await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error="неизвестная версия ядра")))
                return
            self.state.version = "latest" if choice.lower() == "latest" else XRAY_VERSION
            self.save()
            await self.render(
                chat_id,
                msg_id,
                xscreens.core_screen(self.view(notice="выбрана версия ядра " + self.state.version)),
            )
            return
        if action in {"purge2"}:
            await self.purge(chat_id, msg_id)
            return
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view()))

    async def install_core(self, chat_id: int, msg_id: int) -> None:
        version = self.state.version or DEFAULT_VERSION
        await self.render(chat_id, msg_id, xscreens.busy_screen(f"установка ядра {version}", ["загрузка релиза", "проверка хеша", "распаковка"]))
        try:
            response = await self.control.install_core(self.bot.state.ssh, version, force=True)
            logs = response.logs
            state = CoreState.from_dict(response.data)
        except RpcError as exc:
            fallback = exc.code == "download_failed"
            hint = "проверьте доступ к github с сервера" if fallback else ""
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message + (" " + hint if hint else ""))))
            return
        self.core = state_report(state)
        self.save()
        notice = f"ядро {self.core.get('version', version)} установлено"
        if logs:
            notice = notice + ", шагов " + str(len(logs))
        if state.fallback:
            notice = notice + ", последний релиз недоступен, взят закрепленный " + (state.fallback_version or DEFAULT_VERSION)
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice=notice)))

    async def apply(self, chat_id: int, msg_id: int) -> None:
        if not self.state.inbounds:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error="нет инбаундов, применять нечего")))
            return
        try:
            config = self.state.to_config()
        except XrayError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=str(exc))))
            return
        version = self.state.version or DEFAULT_VERSION
        await self.render(chat_id, msg_id, xscreens.busy_screen("запись конфигурации", ["проверка конфигурации", "перезапуск службы"]))
        try:
            state = await self.control.apply(self.bot.state.ssh, config, version=version)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message)))
            return
        self.core = state_report(state)
        self.save()
        ports = ", ".join(str(item) for item in self.core.get("listening") or [])
        notice = "конфигурация применена" + (f", слушают {ports}" if ports else "")
        if state.fallback:
            notice = notice + ", ядро взято из закрепленного " + (state.fallback_version or DEFAULT_VERSION)
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice=notice)))

    async def run_core(self, chat_id: int, msg_id: int, title: str, action: Any) -> None:
        await self.render(chat_id, msg_id, xscreens.busy_screen(title))
        try:
            state = await action(self.bot.state.ssh)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message)))
            return
        self.core = state_report(state)
        self.save()
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice=title + " выполнен")))

    async def purge(self, chat_id: int, msg_id: int) -> None:
        await self.render(chat_id, msg_id, xscreens.busy_screen("удаление ядра"))
        try:
            await self.control.uninstall(self.bot.state.ssh)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message)))
            return
        self.core = {}
        self.save()
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice="ядро удалено с сервера")))

    async def logs(self, chat_id: int, msg_id: int, tail: str) -> None:
        self.require_ssh()
        size = 200
        if tail:
            try:
                size = max(20, min(2000, int(tail)))
            except ValueError:
                size = 200
        try:
            lines = await self.control.logs(self.bot.state.ssh, size)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.logs_screen(self.view(error=exc.message), [], size))
            return
        await self.render(chat_id, msg_id, xscreens.logs_screen(self.view(), lines, size))

    async def scan_action(self, chat_id: int, msg_id: int, action: str, extra: str) -> None:
        if not action:
            await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(), self.results))
            return
        if action == "targets":
            await self.render(chat_id, msg_id, xscreens.scan_targets_screen(self.view()))
            return
        if action == "reset":
            self.state.scan_targets = list(DEFAULT_CANDIDATES)
            self.results = []
            self.save()
            await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(notice="список целей сброшен")))
            return
        if action == "run":
            await self.run_scan(chat_id, msg_id, self.state.scan_targets)
            return
        if action == "use":
            await self.use_target(chat_id, msg_id, extra)
            return
        await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(), self.results))

    async def run_scan(self, chat_id: int, msg_id: int, targets: list[str]) -> None:
        clean = [item for item in targets if item.strip()][:SCAN_LIMIT]
        if not clean:
            await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(error="список целей пуст"), self.results))
            return
        await self.render(chat_id, msg_id, xscreens.busy_screen("сканирование целей", [f"целей {len(clean)}", "проверка tls 1.3 и x25519"]))
        try:
            results = await scan_targets(clean, concurrency=16)
        except ScanError as exc:
            await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(error=str(exc)), self.results))
            return
        self.results = results
        self.save()
        good = sum(1 for item in results if item.feasible)
        await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(notice=f"годных целей {good} из {len(results)}"), results))

    async def use_target(self, chat_id: int, msg_id: int, index: str) -> None:
        try:
            position = int(index)
        except (TypeError, ValueError):
            raise PanelError("неверный номер цели") from None
        if position < 0 or position >= len(self.results):
            raise PanelError("цель не найдена")
        result = self.results[position]
        inbound = next((item for item in self.state.inbounds if item.security == "reality"), None)
        if inbound is None:
            inbound = self.state.inbounds[0] if self.state.inbounds else None
        if inbound is None:
            await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(error="сначала создайте reality инбаунд"), self.results))
            return
        sni = (result.server_names[0] if result.server_names else "") or result.host or result.target
        inbound.dest = f"{result.host or result.target}:{result.port}"
        inbound.sni = sni
        self.save()
        await self.render(
            chat_id,
            msg_id,
            xscreens.inbound_screen(self.view(notice=f"цель {result.target} применена к инбаунду {inbound.remark}"), inbound),
        )

    def set_field(self, ident: str, ctx: str, value: str) -> str:
        if ident not in FIELD_NAMES:
            raise PanelError(f"поле {ident} не поддерживается")
        inbound = self.state.inbound(ctx) if ctx else None
        if ident.startswith("xr_") and ident not in {"xr_scan_targets", "xr_scan_manual", "xr_log_level"} and inbound is None:
            raise PanelError("инбаунд для ввода не найден")
        if ident == "xr_port":
            port = parse_port(value)
            if port != inbound.port:
                for item in self.state.inbounds:
                    if item.port == port and item.id != inbound.id:
                        raise PanelError(f"порт {port} занят инбаундом {item.remark}")
            inbound.port = port
            return f"порт {port} обновлен"
        if ident == "xr_remark":
            if not value:
                raise PanelError("имя не может быть пустым")
            if len(value) > 40:
                raise PanelError("имя не длиннее 40 символов")
            inbound.remark = value
            inbound.tag = f"in-{inbound.port}-{inbound.network}-{inbound.protocol}"
            return "имя обновлено"
        if ident == "xr_sni":
            if not value:
                raise PanelError("server name не может быть пустым")
            inbound.sni = value
            inbound.dest = f"{value}:443" if not inbound.dest else inbound.dest
            return f"server name {value} обновлен"
        if ident == "xr_dest":
            host, port = host_port(value)
            inbound.dest = f"{host}:{port}"
            return f"dest {host}:{port} обновлен"
        if ident == "xr_short_id":
            inbound.short_ids = [valid_short_id(value or "")]
            return "short id обновлен"
        if ident == "xr_private_key":
            inbound.private_key = value.strip()
            return "приватный ключ обновлен"
        if ident == "xr_public_key":
            inbound.public_key = value.strip()
            return "публичный ключ обновлен"
        if ident == "xr_path":
            inbound.path = ensure_slash(value)
            return f"путь {inbound.path} обновлен"
        if ident == "xr_host_header":
            inbound.host_header = value.strip()
            return "заголовок host обновлен"
        if ident == "xr_service":
            inbound.service_name = value.strip()
            return "имя сервиса обновлено"
        if ident == "xr_scan_targets":
            targets = [item.strip() for item in value.split(",") if item.strip()]
            if not targets:
                raise PanelError("список целей пуст")
            if len(targets) > SCAN_LIMIT:
                raise PanelError(f"не больше {SCAN_LIMIT} целей")
            self.state.scan_targets = targets
            return f"целей в списке {len(targets)}"
        if ident == "xr_scan_manual":
            host, port = host_port(value)
            target = f"{host}:{port}"
            if target not in self.state.scan_targets:
                self.state.scan_targets.append(target)
            return f"цель {target} добавлена"
        if ident == "xr_log_level":
            level = (value or "").strip().lower()
            if level not in LEVELS:
                raise PanelError("уровень: debug, info, warning или error")
            self.state.log_level = level
            return f"уровень логов {level}"
        if ident == "xr_client_email":
            email = valid_email(value or "")
            if inbound is None:
                raise PanelError("инбаунд не найден")
            if inbound.client(email) is not None:
                raise PanelError(f"клиент {email} уже есть")
            inbound.make_client(email)
            return f"клиент {email} добавлен"
        raise PanelError(f"поле {ident} не поддерживается")

    async def apply_input(self, chat_id: int, ident: str, ctx: str, value: str) -> None:
        if ident == inline.CANCEL:
            await self.send(chat_id, xscreens.home(self.view(notice="ввод отменен")))
            return
        try:
            notice = self.set_field(ident, ctx, value)
        except (PanelError, XrayError, ValidationError, InlineError) as exc:
            await self.send(chat_id, self.error_screen(ident, ctx, str(exc)))
            return
        self.save()
        await self.send(chat_id, self.screen_for(ident, ctx, notice))

    def error_screen(self, ident: str, ctx: str, message: str) -> Any:
        target = self.back_target(ctx)
        view = self.view(error=message)
        try:
            return xscreens.input_screen(view, ident, ctx, target)
        except InlineError:
            return xscreens.home(self.view(error=message))

    def back_target(self, ctx: str) -> str:
        return f"xr:in:{ctx}" if ctx else "xr:home"

    def screen_for(self, ident: str, ctx: str, notice: str) -> Any:
        inbound = self.state.inbound(ctx) if ctx else None
        if inbound is not None:
            return xscreens.inbound_screen(self.view(notice=notice), inbound)
        if ident in {"xr_scan_targets", "xr_scan_manual"}:
            return xscreens.scan_targets_screen(self.view(notice=notice))
        if ident == "xr_log_level":
            return xscreens.core_screen(self.view(notice=notice))
        return xscreens.home(self.view(notice=notice))

    async def ssh_input(self, chat_id: int, ident: str, value: str) -> None:
        from .flows import Flows

        flows = Flows()
        try:
            notice = flows.apply_field(self.bot.state, ident, value)
        except (ValidationError, XrayError) as exc:
            await self.send(chat_id, xscreens.input_screen(self.view(error=str(exc)), ident, "", "xr:home"))
            return
        self.bot.save()
        await self.send(chat_id, xscreens.home(self.view(notice=notice)))


def host_port(value: object) -> tuple[str, int]:
    text = str(value or "").strip()
    if not text:
        raise PanelError("нужен адрес вида host:port")
    host = text
    port = 443
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        rest = rest.lstrip(":")
        if rest:
            port = parse_port(rest)
    elif text.count(":") == 1:
        host, raw_port = text.split(":", 1)
        port = parse_port(raw_port)
    host = host.strip()
    if not host or any(char.isspace() for char in host):
        raise PanelError("адрес не должен содержать пробелов")
    return host, port


def parse_port(value: object) -> int:
    text = str(value or "").strip()
    if not text.isdigit():
        raise PanelError("порт должен быть числом")
    port = int(text)
    if port < 1 or port > 65535:
        raise PanelError("порт от 1 до 65535")
    return port


def ensure_slash(value: str) -> str:
    text = (value or "/").strip() or "/"
    return text if text.startswith("/") else "/" + text


def state_report(state: CoreState) -> dict[str, Any]:
    return {
        "installed": state.installed,
        "version": state.version,
        "pinned": state.pinned,
        "core_path": state.core_path,
        "config_path": state.config_path,
        "config_exists": state.config_exists,
        "config_digest": state.config_digest,
        "inbounds": state.inbounds,
        "port": state.port,
        "ports": state.ports,
        "listening": state.listening,
        "service": state.service,
        "unit": state.unit,
        "systemd": state.systemd,
        "arch": state.arch,
    }


def best_of(results: list[ScanResult]) -> ScanResult | None:
    if not results:
        return None
    return best_candidate(results)
