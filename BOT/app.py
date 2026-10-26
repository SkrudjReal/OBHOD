from __future__ import annotations

import base64
import logging

from goygram import GoyGram

from . import screens
from .config import Config, ConfigError
from .control import ControlClient, ControlError, ControlResponse
from .drafts import Draft
from .flows import Flows
from .links import LinkError, build_link, link_rows, normalize_conf, parse_link
from .models import ClientInfo, ProbeResult, ShareInfo
from .store import State, Store
from .ui import button, code, muted, quote, row, screen
from . import validate
from .validate import ValidationError

log = logging.getLogger("obhod.app")

DRAFT_ID = 1
SECRET_FIELDS = {"ssh_password", "ssh_key", "ssh_passphrase", "ssh_sudo"}


class Bot:
    def __init__(self, cfg: Config, control: ControlClient | None = None) -> None:
        self.cfg = cfg
        self.store = Store(cfg.state_dir / "state.json")
        self.state: State = self.store.load()
        self.control = control or ControlClient(cfg)
        self.flows = Flows()
        self.app: GoyGram | None = None
        self.probe: ProbeResult | None = None
        self.clients: list[ClientInfo] = []
        self.share: ShareInfo | None = None
        self.pending: dict[int, str] = {}
        self.busy = False

    @property
    def admin_id(self) -> int:
        return int(self.cfg.admin_id or self.state.admin_id or 0)

    def view(self, notice: str = "", error: str = "") -> screens.View:
        return screens.View(
            state=self.state,
            probe=self.probe,
            clients=list(self.clients),
            share=self.share,
            notice=notice,
            error=error,
        )

    def save(self) -> None:
        self.store.save(self.state)

    async def boot(self) -> GoyGram:
        app = GoyGram(
            bot_token=self.cfg.bot_token,
            api_id=self.cfg.api_id,
            api_hash=self.cfg.api_hash,
            session_name=self.cfg.session_name,
            default_transport="mtproto",
            intake="mtproto",
            app_name="OBHOD",
            app_version="2.0",
            device_model="desktop",
            system_version="linux",
            mt_host=self.cfg.dc_host,
            mt_port=self.cfg.dc_port,
        )
        app.on_msg(fn=self.on_message)
        app.on_cb(fn=self.on_callback)
        app.on_cmd("start", "menu", "help", "id")(self.on_command)
        self.app = app
        return app

    async def run(self) -> None:
        app = await self.boot()
        await app.run()

    async def send(self, chat_id: int, rich: object) -> None:
        if self.app is None:
            return
        await self.app.send_rich(chat_id, rich, via="mt")

    async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
        if self.app is None:
            return
        if msg_id:
            try:
                await self.app.edit_rich(chat_id, msg_id, rich, via="mt")
                return
            except Exception as exc:
                log.warning("edit failed: %s", exc)
        await self.send(chat_id, rich)

    async def toast(self, evt: object, text: str, alert: bool = False) -> None:
        try:
            await evt.answer(text or "готово", alert=alert)
        except Exception as exc:
            log.debug("answer failed: %s", exc)

    async def guard(self, evt: object) -> bool:
        who = int(getattr(evt, "from_id", 0) or 0)
        if self.admin_id == 0:
            if who > 0:
                self.state.admin_id = who
                self.save()
                log.info("admin claimed: %s", who)
            return True
        if who == self.admin_id:
            return True
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        await self.send(chat_id, screens.denied())
        return False

    async def on_message(self, evt: object) -> None:
        if not await self.guard(evt):
            return
        if self.busy:
            await self.toast(evt, "дождитесь завершения операции", alert=True)
            return
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        text = str(getattr(evt, "text", "") or "").strip()
        who = int(getattr(evt, "from_id", 0) or 0)
        if who in self.pending:
            await self.accept_text(chat_id, text)
            return
        if text.lower().startswith("freeturn://"):
            await self.do_import(chat_id, text)
            return
        if text.startswith("/"):
            await self.on_command(evt)
            return
        await self.send(chat_id, screens.home(self.view(notice="выберите действие")))

    async def on_command(self, evt: object) -> None:
        if not await self.guard(evt):
            return
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        cmd = str(getattr(evt, "cmd", "") or "").lower()
        text = str(getattr(evt, "text", "") or "")
        if not cmd and text.startswith("/"):
            cmd = text.split()[0][1:].split("@")[0].lower()
        if cmd == "id":
            who = int(getattr(evt, "from_id", 0) or 0)
            rich = screen(
                "Идентификатор",
                "ваш numeric id",
                [f"<p>{code(who)}</p>", quote(muted("этот id задается в конфигурации как ADMIN_ID"))],
                [row(button("Главная", "nav:home"))],
            )
            await self.send(chat_id, rich)
            return
        if cmd == "help":
            await self.send(chat_id, screens.help_screen(self.view()))
            return
        await self.send(chat_id, screens.home(self.view()))

    async def accept_text(self, chat_id: int, text: str) -> None:
        who = self.admin_id
        field = self.pending.pop(who, None)
        if field is None:
            await self.send(chat_id, screens.home(self.view()))
            return
        if field == "client_name":
            await self.do_add_client(chat_id, text)
            return
        try:
            notice = self.flows.apply_field(self.state, field, text)
        except (ValidationError, ConfigError) as exc:
            self.pending[who] = field
            await self.send(chat_id, screens.prompt(self.flows.field(field), error=str(exc)))
            return
        self.save()
        self.pending.pop(who, None)
        target = self.flows.target(field)
        if field in SECRET_FIELDS:
            notice = notice + ", доступ обновите через проверку связи"
        if target == "ssh":
            await self.send(chat_id, screens.ssh_settings(self.view(notice=notice)))
            return
        if target == "setup":
            await self.send(chat_id, screens.setup(self.view(notice=notice)))
            return
        if target == "client":
            await self.send(chat_id, screens.link_settings(self.view(notice=notice)))
            return
        if target == "client_new":
            await self.send(chat_id, screens.clients(self.view(notice=notice)))
            return
        await self.send(chat_id, screens.home(self.view(notice=notice)))

    async def on_callback(self, evt: object) -> None:
        if not await self.guard(evt):
            return
        data = str(getattr(evt, "data", "") or "")
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        msg_id = int(getattr(evt, "msg_id", 0) or 0)
        if self.busy and not data.startswith("nav:"):
            await self.toast(evt, "дождитесь завершения операции", alert=True)
            return
        self.pending.pop(self.admin_id, None)
        try:
            await self.route(chat_id, msg_id, data)
        except (ControlError, ValidationError, LinkError, ConfigError) as exc:
            await self.render(chat_id, msg_id, screens.error_screen(self.view(), "Ошибка", str(exc)))
        except Exception as exc:
            log.exception("callback failed: %s", data)
            await self.render(chat_id, msg_id, screens.error_screen(self.view(), "Сбой", f"{type(exc).__name__}: {exc}"))

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        parts = data.split(":")
        head = parts[0] if parts else ""
        if head == "nav":
            await self.navigate(chat_id, msg_id, parts[1] if len(parts) > 1 else "home")
            return
        if head == "srv":
            await self.server_action(chat_id, msg_id, parts[1] if len(parts) > 1 else "")
            return
        if head == "ssh":
            await self.ssh_action(chat_id, msg_id, ":".join(parts[1:]))
            return
        if head == "setup":
            await self.setup_action(chat_id, msg_id, parts)
            return
        if head == "cli":
            await self.client_action(chat_id, msg_id, parts)
            return
        if head == "lnk":
            await self.link_action(chat_id, msg_id, parts)
            return
        if head == "log":
            await self.log_action(chat_id, msg_id, parts)
            return
        if head == "maint":
            await self.maint_action(chat_id, msg_id, parts)
            return
        await self.render(chat_id, msg_id, screens.home(self.view(notice="неизвестная команда")))

    async def navigate(self, chat_id: int, msg_id: int, page: str) -> None:
        if page == "home":
            await self.render(chat_id, msg_id, screens.home(self.view()))
            return
        if page == "server":
            await self.render(chat_id, msg_id, screens.server(self.view()))
            return
        if page == "ssh":
            await self.render(chat_id, msg_id, screens.ssh_settings(self.view()))
            return
        if page == "setup":
            await self.render(chat_id, msg_id, screens.setup(self.view()))
            return
        if page == "clients":
            await self.do_clients(chat_id, msg_id)
            return
        if page == "link":
            await self.render(chat_id, msg_id, screens.link_settings(self.view()))
            return
        if page == "logs":
            await self.log_action(chat_id, msg_id, ["log", "refresh"])
            return
        if page == "maint":
            await self.render(chat_id, msg_id, screens.maintenance(self.view()))
            return
        if page == "help":
            await self.render(chat_id, msg_id, screens.help_screen(self.view()))
            return
        if page == "import":
            await self.render(chat_id, msg_id, screens.import_screen(self.view()))
            return
        await self.render(chat_id, msg_id, screens.home(self.view()))

    async def server_action(self, chat_id: int, msg_id: int, action: str) -> None:
        if action == "check":
            await self.do_check(chat_id, msg_id)
            return
        if action in {"apply", "install", "start"}:
            await self.do_apply(chat_id, msg_id, update=False)
            return
        if action == "stop":
            await self.do_stop(chat_id, msg_id)
            return
        if action == "restart":
            await self.do_restart(chat_id, msg_id)
            return
        if action == "uninstall":
            await self.render(chat_id, msg_id, screens.confirm_uninstall(self.view()))
            return
        await self.render(chat_id, msg_id, screens.server(self.view()))

    async def ssh_action(self, chat_id: int, msg_id: int, action: str) -> None:
        if action.startswith("edit:"):
            self.pending[self.admin_id] = action.split(":", 1)[1]
            await self.render(chat_id, msg_id, screens.prompt(self.flows.field(self.pending[self.admin_id])))
            return
        if action == "clearfp":
            self.state.ssh.fingerprint = ""
            self.save()
            await self.render(chat_id, msg_id, screens.ssh_settings(self.view(notice="отпечаток сброшен")))
            return
        if action == "togglemode":
            self.flows.toggle_ssh_mode(self.state)
            self.save()
            await self.render(chat_id, msg_id, screens.ssh_settings(self.view(notice="способ входа переключен")))
            return
        await self.render(chat_id, msg_id, screens.ssh_settings(self.view()))

    async def setup_action(self, chat_id: int, msg_id: int, parts: list[str]) -> None:
        action = parts[1] if len(parts) > 1 else ""
        value = parts[2] if len(parts) > 2 else ""
        if action == "edit":
            self.pending[self.admin_id] = value
            await self.render(chat_id, msg_id, screens.prompt(self.flows.field(value)))
            return
        if action == "backend":
            self.flows.set_backend(self.state, value)
        elif action == "method":
            self.flows.set_method(self.state, value)
        elif action == "mode":
            self.flows.set_mode(self.state, value)
        elif action == "obf":
            if value == "menu":
                await self.render(chat_id, msg_id, screens.obf_menu(self.view()))
                return
            self.flows.set_obf(self.state, value)
        elif action == "genkey":
            self.flows.generate_obf_key(self.state)
        else:
            await self.render(chat_id, msg_id, screens.setup(self.view()))
            return
        self.save()
        await self.render(chat_id, msg_id, screens.setup(self.view(notice="параметры обновлены")))

    async def client_action(self, chat_id: int, msg_id: int, parts: list[str]) -> None:
        action = parts[1] if len(parts) > 1 else ""
        name = parts[2] if len(parts) > 2 else ""
        if action == "add":
            self.pending[self.admin_id] = "client_name"
            await self.render(chat_id, msg_id, screens.prompt(self.flows.field("client_name")))
            return
        if action == "refresh":
            await self.do_clients(chat_id, msg_id)
            return
        if action == "open":
            await self.render(chat_id, msg_id, screens.client(self.view(), name))
            return
        if action == "link":
            await self.do_client_link(chat_id, msg_id, name)
            return
        if action == "wg":
            await self.do_client_wg(chat_id, msg_id, name)
            return
        if action == "cfg":
            await self.render(chat_id, msg_id, screens.config_screen(self.view(), name))
            return
        if action == "del":
            await self.render(chat_id, msg_id, screens.confirm_remove(self.view(), name))
            return
        if action == "del2":
            await self.do_remove_client(chat_id, msg_id, name)
            return
        await self.render(chat_id, msg_id, screens.clients(self.view()))

    async def link_action(self, chat_id: int, msg_id: int, parts: list[str]) -> None:
        action = parts[1] if len(parts) > 1 else ""
        value = parts[2] if len(parts) > 2 else ""
        if action == "edit":
            self.pending[self.admin_id] = value
            await self.render(chat_id, msg_id, screens.prompt(self.flows.field(value)))
            return
        if action == "cycle":
            self.flows.cycle(self.state, value)
            self.save()
            await self.render(chat_id, msg_id, screens.link_settings(self.view(notice="значение изменено")))
            return
        if action == "toggle":
            self.flows.toggle_link(self.state, value)
            self.save()
            await self.render(chat_id, msg_id, screens.link_settings(self.view(notice="переключатель изменен")))
            return
        await self.render(chat_id, msg_id, screens.link_settings(self.view()))

    async def log_action(self, chat_id: int, msg_id: int, parts: list[str]) -> None:
        action = parts[1] if len(parts) > 1 else "refresh"
        if action == "tail" and len(parts) > 2:
            try:
                self.state.log_tail = max(20, min(2000, int(parts[2])))
                self.save()
            except ValueError:
                pass
        await self.do_logs(chat_id, msg_id)

    async def maint_action(self, chat_id: int, msg_id: int, parts: list[str]) -> None:
        action = parts[1] if len(parts) > 1 else ""
        if action == "update":
            await self.do_apply(chat_id, msg_id, update=True)
            return
        if action == "restart":
            await self.do_restart(chat_id, msg_id)
            return
        if action == "uninstall":
            await self.render(chat_id, msg_id, screens.confirm_uninstall(self.view()))
            return
        if action == "uninstall2":
            await self.do_uninstall(chat_id, msg_id)
            return
        await self.render(chat_id, msg_id, screens.maintenance(self.view()))

    def require_ssh(self) -> None:
        if not self.state.ssh.is_ready():
            raise ConfigError("сначала заполните доступ по SSH в разделе SSH")

    async def stage(self, chat_id: int, msg_id: int, title: str) -> Draft:
        await self.render(chat_id, msg_id, screens.busy_screen(title))
        draft = Draft(self.app, chat_id, DRAFT_ID)
        await draft.__aenter__()
        await draft.say(title)
        return draft

    async def handshake(self, draft: Draft) -> None:
        await draft.say("проверка связи по ssh", "connect")
        fingerprint = await self.control.connect_check(self.state.ssh)
        stored = self.state.ssh.fingerprint
        if stored and fingerprint != stored:
            raise ControlError("отпечаток сервера изменился, соединение отклонено", "host_key_changed")
        self.state.ssh.fingerprint = fingerprint
        self.state.ssh.mode = await self.control.detect_mode(self.state.ssh)
        self.save()
        await draft.say("определение прав", self.state.ssh.mode)

    async def do_check(self, chat_id: int, msg_id: int) -> None:
        self.require_ssh()
        self.busy = True
        draft = await self.stage(chat_id, msg_id, "проверка сервера")
        try:
            try:
                await self.handshake(draft)
                await draft.say("чтение состояния установки")
                self.probe = await self.control.probe(self.state.ssh)
                if self.probe.config is not None:
                    self.state.opts.from_probe(self.probe.config)
                    self.save()
                await draft.say("чтение списка клиентов")
                self.clients, self.share = await self.control.clients(self.state.ssh)
                await draft.say("готово")
            finally:
                await draft.close()
            await self.render(chat_id, msg_id, screens.server(self.view(notice="сервер на связи")))
        finally:
            self.busy = False

    async def do_apply(self, chat_id: int, msg_id: int, update: bool) -> None:
        self.require_ssh()
        self.flows.validate_server(self.state)
        self.busy = True
        draft = await self.stage(chat_id, msg_id, "перезапуск ядра" if update else "применение конфигурации")
        try:
            try:
                await self.handshake(draft)
                await draft.say("установка free turn proxy" if not update else "обновление ядра")
                response = await self.control.apply(self.state.ssh, self.state.opts, update=update)
                self.apply_owner(response)
                await draft.say("проверка результата")
                self.probe = await self.control.probe(self.state.ssh)
                self.clients, self.share = await self.control.clients(self.state.ssh)
                await draft.say("готово")
            finally:
                await draft.close()
            notice = "ядро обновлено" if update else "сервер настроен"
            await self.render(chat_id, msg_id, screens.server(self.view(notice=notice)))
        finally:
            self.busy = False

    def apply_owner(self, response: ControlResponse) -> None:
        owner = response.data.get("owner") or {}
        key = str(response.data.get("obf_key") or "")
        if key:
            self.state.opts.obf_key = key
        client_id = str(owner.get("client_id") or "")
        if client_id:
            self.state.owner_client_id = client_id
        conf_b64 = str(owner.get("conf_b64") or "")
        if conf_b64:
            try:
                self.state.owner_conf = normalize_conf(base64.b64decode(conf_b64).decode("utf-8", "replace"))
            except (ValueError, UnicodeDecodeError):
                self.state.owner_conf = ""
        self.save()

    async def do_stop(self, chat_id: int, msg_id: int) -> None:
        self.require_ssh()
        self.busy = True
        draft = await self.stage(chat_id, msg_id, "остановка сервиса")
        try:
            try:
                await self.handshake(draft)
                await self.control.stop(self.state.ssh)
                await draft.say("чтение состояния")
                self.probe = await self.control.probe(self.state.ssh)
            finally:
                await draft.close()
            await self.render(chat_id, msg_id, screens.server(self.view(notice="сервис остановлен")))
        finally:
            self.busy = False

    async def do_restart(self, chat_id: int, msg_id: int) -> None:
        self.require_ssh()
        self.busy = True
        draft = await self.stage(chat_id, msg_id, "перезапуск сервиса")
        try:
            try:
                await self.handshake(draft)
                await self.control.restart(self.state.ssh)
                await draft.say("чтение состояния")
                self.probe = await self.control.probe(self.state.ssh)
            finally:
                await draft.close()
            await self.render(chat_id, msg_id, screens.server(self.view(notice="сервис перезапущен")))
        finally:
            self.busy = False

    async def do_logs(self, chat_id: int, msg_id: int) -> None:
        self.require_ssh()
        tail = int(self.state.log_tail)
        lines = await self.control.logs(self.state.ssh, tail)
        await self.render(chat_id, msg_id, screens.logs(self.view(), lines, tail))

    async def do_clients(self, chat_id: int, msg_id: int) -> None:
        self.require_ssh()
        self.clients, self.share = await self.control.clients(self.state.ssh)
        await self.render(chat_id, msg_id, screens.clients(self.view(notice=f"клиентов: {len(self.clients)}")))

    async def do_client_link(self, chat_id: int, msg_id: int, name: str) -> None:
        self.require_ssh()
        client, conf = await self.control.client_conf(self.state.ssh, name)
        if name == "owner":
            if client.client_id:
                self.state.owner_client_id = client.client_id
            if conf:
                self.state.owner_conf = normalize_conf(conf)
            conf = conf or self.state.owner_conf
            self.save()
        link = build_link(self.peer(), self.state.opts, self.state.link, client.client_id, name, conf)
        await self.render(chat_id, msg_id, screens.link_screen(self.view(), name, link, conf, client))

    async def do_client_wg(self, chat_id: int, msg_id: int, name: str) -> None:
        self.require_ssh()
        client, conf = await self.control.client_conf(self.state.ssh, name)
        if not conf:
            conf = self.state.owner_conf if name == "owner" else ""
        if not conf:
            raise ControlError("сервер не вернул конфигурацию клиента", "not_found")
        await self.render(chat_id, msg_id, screens.wg_screen(self.view(), name, conf, client))

    async def do_add_client(self, chat_id: int, name: str) -> None:
        self.require_ssh()
        clean = validate.name(name)
        client, conf = await self.control.client_add(self.state.ssh, clean)
        self.clients, self.share = await self.control.clients(self.state.ssh)
        link = build_link(self.peer(), self.state.opts, self.state.link, client.client_id, clean, conf)
        receipt = screens.link_screen(self.view(notice=f"клиент {clean} добавлен"), clean, link, conf, client)
        await self.send(chat_id, receipt)

    async def do_remove_client(self, chat_id: int, msg_id: int, name: str) -> None:
        self.require_ssh()
        await self.control.client_remove(self.state.ssh, name)
        self.clients, self.share = await self.control.clients(self.state.ssh)
        await self.render(chat_id, msg_id, screens.clients(self.view(notice=f"клиент {name} удален")))

    async def do_uninstall(self, chat_id: int, msg_id: int) -> None:
        self.require_ssh()
        self.busy = True
        draft = await self.stage(chat_id, msg_id, "удаление установки")
        try:
            try:
                await self.handshake(draft)
                await self.control.uninstall(self.state.ssh)
                await draft.say("готово")
            finally:
                await draft.close()
            self.probe = None
            self.clients = []
            self.share = None
            await self.render(chat_id, msg_id, screens.server(self.view(notice="установка удалена")))
        finally:
            self.busy = False

    async def do_import(self, chat_id: int, text: str) -> None:
        try:
            data = parse_link(text)
        except LinkError as exc:
            await self.send(chat_id, screens.import_screen(self.view(), error=str(exc)))
            return
        await self.send(chat_id, screens.import_screen(self.view(), rows=link_rows(data), raw=text))

    def peer(self) -> str:
        host = self.state.opts.host or self.state.ssh.host
        return f"{host}:{int(self.state.opts.listen_port)}"
