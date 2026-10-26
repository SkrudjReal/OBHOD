from __future__ import annotations

from pathlib import Path

from BOT.app import Bot
from BOT.links import build_link, parse_link
from tests.fakes import FakeApp, FakeControl, FakeEvt, make_config


def make_bot(tmp_path: Path, admin: int = 777) -> tuple[Bot, FakeApp, FakeControl]:
    bot = Bot(make_config(tmp_path / "state", admin_id=admin), control=FakeControl())
    app = FakeApp()
    bot.app = app
    return bot, app, bot.control


def arm(bot: Bot) -> None:
    bot.state.ssh.host = "203.0.113.10"
    bot.state.ssh.user = "root"
    bot.state.ssh.password = "hunter2"


async def press(bot: Bot, app: FakeApp, data: str, msg_id: int = 42) -> str:
    await bot.on_callback(FakeEvt(msg_id=msg_id, data=data))
    return app.last_html()


async def say(bot: Bot, app: FakeApp, text: str, who: int = 777) -> str:
    await bot.on_message(FakeEvt(from_id=who, chat_id=who, text=text))
    return app.last_html()


async def command(bot: Bot, app: FakeApp, cmd: str) -> str:
    await bot.on_command(FakeEvt(text="/" + cmd, cmd=cmd))
    return app.last_html()


def names(control: FakeControl) -> list[str]:
    return [name for name, _ in control.calls]


async def test_admin_gate_blocks_others(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    html = await say(bot, app, "/start", who=5)
    assert "Доступ закрыт" in html


async def test_admin_claim_on_first_message(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path, admin=0)
    await say(bot, app, "/start", who=4242)
    assert bot.state.admin_id == 4242
    assert (tmp_path / "state" / "state.json").is_file()
    html = await say(bot, app, "/start", who=9)
    assert "Доступ закрыт" in html


async def test_admin_claim_on_callback(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path, admin=0)
    await bot.on_callback(FakeEvt(from_id=333, data="nav:home"))
    assert bot.state.admin_id == 333


async def test_configured_admin_wins(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path, admin=321)
    bot.state.admin_id = 999
    assert bot.admin_id == 321


async def test_start_renders_home(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    html = await say(bot, app, "/start")
    assert "OBHOD" in html
    assert "tg-button" in html


async def test_help_and_id_commands(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    assert "Команды install.sh" in await command(bot, app, "help")
    assert "777" in await command(bot, app, "id")
    assert "Помощь" in await command(bot, app, "menu")


async def test_plain_text_shows_home(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    assert "выберите действие" in await say(bot, app, "привет")


async def test_navigation_pages(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    pages = {
        "nav:home": "OBHOD",
        "nav:server": "Сервер",
        "nav:ssh": "Доступ по SSH",
        "nav:setup": "Параметры установки",
        "nav:link": "Параметры подключения",
        "nav:maint": "Обслуживание",
        "nav:help": "Помощь",
        "nav:import": "Импорт ссылки",
    }
    for data, marker in pages.items():
        assert marker in await press(bot, app, data), data
    assert "Клиенты" in await press(bot, app, "nav:clients")
    assert "clients" in names(control)
    assert "журнал" in (await press(bot, app, "nav:logs")).lower()


async def test_unknown_callback_falls_back(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    assert "неизвестная команда" in await press(bot, app, "zz:zz")


async def test_ssh_field_flow(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "ssh:edit:ssh_host")
    assert bot.pending[777] == "ssh_host"
    html = await say(bot, app, "203.0.113.10")
    assert "203.0.113.10" in html
    assert bot.state.ssh.host == "203.0.113.10"
    assert bot.pending == {}


async def test_ssh_invalid_input_keeps_pending(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "ssh:edit:ssh_port")
    html = await say(bot, app, "99999")
    assert "Ошибка" in html or "port must be" in html
    assert bot.pending[777] == "ssh_port"


async def test_ssh_password_sets_auth(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    bot.state.ssh.auth = "SSH_KEY"
    await press(bot, app, "ssh:edit:ssh_password")
    await say(bot, app, "s3cret")
    assert bot.state.ssh.password == "s3cret"
    assert bot.state.ssh.auth == "PASSWORD"


async def test_ssh_key_and_passphrase_and_sudo(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "ssh:edit:ssh_key")
    await say(bot, app, "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
    assert bot.state.ssh.auth == "SSH_KEY"
    assert "PRIVATE KEY" in bot.state.ssh.key
    await press(bot, app, "ssh:edit:ssh_passphrase")
    await say(bot, app, "-")
    assert bot.state.ssh.passphrase == ""
    await press(bot, app, "ssh:edit:ssh_sudo")
    await say(bot, app, "-")
    assert bot.state.ssh.sudo_password == ""


async def test_ssh_toggle_and_fingerprint_reset(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "ssh:togglemode")
    assert bot.state.ssh.auth == "SSH_KEY"
    await press(bot, app, "ssh:togglemode")
    assert bot.state.ssh.auth == "PASSWORD"
    bot.state.ssh.fingerprint = "SHA256:x"
    html = await press(bot, app, "ssh:clearfp")
    assert bot.state.ssh.fingerprint == ""
    assert "отпечаток сброшен" in html


async def test_unknown_ssh_field_renders_error(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    html = await press(bot, app, "ssh:edit:nope")
    assert "Ошибка" in html


async def test_setup_toggles(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "setup:backend:external")
    assert bot.state.opts.backend == "external"
    await press(bot, app, "setup:edit:setup_connect")
    await say(bot, app, "127.0.0.1:51820")
    assert bot.state.opts.connect == "127.0.0.1:51820"
    await press(bot, app, "setup:backend:new")
    assert bot.state.opts.mode == "udp"
    await press(bot, app, "setup:method:systemd")
    assert bot.state.opts.method == "systemd"
    html = await press(bot, app, "setup:mode:tcp")
    assert "только в режиме udp" in html
    assert bot.state.opts.mode == "udp"


async def test_setup_obf_menu_and_key(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    assert "Обфускация" in await press(bot, app, "setup:obf:menu")
    bot.state.opts.obf_key = ""
    await press(bot, app, "setup:obf:rtpopus2")
    assert bot.state.opts.obf_profile == "rtpopus2"
    assert len(bot.state.opts.obf_key) == 64
    await press(bot, app, "setup:obf:none")
    assert bot.state.opts.obf_key == ""
    await press(bot, app, "setup:genkey")
    assert len(bot.state.opts.obf_key) == 64


async def test_setup_ports_and_net(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "setup:edit:setup_listen")
    await say(bot, app, "56100")
    assert bot.state.opts.listen_port == 56100
    await press(bot, app, "setup:edit:setup_wgnet")
    html = await say(bot, app, "10.44.0.1/24")
    assert "host bits" in html
    await say(bot, app, "10.44.0.0/24")
    assert bot.state.opts.wg_net == "10.44.0.0/24"


async def test_link_cycle_and_toggle(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "lnk:cycle:transport")
    assert bot.state.link.transport == "udp"
    await press(bot, app, "lnk:cycle:mode")
    assert bot.state.link.mode == "tcp"
    await press(bot, app, "lnk:cycle:dns")
    assert bot.state.link.dns_mode == "plain"
    await press(bot, app, "lnk:toggle:bond")
    assert bot.state.link.bond is True
    await press(bot, app, "lnk:toggle:mcap")
    assert bot.state.link.manual_captcha is True
    assert "параметры" in (await press(bot, app, "lnk:cycle:transport")).lower()


async def test_link_field_edits(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "lnk:edit:link_threads")
    await say(bot, app, "24")
    assert bot.state.link.threads == 24
    await press(bot, app, "lnk:edit:link_spc")
    await say(bot, app, "6")
    assert bot.state.link.streams_per_cred == 6
    await press(bot, app, "lnk:edit:link_timing")
    await say(bot, app, "15")
    assert bot.state.link.timing_ms == 15
    await press(bot, app, "lnk:edit:link_listen")
    await say(bot, app, "127.0.0.1:1080")
    assert bot.state.link.local_listen == "127.0.0.1:1080"
    await press(bot, app, "lnk:edit:link_dnss")
    await say(bot, app, "1.1.1.1,8.8.8.8")
    assert bot.state.link.dns_servers == "1.1.1.1,8.8.8.8"
    await press(bot, app, "lnk:edit:link_call")
    await say(bot, app, "https://vk.ru/call/join/AbCdEf")
    assert bot.state.link.call_link.endswith("AbCdEf")


async def test_pending_input_cancelled_by_navigation(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "lnk:edit:link_threads")
    assert 777 in bot.pending
    await press(bot, app, "nav:home")
    assert bot.pending == {}


async def test_clients_flow(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "nav:clients")
    assert "owner" in html and "phone" in html
    assert "phone" in await press(bot, app, "cli:open:phone")
    assert "клиентов" in await press(bot, app, "cli:refresh")


async def test_add_client(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "cli:add")
    html = await say(bot, app, "laptop")
    assert ("client_add", "laptop") in control.calls
    assert "laptop" in html


async def test_client_link_screen(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "cli:link:owner")
    assert "freeturn://" in html
    assert ("client_conf", "owner") in control.calls
    assert "copy_text" in html


async def test_client_link_is_single_scheme_with_expected_fields(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    bot.state.link.threads = 20
    bot.state.link.call_link = "https://vk.ru/call/join/AbCdEf"
    html = await press(bot, app, "cli:link:owner")
    link = html.split("freeturn://", 1)[1]
    link = "freeturn://" + link.split("<", 1)[0].split()[0]
    data = parse_link(link)
    assert data["peer"] == "203.0.113.10:56000"
    assert data["n"] == 20
    assert data["cid"] == "cid-owner"
    assert data["vk"] == "https://vk.ru/call/join/AbCdEf"
    assert "Endpoint" in data["wg"]
    assert "platform" not in data


async def test_client_wg_and_config_screens(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "cli:wg:owner")
    assert "WireGuard" in html
    assert "Endpoint" in html
    cfg = await press(bot, app, "cli:cfg:owner")
    assert "clientId" in cfg


async def test_remove_client_two_steps(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "cli:del:phone")
    assert ("client_remove", "phone") not in control.calls
    html = await press(bot, app, "cli:del2:phone")
    assert ("client_remove", "phone") in control.calls
    assert "phone удален" in html


async def test_check_requires_ssh(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    html = await press(bot, app, "srv:check")
    assert "SSH" in html
    assert control.calls == []


async def test_check_success(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "srv:check")
    assert names(control)[:3] == ["connect_check", "detect_mode", "probe"]
    assert bot.state.ssh.fingerprint == "SHA256:abc"
    assert bot.state.ssh.mode == "ROOT"
    assert bot.probe is not None and bot.probe.running
    assert "4.1.0" in html
    assert app.mt.drafts
    assert any(entry["act"] == "messages.setTyping" for entry in app.mt.drafts)


async def test_check_detects_fingerprint_change(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    bot.state.ssh.fingerprint = "SHA256:other"
    html = await press(bot, app, "srv:check")
    assert "отпечаток" in html


async def test_apply_success(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "srv:apply")
    assert ("apply", False) in control.calls
    assert bot.state.owner_client_id == "cid-owner"
    assert "Address = 10.13.13.2/24" in bot.state.owner_conf
    assert "сервер настроен" in html
    assert (tmp_path / "state" / "state.json").is_file()


async def test_apply_update_flag(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "maint:update")
    assert ("apply", True) in control.calls


async def test_apply_validation_errors(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    bot.state.opts.backend = "new"
    bot.state.opts.mode = "tcp"
    html = await press(bot, app, "srv:apply")
    assert "только в режиме udp" in html
    bot.state.opts.backend = "external"
    bot.state.opts.connect = ""
    html = await press(bot, app, "srv:apply")
    assert "host:port" in html or "адрес" in html
    assert ("apply", False) not in control.calls


async def test_apply_failure(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    control.fail = ("apply", "сервис не запустился")
    html = await press(bot, app, "srv:apply")
    assert "сервис не запустился" in html


async def test_stop_and_restart(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "srv:check")
    assert "остановлен" in (await press(bot, app, "srv:stop")).lower()
    await press(bot, app, "srv:restart")
    await press(bot, app, "maint:restart")
    assert names(control).count("restart") == 2
    assert names(control).count("stop") == 1


async def test_logs_and_tail(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "nav:logs")
    assert "log line 29" in html
    await press(bot, app, "log:tail:50")
    assert bot.state.log_tail == 50
    assert ("logs", 50) in control.calls


async def test_uninstall_flow(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "maint:uninstall")
    assert "удаление установки" in html.lower()
    assert ("uninstall", "all") not in control.calls
    html = await press(bot, app, "maint:uninstall2")
    assert ("uninstall", "all") in control.calls
    assert "установка удалена" in html
    assert bot.probe is None


async def test_import_link(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    link = build_link("203.0.113.10:56000", bot.state.opts, bot.state.link, "cid", "phone")
    html = await say(bot, app, link)
    assert "203.0.113.10:56000" in html
    assert "copy_text" in html


async def test_import_broken_link(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    html = await say(bot, app, "freeturn://broken")
    assert "Импорт ссылки" in html


async def test_busy_guard(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    bot.busy = True
    evt = FakeEvt(data="srv:check")
    await bot.on_callback(evt)
    assert evt.answers and evt.answers[-1][1] is True
    evt2 = FakeEvt(text="/start")
    await bot.on_message(evt2)
    assert evt2.answers and evt2.answers[-1][1] is True


async def test_edit_failure_falls_back_to_send(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)

    async def boom(*args: object, **kw: object) -> None:
        raise RuntimeError("message to edit not found")

    app.edit_rich = boom
    await press(bot, app, "nav:server")
    assert app.sent


async def test_state_persists_between_bots(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "setup:edit:setup_listen")
    await say(bot, app, "56200")
    again = Bot(make_config(tmp_path / "state", admin_id=777), control=FakeControl())
    assert again.state.ssh.host == "203.0.113.10"
    assert again.state.opts.listen_port == 56200


async def test_drafts_stop_action(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "srv:check")
    actions = [entry.get("action", {}).get("_") for entry in app.mt.drafts]
    assert "sendMessageRichMessageDraftAction" in actions
    assert "sendMessageStopDraftAction" in actions


async def test_secret_input_not_echoed(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "ssh:edit:ssh_password")
    html = await say(bot, app, "topsecretvalue")
    assert "topsecretvalue" not in html
    assert "пароль ssh сохранен" in html


async def test_boot_builds_client_offline(tmp_path: Path) -> None:
    from goygram import GoyGram

    cfg = make_config(
        tmp_path / "state",
        default_dc_host="127.0.0.1",
        default_dc_port=443,
        session_name=str(tmp_path / "session"),
    )
    bot = Bot(cfg, control=FakeControl())
    app = await bot.boot()
    assert isinstance(app, GoyGram)
    assert bot.app is app


async def test_boot_uses_mtproto_transport(tmp_path: Path) -> None:
    cfg = make_config(
        tmp_path / "state",
        default_dc_host="127.0.0.1",
        default_dc_port=443,
        session_name=str(tmp_path / "session"),
    )
    bot = Bot(cfg, control=FakeControl())
    app = await bot.boot()
    assert app.core.default_transport == "mtproto"
    assert app.core.intake == "mtproto"


async def test_admin_id_zero_allows_until_claimed(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path, admin=0)
    assert bot.admin_id == 0
    html = await say(bot, app, "/help", who=15)
    assert "Помощь" in html
    assert bot.admin_id == 15
    html = await say(bot, app, "/help", who=16)
    assert "Доступ закрыт" in html


async def test_reset_needs_confirmation(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "maint:reset")
    assert "переустановка с нуля" in html
    assert "hard_reset" not in names(control)


async def test_reset_from_maintenance_runs_full_wipe(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "maint:reset2")
    assert "hard_reset" in names(control)
    assert ("apply", True) in control.calls
    assert "заново" in html
    assert control.reset_progress[0] == "удаление установки через install.sh"
    assert "каталог установки удален" in control.reset_progress
    assert any(item[0] == "clients" for item in control.calls)


async def test_reset_from_server_screen(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    html = await press(bot, app, "srv:reset")
    assert 'data="maint:reset2"' in html
    await press(bot, app, "srv:reset2")
    assert "hard_reset" in names(control)


async def test_reset_uses_pinned_version_by_default(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "maint:reset2")
    assert ("hard_reset", "v4.1.0") in control.calls


async def test_reset_after_choosing_latest(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "setup:ver:latest")
    assert bot.state.opts.version == "latest"
    await press(bot, app, "maint:reset2")
    assert ("hard_reset", "latest") in control.calls


async def test_setup_version_button_pins_back(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    await press(bot, app, "setup:ver:latest")
    html = await press(bot, app, "setup:ver:v4.1.0")
    assert bot.state.opts.version == "v4.1.0"
    assert 'data="setup:ver:v4.1.0"' in html


async def test_reset_without_ssh_reports_error(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    html = await press(bot, app, "maint:reset2")
    assert "Доступ по SSH" in html or "ssh" in html.lower()
    assert "hard_reset" not in names(control)


async def test_reset_failure_is_rendered(tmp_path: Path) -> None:
    bot, app, control = make_bot(tmp_path)
    arm(bot)
    control.fail = ("hard_reset", "остатки установки не удалены")
    html = await press(bot, app, "maint:reset2")
    assert "остатки установки не удалены" in html
    assert bot.busy is False


async def test_reset_clears_busy_flag_on_success(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "maint:reset2")
    assert bot.busy is False


async def test_reset_writes_draft_progress(tmp_path: Path) -> None:
    bot, app, _ = make_bot(tmp_path)
    arm(bot)
    await press(bot, app, "maint:reset2")
    drafts = [item for item in app.mt.drafts if item["act"] == "messages.setTyping"]
    payloads = []
    for item in drafts:
        action = item.get("action") or {}
        rich = action.get("rich_message") or {}
        payloads.append(rich.get("html", ""))
    joined = "".join(payloads)
    assert "Выполняется" in joined
    assert "очистка процессов, интерфейсов и файлов" in joined
    assert any(action.get("_") == "sendMessageStopDraftAction" for action in [item.get("action") or {} for item in app.mt.drafts])
