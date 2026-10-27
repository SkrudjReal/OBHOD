from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from BOT import i18n, inline, screens, xscreens
from BOT.config import ConfigError
from BOT.models import ModelError
from BOT.xray import new_inbound
from tests.fakes import FakeEvent, make_bot


def run(coro: object) -> None:
    asyncio.run(coro)


def test_admin_is_claimed_on_first_contact(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.cfg.admin_id = 0
    evt = FakeEvent(from_id=55, chat_id=55)
    assert run(bot.guard_admin(evt)) is None
    run(bot.guard_admin(evt))
    assert bot.state.admin_id == 55


def test_foreign_user_is_denied(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)

    async def scenario() -> bool:
        return await bot.guard_admin(FakeEvent(from_id=99))

    assert asyncio.run(scenario()) is False
    assert bot.sent


def test_navigation_renders_every_page(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    for page in ("home", "server", "ssh", "settings", "ban", "sshd", "help", "xray", "other"):
        run(bot.route(1, 0, f"nav:{page}"))
    assert len(bot.rendered) == 9


def test_unknown_callback_falls_back(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.route(1, 0, "zzz:none"))
    assert bot.rendered


def test_help_and_id_commands(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvent(cmd="help")))
    run(bot.on_command(FakeEvent(cmd="id")))
    run(bot.on_command(FakeEvent(cmd="start")))
    assert len(bot.sent) == 3


def test_text_message_shows_home(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_message(FakeEvent(text="hello")))
    assert bot.sent


def test_ssh_fields_are_validated(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    with pytest.raises(ModelError):
        run(bot.ssh_input(1, "ssh_new_port", "0"))
    with pytest.raises(ConfigError):
        run(bot.ssh_input(1, "ssh_unknown", "x"))
    for ident in ("ssh_host", "ssh_port", "ssh_user", "ssh_password", "ssh_key", "ssh_sudo"):
        with pytest.raises(ConfigError):
            run(bot.ssh_input(1, ident, "x"))


def test_credential_fields_are_gone(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    values = bot.input_values()
    for ident in ("ssh_host", "ssh_port", "ssh_user", "ssh_password", "ssh_key", "ssh_sudo"):
        assert ident not in values
        assert ident not in inline.FIELDS
    assert "ssh_new_port" in values
    assert not hasattr(bot.state.ssh, "password")
    assert not hasattr(bot.state.ssh, "key")


def test_ssh_screen_reports_a_local_shell(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    html = screens.ssh_settings(bot.view()).to_html()
    assert i18n.t("SSH_LOCAL_MODE") in html
    assert i18n.t("SSH_NO_PASSWORD") in html


def test_ban_actions_use_the_guard(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.ban_action(1, 0, "install"))
    assert "install" in bot.guard.calls
    assert bot.state.xray.fail2ban_enabled is True
    run(bot.ban_action(1, 0, "status"))
    assert bot.ban is not None
    run(bot.ban_action(1, 0, "reset"))
    run(bot.ban_action(1, 0, "remove"))
    assert bot.state.xray.fail2ban_enabled is False


def test_ban_actions_need_no_credentials(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.ban_action(1, 0, "install"))
    assert "install" in bot.guard.calls


def test_sshd_actions_use_the_guard(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.sshd_action(1, 0, "status", ""))
    assert "ssh_status" in bot.guard.calls
    run(bot.sshd_action(1, 0, "auth", "no"))
    assert "ssh_apply" in bot.guard.calls
    run(bot.sshd_action(1, 0, "root", "no"))
    run(bot.sshd_action(1, 0, "remove", ""))
    assert "ssh_remove" in bot.guard.calls


def test_ssh_new_port_and_pubkey_inputs(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.ssh_input(1, "ssh_new_port", "2200"))
    assert "ssh_apply" in bot.guard.calls
    run(bot.ssh_input(1, "ssh_pubkey", "ssh-ed25519 AAAA test"))
    assert "ssh_add_key" in bot.guard.calls


def test_inline_lists_fields(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    evt = FakeEvent(query="ob")
    run(bot.on_inline(evt))
    assert evt.results
    evt_two = FakeEvent(query="ob xr_sub_port - 2096")
    run(bot.on_inline(evt_two))
    assert evt_two.results


def test_marker_message_is_processed(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    marker = inline.marker("xr_sub_port", "-", "2096")
    evt = FakeEvent(text=marker, msg_id=10)
    run(bot.on_message(evt))
    assert bot.state.xray.sub_port == 2096


def test_cancel_marker_is_routed(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    evt = FakeEvent(text=inline.cancel_marker())
    run(bot.on_message(evt))
    assert bot.sent


def test_input_for_inbound_field(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    marker = inline.marker("xr_sni", str(inbound.id), "www.microsoft.com")
    run(bot.on_message(FakeEvent(text=marker)))
    assert inbound.sni == "www.microsoft.com"


def test_input_error_is_reported(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    marker = inline.marker("xr_sub_port", "-", "bad")
    run(bot.on_message(FakeEvent(text=marker)))
    assert bot.sent


def test_busy_flag_blocks_callbacks(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.busy = True
    evt = FakeEvent(data="fb:install")
    run(bot.on_callback(evt))
    assert evt.answers and evt.answers[0]["alert"] is True


def test_callback_pipeline_registers_admin(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    evt = FakeEvent(data="nav:home")
    run(bot.on_callback(evt))
    assert bot.rendered


def test_ban_and_sshd_callbacks(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    for data in ("fb:install", "fb:status", "fb:reset", "fb:remove", "sshd:status", "sshd:auth:no", "sshd:root:no", "sshd:remove"):
        run(bot.route(1, 0, data))
    assert bot.rendered


def test_address_prefers_sub_address(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    monkeypatch.setattr("BOT.app.public_address", lambda: "")
    assert bot.address() == "127.0.0.1"
    bot.state.xray.sub_address = "198.51.100.5"
    assert bot.address() == "198.51.100.5"


def test_address_falls_back_to_the_detected_interface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    monkeypatch.setattr("BOT.app.public_address", lambda: "203.0.113.77")
    assert bot.address() == "203.0.113.77"


def test_input_values_are_prefilled(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.remark = "main"
    bot.state.xray.add(inbound)
    values = bot.input_values()
    assert values["ssh_new_port"] == "22"
    assert values["xr_remark"] == "main"
    assert values["xr_port"] == "443"
    assert values["xr_bantime"] == "30"


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    bot.save()
    again = make_bot(tmp_path)
    assert again.state.xray.inbounds[0].clients[0].email == "owner"


def test_language_menu_renders_three_choices(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.route(1, 0, "nav:lang"))
    html = bot.rendered[-1].to_html()
    for code_value in ("en", "ru", "zh"):
        assert f"lang:set:{code_value}" in html
    assert bot.language == "en"


def test_language_switch_is_persisted(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.route(1, 0, "lang:set:zh"))
    assert bot.state.language == "zh"
    again = make_bot(tmp_path)
    assert again.state.language == "zh"
    assert again.language == "zh"
    html = bot.rendered[-1].to_html()
    assert i18n.t("LANG_TITLE", "zh") in html


def test_language_switch_changes_every_screen(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.xray.add(new_inbound("vless", 443, "raw", "reality"))
    for code_value in i18n.LANGUAGES:
        bot.state.language = code_value
        bot.save()
        for page in ("home", "ssh", "settings", "ban", "sshd", "help", "lang", "xray"):
            run(bot.route(1, 0, f"nav:{page}"))
        html = bot.rendered[-1].to_html()
        assert i18n.t("NAV_CORE", code_value) in html


def test_language_command_and_unknown_choice(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvent(cmd="language")))
    assert bot.sent
    run(bot.route(1, 0, "lang:set:de"))
    assert bot.state.language == "en"
    run(bot.route(1, 0, "lang:show"))
    assert bot.rendered


def test_language_reaches_views_and_panel(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    assert bot.view().lang == "ru"
    assert bot.xray.view().lang == "ru"
    assert i18n.t("NAV_SETTINGS", "ru") in screens.settings(bot.view()).to_html()
    bot.state.language = "zh"
    assert bot.xray.view().lang == "zh"
    assert i18n.t("NAV_CORE", "zh") in xscreens.core_screen(bot.xray.view()).to_html()


def test_denied_screen_uses_the_chosen_language(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "zh"
    run(bot.guard_admin(FakeEvent(from_id=99)))
    html = bot.sent[-1].to_html()
    assert i18n.t("DENIED_BODY", "zh") in html


def test_toast_and_notice_are_localized(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    bot.busy = True
    evt = FakeEvent(data="fb:install")
    run(bot.on_callback(evt))
    assert evt.answers[0]["text"] == i18n.t("TOAST_BUSY", "ru")
    bot.busy = False
    evt_two = FakeEvent(text="what")
    run(bot.on_message(evt_two))
    assert i18n.t("HOME_NOTICE_PICK", "ru") in bot.sent[-1].to_html()
