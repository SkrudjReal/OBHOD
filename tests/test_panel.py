from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from BOT import inline
from BOT.app import Bot
from BOT.panel import XrayPanel
from BOT.scan import ScanResult
from BOT.xray import new_inbound
from BOT.xrayrpc import CoreState
from tests.fakes import FakeApp, FakeControl, FakeEvt, FakeInlineEvt, FakeXrayControl, make_config


def make_bot(tmp_path: Path, admin: int = 777, ssh: bool = True) -> tuple[Bot, FakeApp, XrayPanel, FakeXrayControl]:
    bot = Bot(make_config(tmp_path / "state", admin_id=admin), control=FakeControl())
    app = FakeApp()
    bot.app = app
    if ssh:
        bot.state.ssh.host = "203.0.113.10"
        bot.state.ssh.user = "root"
        bot.state.ssh.password = "hunter2"
    control = FakeXrayControl()
    panel = XrayPanel(bot, control=control)
    bot.xray = panel
    return bot, app, panel, control


async def press(bot: Bot, app: FakeApp, data: str) -> str:
    await bot.on_callback(FakeEvt(data=data))
    return app.last_html()


async def test_home_screen_from_navigation(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    html = await press(bot, app, "nav:xray")
    assert "Xray" in html
    assert "ядро не проверено" in html
    assert "Новый инбаунд" in html


async def test_home_lists_inbounds(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    html = await press(bot, app, "xr:home")
    assert "vless-443" in html
    assert "443" in html


async def test_home_requires_nothing(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path, ssh=False)
    html = await press(bot, app, "xr:home")
    assert "инбаундов пока нет" in html


async def test_new_menu(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:new")
    assert "vless reality" in html
    assert "shadowsocks" in html


async def test_quick_create_makes_owner_client(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:new:vless:reality")
    inbound = panel.state.inbounds[0]
    assert inbound.protocol == "vless"
    assert inbound.security == "reality"
    assert inbound.port == 443
    assert [item.email for item in inbound.clients] == ["owner"]
    assert "инбаунд создан" in html
    assert "vless-443" in html


async def test_quick_create_advances_port(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await press(bot, app, "xr:new:vless:reality")
    await press(bot, app, "xr:new:trojan:reality")
    assert panel.state.ports() == [443, 8443]


async def test_quick_create_rejects_bad_protocol(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:new:garbage:reality")
    assert "не поддерживается" in html
    assert panel.state.inbounds == []


async def test_vmess_with_reality_is_refused(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:new:vmess:reality")
    assert "reality" in html
    assert panel.state.inbounds == []


async def test_custom_draft_cycles(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await press(bot, app, "xr:custom")
    assert panel.draft["protocol"] == "vless"
    await press(bot, app, "xr:cyc:protocol")
    assert panel.draft["protocol"] == "vmess"
    await press(bot, app, "xr:cyc:network")
    assert panel.draft["network"] == "ws"
    await press(bot, app, "xr:cyc:security")
    assert panel.draft["security"] == "tls"


async def test_custom_create_uses_draft(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await press(bot, app, "xr:custom")
    await press(bot, app, "xr:cyc:protocol")
    await press(bot, app, "xr:cyc:network")
    await press(bot, app, "xr:cyc:security")
    html = await press(bot, app, "xr:create")
    inbound = panel.state.inbounds[0]
    assert inbound.protocol == "vmess"
    assert inbound.network == "ws"
    assert panel.draft == {}
    assert "инбаунд создан" in html


async def test_custom_create_rejects_port_conflict(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    panel.draft = {"protocol": "vless", "network": "tcp", "security": "tls", "port": "443"}
    html = await press(bot, app, "xr:create")
    assert "занят" in html
    assert len(panel.state.inbounds) == 1


async def test_open_inbound_screen(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    html = await press(bot, app, "xr:in:1")
    assert "id 1" in html
    assert "public key" in html
    assert "switch_inline_query_current_chat" in html


async def test_open_missing_inbound(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:in:9")
    assert "не найден" in html


async def test_edit_renders_input_screen(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    html = await press(bot, app, "xr:edit:1:xr_remark")
    assert "ввести значение" in html
    assert 'query="ob xr_remark 1 "' in html


async def test_toggle_inbound(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    await press(bot, app, "xr:toggle:1")
    assert panel.state.inbound(1).enable is False
    html = await press(bot, app, "xr:toggle:1")
    assert panel.state.inbound(1).enable is True
    assert "инбаунд включен" in html


async def test_regen_keys_uses_remote_when_core_installed(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    control.state.installed = True
    panel.core = {"installed": True}
    html = await press(bot, app, "xr:keys:1")
    inbound = panel.state.inbound(1)
    assert inbound.private_key == "remote-private"
    assert inbound.public_key == "remote-public"
    assert "ключи reality обновлены" in html


async def test_regen_keys_local_fallback(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    before = panel.state.inbound(1).public_key
    await press(bot, app, "xr:keys:1")
    assert panel.state.inbound(1).public_key != before


async def test_regen_keys_on_plain_inbound(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vmess", 8443, "ws", "none"))
    html = await press(bot, app, "xr:keys:1")
    assert "только для reality" in html


async def test_delete_flow(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    confirm = await press(bot, app, "xr:del:1")
    assert "Подтвердить" in confirm
    html = await press(bot, app, "xr:del2:1")
    assert panel.state.inbounds == []
    assert "удален" in html


async def test_links_screen(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    inbound.make_client("phone")
    html = await press(bot, app, "xr:link:1")
    assert "vless://" in html
    assert "phone" in html
    assert "copy_text" in html


async def test_links_screen_without_clients(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    html = await press(bot, app, "xr:link:1")
    assert "добавьте клиента" in html


async def test_client_screen(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    inbound.make_client("phone")
    html = await press(bot, app, "xr:cl:1:phone")
    assert "phone" in html
    assert "vless://" in html
    assert "Удалить клиента" in html


async def test_client_delete(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    inbound.make_client("phone")
    html = await press(bot, app, "xr:cldel:1:phone")
    assert inbound.clients == []
    assert "удален" in html


async def test_core_screen(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:core")
    assert "Ядро Xray" in html
    assert "Установить или обновить" in html


async def test_check_reads_core_state(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    control.state.installed = True
    control.state.version = "26.10.21"
    control.state.service = "active"
    html = await press(bot, app, "xr:check")
    assert "26.10.21" in html
    assert panel.core["installed"] is True


async def test_check_requires_ssh(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path, ssh=False)
    html = await press(bot, app, "xr:check")
    assert "ssh" in html.lower()


async def test_install_core(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    html = await press(bot, app, "xr:core:install")
    assert ("install_core", "v26.10.21") in control.calls
    assert panel.core["installed"] is True
    assert "установлено" in html


async def test_core_version_switch_to_latest(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    html = await press(bot, app, "xr:core:ver:latest")
    assert panel.state.version == "latest"
    assert "выбрана версия ядра latest" in html
    html = await press(bot, app, "xr:core:install")
    assert ("install_core", "latest") in control.calls
    assert "установлено" in html


async def test_core_version_switch_back_to_pinned(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await press(bot, app, "xr:core:ver:latest")
    html = await press(bot, app, "xr:core:ver:v26.10.21")
    assert panel.state.version == "v26.10.21"
    assert "выбрана версия ядра v26.10.21" in html


async def test_core_version_rejects_unknown(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:core:ver:v1.2.3")
    assert "неизвестная версия ядра" in html
    assert panel.state.version == "v26.10.21"


async def test_core_version_switch_survives_reload(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await press(bot, app, "xr:core:ver:latest")
    other = make_bot(tmp_path)
    assert other[2].state.version == "latest"


async def test_install_core_reports_fallback(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    control.state.fallback = True
    control.state.fallback_version = "v26.10.21"
    html = await press(bot, app, "xr:core:install")
    assert "закрепленный" in html
    assert "v26.10.21" in html


async def test_apply_reports_fallback(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    control.state.fallback = True
    control.state.fallback_version = "v26.10.21"
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    html = await press(bot, app, "xr:core:apply")
    assert "закрепленного" in html


async def test_install_core_failure(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    control.fail = ("install_core", "github недоступен")
    html = await press(bot, app, "xr:core:install")
    assert "github недоступен" in html
    assert panel.core.get("installed") in {None, False}


async def test_apply_writes_config(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    inbound.make_client("owner")
    html = await press(bot, app, "xr:core:apply")
    assert ("apply", "v26.10.21") in control.calls
    body = json.loads(control.config_seen)
    assert body["inbounds"][0]["port"] == 443
    assert panel.core["listening"] == [443]
    assert "конфигурация применена" in html


async def test_apply_without_inbounds(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:core:apply")
    assert "применять нечего" in html


async def test_apply_failure(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    control.fail = ("apply", "порт занят")
    html = await press(bot, app, "xr:core:apply")
    assert "порт занят" in html


async def test_stop_and_restart(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    await press(bot, app, "xr:core:apply")
    html = await press(bot, app, "xr:core:stop")
    assert panel.core["service"] == "inactive"
    assert "остановка ядра выполнен" in html
    html = await press(bot, app, "xr:core:restart")
    assert panel.core["service"] == "active"
    assert "перезапуск ядра выполнен" in html


async def test_purge_flow(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    panel.core = {"installed": True, "version": "26.10.21"}
    confirm = await press(bot, app, "xr:core:purge")
    assert "Подтвердить" in confirm
    html = await press(bot, app, "xr:core:purge2")
    assert ("uninstall", True) in control.calls
    assert panel.core == {}
    assert "ядро удалено" in html


async def test_logs_screen(tmp_path: Path) -> None:
    bot, app, _, control = make_bot(tmp_path)
    html = await press(bot, app, "xr:logs:50")
    assert ("logs", 50) in control.calls
    assert "xray log 39" in html


async def test_logs_failure(tmp_path: Path) -> None:
    bot, app, _, control = make_bot(tmp_path)
    control.fail = ("logs", "журнал недоступен")
    html = await press(bot, app, "xr:logs")
    assert "журнал недоступен" in html


async def test_scan_screen_defaults(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:scan")
    assert "Сканер Reality" in html
    assert len(panel.state.scan_targets) == 10
    assert "www.cloudflare.com:443" in html


async def test_scan_run_uses_mocked_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot, app, panel, _ = make_bot(tmp_path)

    async def fake_scan(targets: list[str], **kw: Any) -> list[ScanResult]:
        assert targets
        return [
            ScanResult(target="www.cloudflare.com:443", host="www.cloudflare.com", feasible=True, latency_ms=25, server_names=["www.cloudflare.com"]),
            ScanResult(target="dead:443", feasible=False, reason="нет связи"),
        ]

    monkeypatch.setattr("BOT.panel.scan_targets", fake_scan)
    html = await press(bot, app, "xr:scan:run")
    assert panel.results[0].feasible is True
    assert "годных целей 1 из 2" in html
    assert "годен" in html


async def test_scan_run_reports_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot, app, panel, _ = make_bot(tmp_path)

    async def fake_scan(targets: list[str], **kw: Any) -> list[ScanResult]:
        from BOT.scan import ScanError

        raise ScanError("неверная подсеть")

    monkeypatch.setattr("BOT.panel.scan_targets", fake_scan)
    html = await press(bot, app, "xr:scan:run")
    assert "неверная подсеть" in html


async def test_scan_empty_targets(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.scan_targets = []
    html = await press(bot, app, "xr:scan:run")
    assert "список целей пуст" in html


async def test_scan_use_target_patches_reality(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    panel.results = [ScanResult(target="www.microsoft.com:443", host="www.microsoft.com", port=443, server_names=["www.microsoft.com"], feasible=True)]
    html = await press(bot, app, "xr:scan:use:0")
    assert inbound.dest == "www.microsoft.com:443"
    assert inbound.sni == "www.microsoft.com"
    assert "применена" in html


async def test_scan_use_without_inbound(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.results = [ScanResult(target="a:443", host="a", feasible=True)]
    html = await press(bot, app, "xr:scan:use:0")
    assert "сначала создайте reality инбаунд" in html


async def test_scan_use_bad_index(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    html = await press(bot, app, "xr:scan:use:7")
    assert "не найдена" in html
    html = await press(bot, app, "xr:scan:use:x")
    assert "неверный номер" in html


async def test_scan_targets_screen_and_reset(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.scan_targets = ["a:443"]
    html = await press(bot, app, "xr:scan:targets")
    assert "a:443" in html
    html = await press(bot, app, "xr:scan:reset")
    assert len(panel.state.scan_targets) == 10
    assert "сброшен" in html


async def test_unknown_xray_action(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    html = await press(bot, app, "xr:bogus")
    assert "неизвестное действие" in html


async def test_input_rename_inbound(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    await panel.apply_input(777, "xr_remark", "1", "node-a")
    assert panel.state.inbound(1).remark == "node-a"
    assert "имя обновлено" in app.last_html()
    saved = json.loads((tmp_path / "state" / "state.json").read_text(encoding="utf-8"))
    assert saved["xray"]["inbounds"][0]["remark"] == "node-a"


async def test_input_port_conflict(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    first = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    panel.state.add(new_inbound("trojan", 8443, "tcp", "reality"))
    await panel.apply_input(777, "xr_port", "1", "8443")
    assert first.port == 443
    assert "занят" in app.last_html()


async def test_input_bad_port(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    await panel.apply_input(777, "xr_port", "1", "70000")
    assert "1 до 65535" in app.last_html()


async def test_input_empty_remark(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    await panel.apply_input(777, "xr_remark", "1", "")
    assert "не может быть пустым" in app.last_html()


async def test_input_sni_and_dest(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    await panel.apply_input(777, "xr_sni", "1", "www.microsoft.com")
    assert inbound.sni == "www.microsoft.com"
    await panel.apply_input(777, "xr_dest", "1", "www.microsoft.com:8443")
    assert inbound.dest == "www.microsoft.com:8443"
    await panel.apply_input(777, "xr_dest", "1", "www.microsoft.com")
    assert inbound.dest == "www.microsoft.com:443"


async def test_input_short_id_and_keys(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    await panel.apply_input(777, "xr_short_id", "1", "deadbeef")
    assert inbound.short_ids == ["deadbeef"]
    await panel.apply_input(777, "xr_short_id", "1", "zzzz")
    assert inbound.short_ids == ["deadbeef"]
    await panel.apply_input(777, "xr_private_key", "1", "private-value")
    assert inbound.private_key == "private-value"
    await panel.apply_input(777, "xr_public_key", "1", "public-value")
    assert inbound.public_key == "public-value"


async def test_input_path_and_service(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 8443, "ws", "tls"))
    await panel.apply_input(777, "xr_path", "1", "obhod")
    assert inbound.path == "/obhod"
    await panel.apply_input(777, "xr_host_header", "1", "cdn.example.com")
    assert inbound.host_header == "cdn.example.com"
    await panel.apply_input(777, "xr_service", "1", "grpc-obhod")
    assert inbound.service_name == "grpc-obhod"


async def test_input_client_email(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    await panel.apply_input(777, "xr_client_email", "1", "phone-2")
    assert [item.email for item in inbound.clients] == ["phone-2"]
    assert "добавлен" in app.last_html()
    await panel.apply_input(777, "xr_client_email", "1", "phone-2")
    assert "уже есть" in app.last_html()
    await panel.apply_input(777, "xr_client_email", "1", "плохое имя")
    assert "буквы" in app.last_html() or "латиница" in app.last_html() or "имя" in app.last_html()


async def test_input_scan_targets(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await panel.apply_input(777, "xr_scan_targets", "", "a:443, b:8443")
    assert panel.state.scan_targets == ["a:443", "b:8443"]
    await panel.apply_input(777, "xr_scan_manual", "", "1.1.1.1:443")
    assert "1.1.1.1:443" in panel.state.scan_targets
    await panel.apply_input(777, "xr_scan_manual", "", "1.1.1.1:443")
    assert panel.state.scan_targets.count("1.1.1.1:443") == 1


async def test_input_scan_targets_empty(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await panel.apply_input(777, "xr_scan_targets", "", "")
    assert "пуст" in app.last_html()


async def test_input_log_level(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await panel.apply_input(777, "xr_log_level", "", "debug")
    assert panel.state.log_level == "debug"
    await panel.apply_input(777, "xr_log_level", "", "verbose")
    assert panel.state.log_level == "debug"
    assert "debug, info" in app.last_html()


async def test_input_cancel(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await panel.apply_input(777, "cancel", "", "")
    assert "ввод отменен" in app.last_html()


async def test_input_unknown_field(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await panel.apply_input(777, "xr_unknown", "1", "value")
    assert "не поддерживается" in app.last_html()


async def test_next_port_skips_used(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    for port in (443, 8443, 2053):
        panel.state.add(new_inbound("vless", port, "tcp", "none"))
    assert panel.next_port() == 2083


async def test_address_of_falls_back_to_ssh_host(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    inbound = panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    assert panel.address_of(inbound) == "203.0.113.10:443"
    bot.state.opts.host = "example.com"
    assert panel.address_of(inbound) == "example.com:443"


async def test_inline_handler_returns_results(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    evt = FakeInlineEvt(query="ob ssh_host - 10.1.1.1")
    await bot.on_inline(evt)
    assert evt.results
    assert evt.results[0]["send_message"]["message"] == "#ob ssh_host - 10.1.1.1"


async def test_inline_handler_picker(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    evt = FakeInlineEvt(query="ob")
    await bot.on_inline(evt)
    assert len(evt.results) == len(inline.FIELDS)


async def test_inline_handler_unknown_query_uses_picker(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    evt = FakeInlineEvt(query="garbage")
    await bot.on_inline(evt)
    assert evt.results
    assert evt.results[0]["id"].startswith("pick-")


async def test_inline_handler_blocks_strangers(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    evt = FakeInlineEvt(query="ob ssh_host - 10.1.1.1")
    evt.from_id = 42
    await bot.on_inline(evt)
    assert evt.results == []


async def test_inline_handler_with_bot_source(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    evt = FakeInlineEvt(query="ob xr_remark 1 node", src="bot")
    await bot.on_inline(evt)
    assert evt.results[0]["input_message_content"]["message_text"] == "#ob xr_remark 1 node"


async def test_marker_message_applies_value(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    panel.state.add(new_inbound("vless", 443, "tcp", "reality"))
    await bot.on_message(FakeEvt(text="#ob xr_remark 1 node-b", msg_id=55))
    assert panel.state.inbound(1).remark == "node-b"
    assert (777, 55) in app.deleted


async def test_marker_message_cancel(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    await bot.on_message(FakeEvt(text=inline.cancel_marker()))
    assert "ввод отменен" in app.last_html()


async def test_marker_message_ssh_field(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path, ssh=False)
    await bot.on_message(FakeEvt(text="#ob ssh_host - 198.51.100.7"))
    assert bot.state.ssh.host == "198.51.100.7"
    assert "SSH" in app.last_html() or "сервер" in app.last_html()


async def test_marker_message_ssh_field_invalid(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path, ssh=False)
    await bot.on_message(FakeEvt(text="#ob ssh_port - 99999"))
    assert bot.state.ssh.port == 22
    assert "1..65535" in app.last_html()


async def test_marker_message_from_stranger_is_blocked(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    await bot.on_message(FakeEvt(from_id=1, chat_id=1, text="#ob ssh_host - 6.6.6.6"))
    assert bot.state.ssh.host == "203.0.113.10"


async def test_panel_state_is_persisted(tmp_path: Path) -> None:
    bot, app, panel, _ = make_bot(tmp_path)
    await press(bot, app, "xr:new:vless:reality")
    saved = json.loads((tmp_path / "state" / "state.json").read_text(encoding="utf-8"))
    assert saved["xray"]["inbounds"][0]["protocol"] == "vless"
    reloaded = Bot(make_config(tmp_path / "state", admin_id=777), control=FakeControl())
    assert reloaded.state.xray.inbounds[0].port == 443


async def test_core_state_survives_reload(tmp_path: Path) -> None:
    bot, app, panel, control = make_bot(tmp_path)
    control.state.installed = True
    control.state.version = "26.10.21"
    await press(bot, app, "xr:check")
    reloaded = Bot(make_config(tmp_path / "state", admin_id=777), control=FakeControl())
    assert reloaded.state.xray.last_core["installed"] is True


async def test_error_screen_on_panel_failure(tmp_path: Path) -> None:
    bot, app, _, _ = make_bot(tmp_path)
    await bot.on_callback(FakeEvt(data="xr:in:42"))
    html = app.last_html()
    assert "не найден" in html


async def test_core_report_mapping(tmp_path: Path) -> None:
    from BOT.panel import state_report

    report = state_report(CoreState(installed=True, version="26.10.21", ports=[443], listening=[443], service="active"))
    assert report["ports"] == [443]
    assert report["service"] == "active"
    assert report["installed"] is True
