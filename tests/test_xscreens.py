from __future__ import annotations

import pytest

from BOT import xscreens
from BOT.scan import ScanResult
from BOT.ui import MAX_BUTTONS, count_buttons
from BOT.xray import XrayState, new_inbound


def build(state: XrayState | None = None, core: dict | None = None, **kw) -> xscreens.XrayView:
    view = xscreens.XrayView(state=state or XrayState(), core=core if core is not None else {}, **kw)
    view.draft = {}
    return view


def html(rich) -> str:
    return rich.build() if hasattr(rich, "build") else str(rich)


def with_inbound(protocol: str = "vless", port: int = 443, network: str = "tcp", security: str = "reality") -> tuple[XrayState, object]:
    state = XrayState()
    inbound = state.add(new_inbound(protocol, port, network, security))
    inbound.make_client("owner")
    return state, inbound


def test_home_without_inbounds() -> None:
    body = html(xscreens.home(build()))
    assert "Xray" in body
    assert "инбаундов пока нет" in body
    assert "ядро не проверено" in body


def test_home_with_core_and_inbounds() -> None:
    state, _ = with_inbound()
    view = build(state, {"installed": True, "version": "26.10.21", "service": "active", "port": 443, "config_path": "/usr/local/etc/xray/config.json"})
    body = html(xscreens.home(view))
    assert "ядро установлено" in body
    assert "26.10.21" in body
    assert "запущено" in body
    assert "vless-443" in body


def test_home_shows_notice_and_error() -> None:
    body = html(xscreens.home(build(notice="сохранено", error="сбой")))
    assert "сохранено" in body
    assert "сбой" in body


def test_core_line_states() -> None:
    assert "не установлено" in xscreens.core_line(build(core={"installed": False}))
    assert "остановлено" in xscreens.core_line(build(core={"installed": True, "service": "inactive"}))


def test_new_menu_lists_protocols() -> None:
    body = html(xscreens.new_menu(build()))
    for token in ("vless reality", "vless tls", "vmess ws", "trojan reality", "shadowsocks"):
        assert token in body


def test_custom_menu_uses_draft() -> None:
    view = build()
    view.draft = {"protocol": "vmess", "network": "ws", "security": "tls"}
    body = html(xscreens.custom_menu(view))
    assert "vmess" in body
    assert "ws" in body
    assert "tls" in body


def test_inbound_screen_reality_details() -> None:
    state, inbound = with_inbound()
    body = html(xscreens.inbound_screen(build(state), inbound))
    assert "public key" in body
    assert "short id" in body
    assert "owner" in body
    assert 'query="ob xr_sni 1 "' in body


def test_inbound_screen_ws_path_button() -> None:
    state, inbound = with_inbound("vless", 8443, "ws", "tls")
    body = html(xscreens.inbound_screen(build(state), inbound))
    assert 'query="ob xr_path 1 "' in body
    assert "path" in body


def test_inbound_screen_grpc_service_button() -> None:
    state, inbound = with_inbound("vless", 8443, "grpc", "tls")
    body = html(xscreens.inbound_screen(build(state), inbound))
    assert 'query="ob xr_service 1 "' in body


def test_inbound_screen_without_clients() -> None:
    state = XrayState()
    inbound = state.add(new_inbound("vless", 443, "tcp", "reality"))
    body = html(xscreens.inbound_screen(build(state), inbound))
    assert "нет" in body


def test_links_screen_lists_links() -> None:
    state, inbound = with_inbound()
    links = [("owner", "vless://uuid@host:443?security=reality#owner")]
    body = html(xscreens.links_screen(build(state), inbound, "host:443", links))
    assert "vless://uuid@host:443" in body
    assert "copy_text" in body


def test_links_screen_empty() -> None:
    state, inbound = with_inbound()
    body = html(xscreens.links_screen(build(state), inbound, "host:443", []))
    assert "добавьте клиента" in body


def test_links_screen_limits_rows() -> None:
    state, inbound = with_inbound()
    links = [(f"c{index}", f"vless://x{index}@h:443") for index in range(8)]
    body = html(xscreens.links_screen(build(state), inbound, "h:443", links))
    assert "vless://x0@" in body
    assert "vless://x5@" not in body


def test_client_screen_fields() -> None:
    state, inbound = with_inbound()
    client = inbound.clients[0]
    body = html(xscreens.client_screen(build(state), inbound, client.email, "vless://link"))
    assert client.email in body
    assert client.ident in body
    assert "flow" in body
    assert "copy_text" in body


def test_client_screen_missing_client() -> None:
    state, inbound = with_inbound()
    body = html(xscreens.client_screen(build(state), inbound, "ghost", ""))
    assert "клиент не найден" in body


def test_core_screen_table() -> None:
    core = {
        "installed": True,
        "version": "26.10.21",
        "pinned": "v26.10.21",
        "service": "active",
        "systemd": True,
        "arch": "x86_64",
        "core_path": "/usr/local/bin/xray",
        "config_path": "/usr/local/etc/xray/config.json",
        "inbounds": 2,
        "ports": [443, 8443],
        "listening": [443],
        "config_digest": "a" * 64,
    }
    body = html(xscreens.core_screen(build(core=core)))
    assert "26.10.21" in body
    assert "443, 8443" in body
    assert "a" * 24 in body


def test_core_screen_empty() -> None:
    body = html(xscreens.core_screen(build()))
    assert "состояние ядра не читано" in body


def test_scan_screen_without_results() -> None:
    body = html(xscreens.scan_screen(build()))
    assert "Сканер Reality" in body
    assert "сканирование еще не запускалось" in body
    assert "www.cloudflare.com:443" in body


def test_scan_screen_with_results() -> None:
    results = [
        ScanResult(target="a:443", host="a", feasible=True, latency_ms=12, server_names=["a"]),
        ScanResult(target="b:443", host="b", feasible=False, latency_ms=0, reason="нет tls 1.3"),
    ]
    body = html(xscreens.scan_screen(build(), results))
    assert "годен" in body
    assert "не годен" in body
    assert "лучший кандидат a:443" in body
    assert "взять a:443" in body


def test_scan_screen_restores_persisted_results() -> None:
    state = XrayState()
    state.scan_results = [ScanResult(target="stored:443", feasible=True, latency_ms=5).to_dict()]
    body = html(xscreens.scan_screen(build(state)))
    assert "stored:443" in body


def test_scan_targets_screen() -> None:
    state = XrayState()
    state.scan_targets = ["a:443", "b:8443"]
    body = html(xscreens.scan_targets_screen(build(state)))
    assert "a:443" in body
    assert 'query="ob xr_scan_targets - "' in body


def test_confirm_screen() -> None:
    body = html(xscreens.confirm_screen(build(), "Удаление", "инбаунд будет удален", "xr:del2:1"))
    assert "Подтвердить" in body
    assert 'data="xr:del2:1"' in body


def test_input_screen_has_inline_button() -> None:
    body = html(xscreens.input_screen(build(), "xr_sni", "3", "xr:in:3"))
    assert 'type="switch_inline_query_current_chat"' in body
    assert 'query="ob xr_sni 3 "' in body
    assert "server name" in body


def test_input_screen_shows_error() -> None:
    body = html(xscreens.input_screen(build(error="плохое значение"), "xr_port", "", "xr:home"))
    assert "плохое значение" in body


def test_logs_screen() -> None:
    body = html(xscreens.logs_screen(build(), ["line one", "line two"], 200))
    assert "line one" in body
    assert "последние" in body


def test_logs_screen_empty() -> None:
    body = html(xscreens.logs_screen(build(), [], 50))
    assert "пусто" in body


def test_busy_screen() -> None:
    body = html(xscreens.busy_screen("сканирование", ["шаг один"]))
    assert "сканирование" in body
    assert "шаг один" in body


def test_button_budget_home() -> None:
    body = html(xscreens.home(build()))
    assert count_buttons(body) <= MAX_BUTTONS


def test_button_budget_inbound() -> None:
    state, inbound = with_inbound("vless", 443, "tcp", "reality")
    body = html(xscreens.inbound_screen(build(state), inbound))
    assert count_buttons(body) <= MAX_BUTTONS


def test_button_budget_core_and_scan() -> None:
    assert count_buttons(html(xscreens.core_screen(build()))) <= MAX_BUTTONS
    assert count_buttons(html(xscreens.scan_screen(build()))) <= MAX_BUTTONS


def test_callback_data_is_short() -> None:
    state, inbound = with_inbound()
    body = html(xscreens.inbound_screen(build(state), inbound))
    for chunk in body.split('data="')[1:]:
        value = chunk.split('"')[0]
        assert len(value.encode("utf-8")) <= 64


def test_summary_pairs_mirror_model() -> None:
    state, inbound = with_inbound("trojan", 8443, "ws", "tls")
    pairs = dict(xscreens.summary_pairs(inbound))
    assert pairs["протокол"] == "trojan"
    assert pairs["сеть"] == "ws"


def test_mask_host() -> None:
    assert xscreens.mask_host("") == "не задан"
    assert xscreens.mask_host("203.0.113.10") == "203.0.*.*"
    assert xscreens.mask_host("example.com") == "example.com"


def test_stat_line() -> None:
    _, inbound = with_inbound("vless", 8443, "xhttp", "tls")
    assert xscreens.stat_line(inbound) == "vless 8443 xhttp tls"


def test_default_targets_copy() -> None:
    first = xscreens.default_targets()
    first.append("mutated:443")
    assert "mutated:443" not in xscreens.default_targets()


def test_apply_hint() -> None:
    assert "применять нечего" in xscreens.apply_hint(XrayState())
    state, _ = with_inbound()
    assert "1" in xscreens.apply_hint(state)


def test_escaped_join() -> None:
    body = xscreens.escaped_join(["a", "b"])
    assert "<code>a</code>" in body


def test_target_pairs() -> None:
    pairs = xscreens.target_pairs([ScanResult(target="a:443", latency_ms=9)])
    assert pairs == [("a:443", "9 ms")]


def test_html_is_escaped_in_remark() -> None:
    state = XrayState()
    inbound = state.add(new_inbound("vless", 443, "tcp", "reality"))
    inbound.remark = "<script>alert(1)</script>"
    body = html(xscreens.home(build(state)))
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


def test_screen_titles_present() -> None:
    for rich, title in (
        (xscreens.home(build()), "Xray"),
        (xscreens.new_menu(build()), "Новый инбаунд"),
        (xscreens.core_screen(build()), "Ядро Xray"),
        (xscreens.scan_screen(build()), "Сканер Reality"),
    ):
        assert title in html(rich)


def test_view_defaults() -> None:
    view = xscreens.XrayView(state=XrayState())
    assert view.installed is False
    assert view.running is False
    assert view.version == ""
    assert view.draft == {}


def test_key_row_buttons() -> None:
    _, inbound = with_inbound()
    body = xscreens.key_row(inbound)
    assert "copy_text" in body
    assert inbound.public_key in body


def test_links_hint_mentions_3xui() -> None:
    _, inbound = with_inbound()
    assert "3x-ui" in xscreens.links_hint(inbound)


def test_top_row_button() -> None:
    assert 'data="nav:xray"' in xscreens.top_row()
    assert 'data="xr:scan"' in xscreens.xray_button_row()


def test_back_row_targets() -> None:
    body = xscreens.back_row()
    assert 'data="xr:home"' in body
    assert 'data="nav:home"' in body
    assert 'data="xr:in:5"' in xscreens.back_row("xr:in:5")


def test_scan_screen_survives_bad_persisted_rows() -> None:
    state = XrayState()
    state.scan_results = [{"target": "x:443"}]
    body = html(xscreens.scan_screen(build(state)))
    assert "x:443" in body


@pytest.mark.parametrize("network", ["tcp", "ws", "grpc", "httpupgrade", "xhttp"])
def test_inbound_screens_render_for_every_network(network: str) -> None:
    state = XrayState()
    inbound = state.add(new_inbound("vless", 8443, network, "tls"))
    inbound.make_client("owner")
    body = html(xscreens.inbound_screen(build(state), inbound))
    assert network in body


def test_version_row_offers_latest_and_pin() -> None:
    row_html = xscreens.version_row("v26.10.21")
    assert "xr:core:ver:latest" in row_html
    assert "xr:core:ver:v26.10.21" in row_html
    assert "версия latest" in row_html


def test_version_row_marks_latest_when_selected() -> None:
    row_html = xscreens.version_row("latest")
    assert '>latest</tg-button>' in row_html
    assert '>версия v26.10.21</tg-button>' in row_html


def test_core_screen_has_version_buttons() -> None:
    view = build(core={"installed": True, "version": "26.10.21"})
    body = html(xscreens.core_screen(view))
    assert "xr:core:ver:latest" in body
    assert "xr:core:ver:v26.10.21" in body
