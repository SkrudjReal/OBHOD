from __future__ import annotations

import re

import pytest
from goygram.rich import Rich

from BOT import screens
from BOT.links import build_link
from BOT.models import ClientInfo, ProbeResult, RemoteConfig, ShareInfo
from BOT.screens import View
from BOT.ui import count_buttons
from tests.fakes import WG, make_state

BUTTON_RE = re.compile(r"<tg-button ([^>]*)>([^<]*)</tg-button>")
ROW_RE = re.compile(r"<tg-button-row[^>]*>(.*?)</tg-button-row>", re.S)
CALLBACK_RE = re.compile(r'data="([^"]*)"')


def full_view() -> View:
    state = make_state()
    return View(
        state=state,
        probe=ProbeResult(
            installed=True,
            running=True,
            version="4.1.0",
            euid=0,
            arch="x86_64",
            method="docker",
            config=RemoteConfig(method="docker", backend="new", listen_port=56000, obf_key="a" * 64),
        ),
        clients=[
            ClientInfo(name="owner", client_id="cid-owner", is_self=True, ip="10.13.13.2", pub="cHVi", handshake=1700000000),
            ClientInfo(name="phone", client_id="cid-phone", ip="10.13.13.3"),
        ],
        share=ShareInfo(backend="new", host="203.0.113.10", port=56000, mode="udp", obf_profile="rtpopus3"),
        notice="уведомление",
    )


def render_all() -> list[tuple[str, Rich]]:
    view = full_view()
    link = build_link("203.0.113.10:56000", view.state.opts, view.state.link, "cid-owner", "owner", WG)
    client = view.clients[0]
    items: list[tuple[str, Rich]] = [
        ("home", screens.home(view)),
        ("server", screens.server(view)),
        ("ssh", screens.ssh_settings(view)),
        ("setup", screens.setup(view)),
        ("obf", screens.obf_menu(view)),
        ("clients", screens.clients(view)),
        ("client", screens.client(view, "owner")),
        ("confirm_remove", screens.confirm_remove(view, "phone")),
        ("confirm_uninstall", screens.confirm_uninstall(view)),
        ("link_settings", screens.link_settings(view)),
        ("link", screens.link_screen(view, "owner", link, WG, client)),
        ("wg", screens.wg_screen(view, "owner", WG, client)),
        ("config", screens.config_screen(view, "owner")),
        ("logs", screens.logs(view, [f"line {index}" for index in range(40)], 200)),
        ("maint", screens.maintenance(view)),
        ("help", screens.help_screen(view)),
        ("import", screens.import_screen(view, rows=[("peer", "203.0.113.10:56000")], raw=link)),
        ("import_error", screens.import_screen(view, error="ссылка не разобрана")),
        ("error", screens.error_screen(view, "Ошибка", "нет связи")),
        ("prompt", screens.prompt(_spec())),
        ("prompt_error", screens.prompt(_spec(), error="порт вне диапазона")),
        ("busy", screens.busy_screen("применение", "шаг 1")),
        ("denied", screens.denied()),
        ("void", screens.void()),
    ]
    return items


def _spec() -> object:
    from BOT.flows import Flows

    return Flows().field("ssh_port")


SCREENS = render_all()
IDS = [name for name, _ in SCREENS]


@pytest.mark.parametrize("name,rich", SCREENS, ids=IDS)
def test_screen_is_rich(name: str, rich: Rich) -> None:
    assert isinstance(rich, Rich)
    html = rich.build()
    assert html.startswith("<h2>")
    assert "None" not in html


@pytest.mark.parametrize("name,rich", SCREENS, ids=IDS)
def test_buttons_inside_rows(name: str, rich: Rich) -> None:
    html = rich.build()
    inside = sum(count_buttons(body) for body in ROW_RE.findall(html))
    assert inside == count_buttons(html)


@pytest.mark.parametrize("name,rich", SCREENS, ids=IDS)
def test_callbacks_short_and_plain(name: str, rich: Rich) -> None:
    html = rich.build()
    for value in CALLBACK_RE.findall(html):
        assert len(value.encode()) <= 64
        assert " " not in value
        assert not value.startswith("http")


@pytest.mark.parametrize("name,rich", SCREENS, ids=IDS)
def test_no_url_buttons(name: str, rich: Rich) -> None:
    assert 'type="url"' not in rich.build()


@pytest.mark.parametrize("name,rich", SCREENS, ids=IDS)
def test_button_budget(name: str, rich: Rich) -> None:
    assert count_buttons(rich.build()) <= 18


def test_home_facts() -> None:
    html = screens.home(full_view()).build()
    assert "203.0.113.10" in html
    assert "56000" in html
    assert "rtpopus3" in html


def test_home_without_server() -> None:
    view = full_view()
    view.state.ssh.host = ""
    view.probe = None
    html = screens.home(view).build()
    assert "не задан" in html
    assert "состояние не читано" in html


def test_server_backend_rows() -> None:
    view = full_view()
    html = screens.server(view).build()
    assert "10.13.13.0/24" in html
    view.state.opts.backend = "external"
    view.state.opts.connect = "127.0.0.1:51820"
    html = screens.server(view).build()
    assert "127.0.0.1:51820" in html


def test_server_apply_label_switches() -> None:
    view = full_view()
    view.probe = ProbeResult(installed=False)
    html = screens.server(view).build()
    assert "Установить на сервер" in html


def test_clients_empty() -> None:
    view = full_view()
    view.clients = []
    view.share = None
    assert "список пуст" in screens.clients(view).build()


def test_client_unknown_name_falls_back() -> None:
    html = screens.client(full_view(), "ghost").build()
    assert "ghost" in html


def test_link_screen_contains_link() -> None:
    view = full_view()
    link = build_link("203.0.113.10:56000", view.state.opts, view.state.link, "cid", "owner", WG)
    html = screens.link_screen(view, "owner", link, WG, view.clients[0]).build()
    assert link in html
    assert 'type="copy_text"' in html
    assert "<details" in html


def test_config_screen_json() -> None:
    import json

    html = screens.config_screen(full_view(), "owner").build()
    start = html.index('class="language-json">') + len('class="language-json">')
    end = html.index("</code>", start)
    body = html[start:end]
    body = body.replace("&quot;", '"').replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    data = json.loads(body)
    assert data["peer"] == "203.0.113.10:56000"
    assert data["clientId"] == "cid-owner"
    assert data["obf"]["profile"] == "rtpopus3"


def test_logs_screen_tail() -> None:
    html = screens.logs(full_view(), ["alpha", "beta"], 200).build()
    assert "alpha" in html
    assert "beta" in html


def test_prompt_shows_hint_and_error() -> None:
    html = screens.prompt(_spec(), error="плохо").build()
    assert "плохо" in html
    assert "Порт SSH" in html


def test_denied_has_no_buttons() -> None:
    assert count_buttons(screens.denied().build()) == 0


def test_setup_has_pinned_version_buttons() -> None:
    html = screens.setup(full_view()).build()
    assert 'data="setup:ver:v4.1.0"' in html
    assert 'data="setup:ver:latest"' in html
    assert "Своя версия" in html


def test_setup_mentions_pinned_policy() -> None:
    html = screens.setup(full_view()).build()
    assert "версия ядра закреплена" in html


def test_confirm_reset_lists_destructive_steps() -> None:
    html = screens.confirm_reset(full_view()).build()
    assert "переустановка с нуля" in html
    assert "контейнер" in html
    assert "ft-wg0" in html
    assert "процессы" in html
    assert "/opt/free-turn-proxy" in html
    assert 'data="maint:reset2"' in html
    assert "перестанут работать" in html


def test_confirm_reset_has_single_danger_action() -> None:
    html = screens.confirm_reset(full_view()).build()
    buttons = BUTTON_RE.findall(html)
    danger = [body for attrs, body in buttons if 'style="danger"' in attrs]
    assert danger == ["Удалить все и поставить заново"]


def test_maintenance_offers_reset() -> None:
    html = screens.maintenance(full_view()).build()
    assert 'data="maint:reset"' in html
    assert "Переустановить с нуля" in html


def test_server_screen_offers_reset_and_uninstall() -> None:
    html = screens.server(full_view()).build()
    assert 'data="srv:reset"' in html
    assert 'data="srv:uninstall"' in html
    assert 'data="maint:uninstall2"' not in html


def test_uninstall_confirmation_follows_the_entry_point() -> None:
    assert 'data="maint:uninstall2"' in screens.confirm_uninstall(full_view()).build()
    assert 'data="srv:uninstall2"' in screens.confirm_uninstall(full_view(), "srv:uninstall2").build()


def test_every_screen_stays_within_button_budget() -> None:
    view = full_view()
    for rich in (
        screens.home(view),
        screens.server(view),
        screens.setup(view),
        screens.maintenance(view),
        screens.clients(view),
        screens.link_settings(view),
        screens.help_screen(view),
        screens.confirm_reset(view),
        screens.confirm_uninstall(view),
    ):
        assert count_buttons(rich.build()) <= 18
