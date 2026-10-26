from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import inline
from .scan import ScanResult
from .xray import SCAN_DEFAULTS, XRAY_VERSION, XrayInbound, XrayState, summary
from .ui import (
    big,
    bold,
    bullet_list,
    button,
    code,
    copy_button,
    details,
    divider,
    heading,
    inline_button,

    muted,
    pre,
    quote,
    row,
    screen,
    table,
)

MAX_LINKS = 4

@dataclass
class XrayView:
    state: XrayState
    core: dict[str, Any] = field(default_factory=dict)
    notice: str = ""
    error: str = ""
    busy: str = ""
    draft: dict[str, str] = field(default_factory=dict)

    @property
    def installed(self) -> bool:
        return bool(self.core.get("installed", False))

    @property
    def running(self) -> bool:
        return str(self.core.get("service", "")) == "active"

    @property
    def version(self) -> str:
        return str(self.core.get("version", "") or "")

def banner(view: XrayView) -> list[str]:
    out: list[str] = []
    if view.notice:
        out.append(quote(muted(view.notice)))
    if view.error:
        out.append(quote(bold(view.error)))
    return out

def core_line(view: XrayView) -> str:
    if not view.core:
        return bold("ядро не проверено")
    parts = ["ядро установлено" if view.installed else "ядро не установлено"]
    if view.installed:
        parts.append(view.version or "версия неизвестна")
        parts.append("запущено" if view.running else "остановлено")
        if view.core.get("port"):
            parts.append(f"порт {view.core['port']}")
    return bold(", ".join(parts))

def back_row(target: str = "xr:home") -> str:
    return row(button("Xray", target), button("Главная", "nav:home"))

def home(view: XrayView) -> Any:
    state = view.state
    blocks = banner(view)
    blocks.append(f"<p>{core_line(view)}</p>")
    blocks.append(f"<p>цель: {code(view.core.get('config_path', '') or 'не задана')}</p>")
    if state.inbounds:
        pairs = []
        for item in state.inbounds:
            mark = "вкл" if item.enable else "выкл"
            pairs.append((f"{item.id} {item.remark}", f"{item.protocol} {item.port} {mark}"))
        blocks.append(table(pairs, ("инбаунд", "параметры")))
    else:
        blocks.append(quote(muted("инбаундов пока нет, создайте первый")))
    buttons = [
        row(button("Новый инбаунд", "xr:new"), button("Сканер подсети", "xr:scan")),
        row(button("Ядро", "xr:core"), button("Состояние", "xr:check")),
        row(button("Логи", "xr:logs"), button("Проверить сервер", "srv:check")),
        back_row("nav:server"),
    ]
    if state.inbounds:
        buttons.insert(2, row(*[button(f"открыть {item.remark}", f"xr:in:{item.id}") for item in state.inbounds[:3]]))
    return screen("Xray", "панель инбаундов и ядра", blocks, buttons, footer="конфигурация собирается ботом")

def new_menu(view: XrayView) -> Any:
    blocks = banner(view)
    blocks.append(quote(muted("выберите протокол, сеть и безопасность, затем задайте порт")))
    blocks.append(
        bullet_list(
            [
                f"протоколы: {code('vless')} {code('vmess')} {code('trojan')} {code('shadowsocks')}",
                f"сети: {code('tcp')} {code('ws')} {code('grpc')} {code('httpupgrade')} {code('xhttp')}",
                f"безопасность: {code('reality')} {code('tls')} {code('none')}",
            ]
        )
    )
    buttons = [
        row(button("vless reality", "xr:new:vless:reality"), button("vless tls", "xr:new:vless:tls")),
        row(button("vmess ws", "xr:new:vmess:none:ws"), button("trojan reality", "xr:new:trojan:reality")),
        row(button("shadowsocks", "xr:new:shadowsocks:none"), button("Свой набор", "xr:custom")),
        back_row(),
    ]
    return screen("Новый инбаунд", "готовые наборы", blocks, buttons)

def custom_menu(view: XrayView) -> Any:
    blocks = banner(view)
    blocks.append(f"<p>сеть {code(grab(view, 'network'))}, безопасность {code(grab(view, 'security'))}, протокол {code(grab(view, 'protocol'))}</p>")
    buttons = [
        row(button("протокол", "xr:cyc:protocol"), button("сеть", "xr:cyc:network")),
        row(button("безопасность", "xr:cyc:security"), button("Создать", "xr:create")),
        row(inline_button("порт", inline.prefill("xr_port"))),
        back_row(),
    ]
    return screen("Свой инбаунд", "переключайте параметры и создайте", blocks, buttons)

def grab(view: XrayView, key: str) -> str:
    return str(view.draft.get(key, ""))

def inbound_screen(view: XrayView, inbound: XrayInbound) -> Any:
    blocks = banner(view)
    blocks.append(f"<h3>{bold(inbound.remark)}</h3>")
    blocks.append(table(summary(inbound), ("параметр", "значение")))
    if inbound.security == "reality":
        blocks.append(
            details(
                "ключи reality",
                table(
                    [
                        ("public key", code(inbound.public_key or "нет")),
                        ("short id", code((inbound.short_ids or [""])[0])),
                        ("fingerprint", code(inbound.fingerprint)),
                    ],
                    ("поле", "значение"),
                ),
                open_=False,
            )
        )
    clients = [item.email for item in inbound.clients]
    blocks.append(f"<p>клиентов {code(len(clients))}: {escaped_join(clients) if clients else muted('нет')}</p>")
    buttons = [
        row(button("Ссылки", f"xr:link:{inbound.id}"), button("Добавить клиента", f"xr:cladd:{inbound.id}")),
        row(*[button(f"клиент {item.email}", f"xr:cl:{inbound.id}:{item.email}") for item in inbound.clients[:3]]),
        row(button("Порт", f"xr:edit:{inbound.id}:xr_port"), button("Имя", f"xr:edit:{inbound.id}:xr_remark")),
        row(button("Ключи", f"xr:keys:{inbound.id}"), button("Вкл/выкл", f"xr:toggle:{inbound.id}")),
        row(button("Удалить", f"xr:del:{inbound.id}"), button("К списку", "xr:home")),
        back_row(),
    ]
    if inbound.security == "reality":
        buttons.insert(
            3,
            row(
                inline_button("server name", inline.prefill("xr_sni", str(inbound.id))),
                inline_button("dest", inline.prefill("xr_dest", str(inbound.id))),
            ),
        )
    if inbound.network in {"ws", "httpupgrade", "xhttp"}:
        buttons.insert(4, row(inline_button("path", inline.prefill("xr_path", str(inbound.id)))))
    if inbound.network == "grpc":
        buttons.insert(4, row(inline_button("service", inline.prefill("xr_service", str(inbound.id)))))
    return screen("Инбаунд", f"id {inbound.id}", blocks, buttons)

def escaped_join(items: list[str]) -> str:
    return ", ".join(code(item) for item in items[:6])

def links_screen(view: XrayView, inbound: XrayInbound, address: str, links: list[tuple[str, str]]) -> Any:
    blocks = banner(view)
    blocks.append(f"<p>адрес {code(address)}</p>")
    if not links:
        blocks.append(quote(bold("у инбаунда нет клиентов, добавьте клиента")))
    for name, link in links[:MAX_LINKS]:
        blocks.append(heading(name, 4))
        blocks.append(pre(link))
    buttons = [
        row(*[copy_button(f"копировать {name}", link) for name, link in links[:2]]),
        row(button("Обновить", f"xr:link:{inbound.id}"), button("Инбаунд", f"xr:in:{inbound.id}")),
        back_row(),
    ]
    return screen("Ссылки инбаунда", inbound.remark, blocks, buttons)

def client_screen(view: XrayView, inbound: XrayInbound, client_email: str, link: str) -> Any:
    client = inbound.client(client_email)
    blocks = banner(view)
    if client is None:
        blocks.append(quote(bold("клиент не найден")))
        return screen("Клиент", client_email, blocks, [back_row(f"xr:in:{inbound.id}")])
    pairs = [("имя", code(client.email)), ("включен", code("да" if client.enable else "нет"))]
    if client.ident:
        pairs.append(("идентификатор", code(client.ident)))
    if client.password:
        pairs.append(("пароль", code(client.password)))
    if client.flow:
        pairs.append(("flow", code(client.flow)))
    blocks.append(table(pairs, ("поле", "значение")))
    if link:
        blocks.append(pre(link))
    buttons = [
        row(copy_button("копировать ссылку", link)) if link else "",
        row(button("Удалить клиента", f"xr:cldel:{inbound.id}:{client.email}"), button("Инбаунд", f"xr:in:{inbound.id}")),
        back_row(),
    ]
    return screen("Клиент", f"{inbound.remark} / {client.email}", blocks, buttons)

def core_screen(view: XrayView) -> Any:
    blocks = banner(view)
    core = view.core
    if core:
        pairs = [
            ("установлено", code("да" if core.get("installed") else "нет")),
            ("версия", code(core.get("version", "") or "нет")),
            ("закреплено", code(core.get("pinned", "") or "")),
            ("служба", code(core.get("service", "") or "нет")),
            ("systemd", code("да" if core.get("systemd") else "нет")),
            ("архитектура", code(core.get("arch", "") or "")),
            ("файл ядра", code(core.get("core_path", "") or "")),
            ("конфигурация", code(core.get("config_path", "") or "")),
            ("инбаундов в файле", code(core.get("inbounds", 0))),
            ("порты", code(", ".join(str(item) for item in core.get("ports") or []) or "нет")),
            ("слушают", code(", ".join(str(item) for item in core.get("listening") or []) or "нет")),
        ]
        blocks.append(table(pairs, ("параметр", "значение")))
        if core.get("config_digest"):
            blocks.append(f"<p>хеш конфигурации {code(str(core['config_digest'])[:24])}</p>")
    else:
        blocks.append(quote(muted("состояние ядра не читано")))
    buttons = [
        row(button("Установить или обновить", "xr:core:install"), button("Применить конфигурацию", "xr:core:apply")),
        row(button("Перезапустить", "xr:core:restart"), button("Остановить", "xr:core:stop")),
        row(button("Удалить ядро", "xr:core:purge"), button("Обновить", "xr:check")),
        version_row(view.state.version),
        row(inline_button("уровень логов", inline.prefill("xr_log_level"))),
        back_row(),
    ]
    return screen("Ядро Xray", "установка и служба", blocks, buttons)


def version_row(current: str) -> str:
    mark_latest = "версия latest" if current.lower() != "latest" else "latest выбрана"
    mark_pin = "версия " + XRAY_VERSION if current.lower() == "latest" else XRAY_VERSION + " выбрана"
    return row(
        button(mark_latest if current.lower() != "latest" else "latest", "xr:core:ver:latest"),
        button(mark_pin if current.lower() == "latest" else XRAY_VERSION, "xr:core:ver:" + XRAY_VERSION),
    )

def scan_screen(view: XrayView, results: list[ScanResult] | None = None) -> Any:
    state = view.state
    blocks = banner(view)
    rows = results if results is not None else [ScanResult.from_dict(item) for item in state.scan_results]
    blocks.append(f"<p>целей в списке {code(len(state.scan_targets))}</p>")
    blocks.append(pre("\n".join(state.scan_targets) or "нет"))
    if rows:
        pairs = []
        for item in rows[:10]:
            mark = "годен" if item.feasible else "не годен"
            name = (item.server_names[0] if item.server_names else "") or item.host or item.target
            pairs.append((item.target, f"{mark}, {item.latency_ms} ms, {name}"))
        blocks.append(table(pairs, ("цель", "итог")))
        best = next((item for item in rows if item.feasible), None)
        if best is not None:
            blocks.append(quote(muted(f"лучший кандидат {best.target}, задержка {best.latency_ms} ms")))
    else:
        blocks.append(quote(muted("сканирование еще не запускалось")))
    buttons = [
        row(button("Сканировать", "xr:scan:run"), button("Мои цели", "xr:scan:targets")),
        row(inline_button("своя цель", inline.prefill("xr_scan_manual")), button("Сброс к умолчанию", "xr:scan:reset")),
    ]
    if rows:
        buttons.insert(
            1,
            row(*[button(f"взять {item.target}", f"xr:scan:use:{index}") for index, item in enumerate(rows[:3])]),
        )
    buttons.append(back_row())
    return screen("Сканер Reality", "tls 1.3, h2, x25519, годный сертификат", blocks, buttons)

def scan_targets_screen(view: XrayView) -> Any:
    blocks = banner(view)
    blocks.append(quote(muted("список целей можно изменить одной строкой через запятую")))
    blocks.append(pre("\n".join(view.state.scan_targets) or "нет"))
    buttons = [
        row(inline_button("изменить список", inline.prefill("xr_scan_targets"))),
        row(button("К умолчанию", "xr:scan:reset"), button("Сканер", "xr:scan")),
        back_row(),
    ]
    return screen("Цели сканирования", "host:port или подсеть", blocks, buttons)

def input_screen(view: XrayView, ident: str, ctx: str = "", back: str = "xr:home") -> Any:
    from . import inline as input_fields

    item = input_fields.field(ident)
    blocks = banner(view)
    blocks.append(table([("поле", code(item.label)), ("подсказка", muted(item.hint))], ("поле", "значение")))
    if item.example:
        blocks.append(f"<p>пример {code(item.example)}</p>")
    blocks.append(quote(muted("нажмите кнопку ввода, наберите значение в строке запроса и выберите результат")))
    buttons = [
        row(inline_button("ввести значение", input_fields.prefill(ident, ctx or "-"))),
        row(button("Назад", back), button("Xray", "xr:home")),
    ]
    return screen("Ввод значения", item.label, blocks, buttons)


def confirm_screen(view: XrayView, title: str, body: str, action: str, back: str = "xr:home") -> Any:
    blocks = banner(view)
    blocks.append(quote(bold(body)))
    buttons = [row(button("Подтвердить", action), button("Отмена", back))]
    return screen(title, "действие необратимо", blocks, buttons)

def logs_screen(view: XrayView, lines: list[str], tail: int) -> Any:
    blocks = banner(view)
    blocks.append(f"<p>последние {code(tail)} строк</p>")
    blocks.append(pre("\n".join(lines) or "пусто"))
    buttons = [
        row(button("50", "xr:logs:50"), button("200", "xr:logs:200"), button("500", "xr:logs:500")),
        row(button("Обновить", f"xr:logs:{tail}"), button("Ядро", "xr:core")),
        back_row(),
    ]
    return screen("Логи Xray", "journal или файл состояния", blocks, buttons)

def busy_screen(title: str, steps: list[str] | None = None) -> Any:
    blocks = [quote(muted(title))]
    if steps:
        blocks.append(bullet_list([muted(item) for item in steps]))
    return screen("Xray", "выполняется", blocks, [])

def default_targets() -> list[str]:
    return list(SCAN_DEFAULTS)

def key_row(inbound: XrayInbound) -> str:
    return row(
        copy_button("копировать public key", inbound.public_key or ""),
        copy_button("копировать short id", (inbound.short_ids or [""])[0]),
    )

def stat_line(inbound: XrayInbound) -> str:
    return f"{inbound.protocol} {inbound.port} {inbound.network} {inbound.security}"

def links_hint(inbound: XrayInbound) -> str:
    return divider() + f"<p>{muted('ссылки собираются по правилам 3x-ui')}</p>"

def summary_pairs(inbound: XrayInbound) -> list[tuple[str, str]]:
    return summary(inbound)

def mask_host(host: str) -> str:
    if not host:
        return "не задан"
    parts = host.split(".")
    if len(parts) == 4:
        return ".".join(parts[:2] + ["*", "*"])
    return host

def target_pairs(results: list[ScanResult]) -> list[tuple[str, str]]:
    return [(item.target, f"{item.latency_ms} ms") for item in results[:10]]

def xray_button_row() -> str:
    return row(button("Xray", "nav:xray"), button("Сканер", "xr:scan"))

def apply_hint(state: XrayState) -> str:
    if not state.inbounds:
        return muted("нет инбаундов, применять нечего")
    return muted(f"инбаундов к записи: {len(state.enabled())}")

def top_row() -> str:
    return big("Xray панель", "nav:xray")
