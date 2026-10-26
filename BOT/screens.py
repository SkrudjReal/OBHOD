from __future__ import annotations

from dataclasses import dataclass, field

from goygram.rich import Rich

from .links import core_config, normalize_conf, wg_summary
from .models import (
    AUTH_KEY,
    BACKEND_NEW,
    OBF_PROFILES,
    ClientInfo,
    ProbeResult,
    ShareInfo,
)
from .store import State
from .ui import (
    big,
    bold,
    bullet_list,
    button,
    code,
    copy_button,
    details,
    heading,
    muted,
    numbered,
    pre,
    quote,
    row,
    screen,
    table,
)

@dataclass
class View:
    state: State
    probe: ProbeResult | None = None
    clients: list[ClientInfo] = field(default_factory=list)
    share: ShareInfo | None = None
    notice: str = ""
    error: str = ""


def mask(value: str) -> str:
    if not value:
        return muted("не задано")
    return code("*" * min(len(value), 12)) + " " + muted(f"{len(value)} символов")


def flag(value: bool, yes: str = "да", no: str = "нет") -> str:
    return code(yes if value else no)


def status_line(view: View) -> str:
    probe = view.probe
    if probe is None:
        return bold("состояние не читано")
    parts = []
    parts.append("установлено" if probe.installed else "не установлено")
    parts.append("запущено" if probe.running else "остановлено")
    if probe.version:
        parts.append(probe.version)
    return bold(", ".join(parts))


def banner(view: View) -> list[str]:
    out: list[str] = []
    if view.notice:
        out.append(quote(muted(view.notice)))
    if view.error:
        out.append(quote(bold(view.error)))
    return out


def back_row() -> str:
    return row(button("Главная", "nav:home"), button("Сервер", "nav:server"))


def home(view: View) -> Rich:
    state = view.state
    ssh = state.ssh
    blocks = [
        f"<p>{status_line(view)}</p>",
        table(
            [
                ("сервер", code(ssh.host or "не задан") + (":" + code(ssh.port) if ssh.host else "")),
                ("доступ", code("ключ" if ssh.auth == AUTH_KEY else "пароль") if ssh.is_ready() else muted("не настроен")),
                ("режим root", code(ssh.mode)),
                ("клиентов", code(len(view.clients))),
                ("порт входа", code(state.opts.listen_port)),
                ("обфускация", code(state.opts.obf_profile)),
            ]
        ),
    ]
    blocks.extend(banner(view))
    buttons = [
        big("Сервер", "nav:server", "primary"),
        big("Клиенты", "nav:clients"),
        row(button("Ссылки", "nav:link"), button("Журнал", "nav:logs")),
        row(button("Параметры установки", "nav:setup"), button("SSH", "nav:ssh")),
        row(button("Обслуживание", "nav:maint"), button("Помощь", "nav:help")),
    ]
    return screen("OBHOD", "управление free turn на одном сервере", blocks, buttons, footer=muted("mtproto transport, rich interface"))


def server(view: View) -> Rich:
    state = view.state
    opts = state.opts
    probe = view.probe
    rows = [
        ("статус", status_line(view)),
        ("ssh", code(f"{state.ssh.user}@{state.ssh.host or '-'}:{state.ssh.port}")),
        ("метод", code(opts.method)),
        ("backend", code(opts.backend)),
        ("порт входа", code(opts.listen_port)),
    ]
    if opts.backend == BACKEND_NEW:
        rows.append(("wireguard", code(f"{opts.wg_net} udp/{opts.wg_port}")))
    else:
        rows.append(("внешний vpn", code(opts.connect or "-")))
    rows.extend(
        [
            ("режим", code(opts.mode)),
            ("обфускация", code(opts.obf_profile)),
            ("ключ", mask(opts.obf_key)),
            ("версия", code(opts.version)),
        ]
    )
    if probe is not None and probe.arch:
        rows.append(("архитектура", code(probe.arch)))
    blocks = [table(rows)]
    if probe is not None and probe.config is not None and probe.config.obf_key:
        blocks.append(details("конфигурация на сервере", table([
            ("метод", code(probe.config.method or "-")),
            ("backend", code(probe.config.backend or "-")),
            ("порт", code(probe.config.listen_port or "-")),
            ("ключ", mask(probe.config.obf_key)),
        ])))
    blocks.extend(banner(view))
    apply_label = "Применить конфигурацию" if probe is not None and probe.installed else "Установить на сервер"
    buttons = [
        big("Проверить связь и состояние", "srv:check", "primary"),
        big(apply_label, "srv:apply", "success"),
        row(button("Остановить", "srv:stop"), button("Перезапустить", "srv:restart")),
        row(button("Параметры установки", "nav:setup"), button("SSH", "nav:ssh")),
        row(button("Журнал", "nav:logs"), button("Обслуживание", "nav:maint")),
        back_row(),
    ]
    return screen("Сервер", "все действия идут через install.sh по ssh", blocks, buttons)


def ssh_settings(view: View) -> Rich:
    ssh = view.state.ssh
    rows = [
        ("хост", code(ssh.host or "не задан")),
        ("порт", code(ssh.port)),
        ("пользователь", code(ssh.user)),
        ("вход по", code("ключу" if ssh.auth == AUTH_KEY else "паролю")),
        ("пароль", mask(ssh.password)),
        ("ключ", mask(ssh.key)),
        ("пароль ключа", mask(ssh.passphrase)),
        ("пароль sudo", mask(ssh.sudo_password)),
        ("режим root", code(ssh.mode)),
        ("отпечаток", code(ssh.fingerprint[:26] + "...") if ssh.fingerprint else muted("не сохранен")),
    ]
    blocks = [
        table(rows),
        quote(muted("пароли и ключи лежат в state.json с правами 600 и никогда не попадают в сообщения")),
    ]
    blocks.extend(banner(view))
    buttons = [
        big("Изменить адрес сервера", "ssh:edit:ssh_host", "primary"),
        row(button("Порт", "ssh:edit:ssh_port"), button("Пользователь", "ssh:edit:ssh_user")),
        row(button("Пароль", "ssh:edit:ssh_password"), button("Ключ", "ssh:edit:ssh_key")),
        row(button("Пароль ключа", "ssh:edit:ssh_passphrase"), button("Пароль sudo", "ssh:edit:ssh_sudo")),
        row(button("Сменить способ входа", "ssh:togglemode"), button("Сбросить отпечаток", "ssh:clearfp")),
        row(button("Проверить связь", "srv:check"), button("Главная", "nav:home")),
    ]
    return screen("Доступ по SSH", "бот входит на сервер и запускает install.sh", blocks, buttons)


def setup(view: View) -> Rich:
    opts = view.state.opts
    rows = [
        ("backend", code("свой wireguard" if opts.backend == BACKEND_NEW else "внешний vpn")),
        ("метод", code(opts.method)),
        ("порт входа", code(opts.listen_port)),
        ("режим", code(opts.mode)),
        ("обфускация", code(opts.obf_profile)),
        ("ключ", mask(opts.obf_key)),
        ("версия", code(opts.version)),
    ]
    if opts.backend == BACKEND_NEW:
        rows.append(("wireguard", code(f"{opts.wg_net} udp/{opts.wg_port}")))
    else:
        rows.append(("внешний vpn", code(opts.connect or "не задан")))
    rows.append(("адрес в ссылке", code(opts.host or view.state.ssh.host or "не задан")))
    blocks = [
        table(rows),
        quote(muted("свой wireguard поднимается на сервере, внешний vpn уже работает вне бота")),
    ]
    if opts.backend == BACKEND_NEW and opts.mode != "udp":
        blocks.append(quote(bold("свой wireguard работает только в режиме udp")))
    blocks.extend(banner(view))
    buttons = [
        row(button("Свой wireguard", "setup:backend:new"), button("Внешний vpn", "setup:backend:external")),
        row(button("docker", "setup:method:docker"), button("systemd", "setup:method:systemd")),
        row(button("udp", "setup:mode:udp"), button("tcp", "setup:mode:tcp")),
        row(button("Порт входа", "setup:edit:setup_listen"), button("Порт wg", "setup:edit:setup_wgport")),
        row(button("Подсеть wg", "setup:edit:setup_wgnet"), button("Адрес vpn", "setup:edit:setup_connect")),
        row(button("Обфускация", "setup:obf:menu"), button("Адрес в ссылке", "setup:edit:setup_host")),
        row(button("Версия", "setup:edit:setup_version"), button("Сгенерировать ключ", "setup:genkey")),
        back_row(),
    ]
    return screen("Параметры установки", "те же поля, что в мобильном клиенте", blocks, buttons)


def obf_menu(view: View) -> Rich:
    current = view.state.opts.obf_profile
    rows = []
    for name in OBF_PROFILES:
        mark = "текущий" if name == current else "выбрать"
        if name == "none":
            rows.append(button("none, без маскировки", "setup:obf:none"))
        else:
            rows.append(button(f"{name}, {mark}", f"setup:obf:{name}"))
    blocks = [
        bullet_list(
            [
                bold("rtpopus3") + " " + muted("rtp/opus, расширения rfc 8285, имитация речи и потерь"),
                bold("rtpopus2") + " " + muted("rtp/opus с базовым заголовком расширений"),
                bold("rtpopus") + " " + muted("простой rtp/opus заголовок"),
                bold("none") + " " + muted("без маскировки, подходит только для тестов"),
            ]
        ),
        quote(muted("профиль и ключ должны совпадать на сервере и в ссылке клиента")),
    ]
    blocks.extend(banner(view))
    buttons = [rows[0], rows[1], rows[2], rows[3], back_row()]
    return screen("Обфускация", "ключ: " + mask(view.state.opts.obf_key), blocks, buttons)


def clients(view: View) -> Rich:
    blocks: list[str] = []
    if not view.clients:
        blocks.append(quote(muted("список пуст, обновите его или добавьте клиента")))
    else:
        rows = []
        for item in view.clients[:10]:
            label = item.name + (" (owner)" if item.is_self else "")
            rows.append((label, code(item.ip or "-") + " " + (muted("handshake") if item.handshake else muted("без handshake"))))
        blocks.append(table(rows))
    if view.share is not None and view.share.host:
        blocks.append(details("параметры выдачи", table([
            ("backend", code(view.share.backend or "-")),
            ("адрес", code(f"{view.share.host}:{view.share.port}")),
            ("режим", code(view.share.mode or "-")),
            ("обфускация", code(view.share.obf_profile or "-")),
        ])))
    blocks.extend(banner(view))
    buttons = [big("Добавить клиента", "cli:add", "success"), big("Обновить список", "cli:refresh", "primary")]
    links = [button(item.name, f"cli:open:{item.name}") for item in view.clients[:8]]
    while links:
        chunk, links = links[:3], links[3:]
        buttons.append(row(*chunk))
    buttons.append(back_row())
    return screen("Клиенты", "allowlist и выдача ссылок", blocks, buttons)


def client(view: View, name: str) -> Rich:
    item = next((entry for entry in view.clients if entry.name == name), ClientInfo(name=name))
    rows = [
        ("имя", code(item.name)),
        ("client id", code(item.client_id or "-")),
        ("признак", code("owner" if item.is_self else "client")),
        ("адрес пира", code(item.ip or "-")),
        ("публичный ключ", code(item.pub[:24] + "...") if item.pub else muted("нет")),
        ("handshake", code(item.handshake)),
    ]
    blocks = [table(rows)]
    blocks.extend(banner(view))
    buttons = [
        big("Ссылка freeturn", f"cli:link:{name}", "primary"),
        big("Конфигурация wireguard", f"cli:wg:{name}"),
        big("Снимок конфигурации ядра", f"cli:cfg:{name}"),
        row(button("Удалить", f"cli:del:{name}"), button("К клиентам", "nav:clients")),
    ]
    return screen(name, "клиент free turn", blocks, buttons)


def confirm_remove(view: View, name: str) -> Rich:
    blocks = [
        bold("удаление необратимо"),
        bullet_list(
            [
                "клиент исчезнет из allowlist на сервере",
                "его пир будет вырезан из wireguard",
                "выданная ему ссылка перестанет работать",
            ]
        ),
        table([("клиент", code(name))]),
    ]
    blocks.extend(banner(view))
    buttons = [
        row(button("Удалить клиента", f"cli:del2:{name}", "danger"), button("Отмена", f"cli:open:{name}")),
    ]
    return screen("Подтверждение", "удаляем " + name, blocks, buttons)


def confirm_uninstall(view: View) -> Rich:
    blocks = [
        bold("удаление установки"),
        bullet_list(
            [
                "останавливается сервис free turn proxy",
                "удаляется свой интерфейс wireguard и его пиры",
                "удаляются каталог установки и правила firewall",
            ]
        ),
        quote(muted("бот и его настройки остаются на месте")),
    ]
    blocks.extend(banner(view))
    buttons = [
        row(button("Удалить установку", "maint:uninstall2", "danger"), button("Отмена", "nav:maint")),
    ]
    return screen("Подтверждение", "удаляем сервер целиком", blocks, buttons)


def link_settings(view: View) -> Rich:
    state = view.state
    link = state.link
    rows = [
        ("потоки", code(link.threads)),
        ("потоков на креды", code(link.streams_per_cred)),
        ("транспорт turn", code(link.transport)),
        ("режим", code(link.mode)),
        ("bond", flag(link.bond)),
        ("задержка", code(f"{link.timing_ms} ms")),
        ("локальный адрес", code(link.local_listen)),
        ("dns режим", code(link.dns_mode)),
        ("dns серверы", code(link.dns_servers or "оператора")),
        ("ручная captcha", flag(link.manual_captcha)),
        ("ссылка на звонок", code(link.call_link[:40]) if link.call_link else muted("не задана")),
    ]
    blocks = [
        table(rows),
        quote(muted("эти значения попадают в ссылку freeturn и применяются клиентом на устройстве")),
    ]
    blocks.extend(banner(view))
    buttons = [
        row(button("Потоки", "lnk:edit:link_threads"), button("На креды", "lnk:edit:link_spc")),
        row(button("Транспорт", "lnk:cycle:transport"), button("Режим", "lnk:cycle:mode")),
        row(button("Bond", "lnk:toggle:bond"), button("Задержка", "lnk:edit:link_timing")),
        row(button("Локальный адрес", "lnk:edit:link_listen"), button("DNS режим", "lnk:cycle:dns")),
        row(button("DNS серверы", "lnk:edit:link_dnss"), button("Ручная captcha", "lnk:toggle:mcap")),
        big("Ссылка на звонок", "lnk:edit:link_call"),
        row(button("Клиенты", "nav:clients"), button("Главная", "nav:home")),
    ]
    return screen("Параметры подключения", "как в мобильном клиенте", blocks, buttons)


def link_screen(view: View, name: str, link: str, conf: str, client_info: ClientInfo) -> Rich:
    blocks = [
        pre(link),
        row(copy_button("Скопировать ссылку", link)),
        table(
            [
                ("клиент", code(name)),
                ("client id", code(client_info.client_id or "-")),
                ("адрес", code(client_info.ip or "-")),
                ("длина", code(len(link))),
            ]
        ),
        quote(muted("ссылка работает и на android, и на ios, других форматов больше нет")),
    ]
    if conf:
        summary = wg_summary(conf)
        blocks.append(details("wireguard внутри ссылки", table(summary.fields)))
    blocks.extend(banner(view))
    buttons = [
        row(button("Клиенты", "nav:clients"), button("Обновить", f"cli:link:{name}")),
        row(button("Параметры ссылки", "nav:link"), button("Главная", "nav:home")),
    ]
    return screen("Ссылка доступа", name, blocks, buttons)


def wg_screen(view: View, name: str, conf: str, client_info: ClientInfo) -> Rich:
    summary = wg_summary(conf)
    blocks = [
        pre(normalize_conf(conf)),
        details("разбор", table(summary.fields)),
        row(copy_button("Скопировать конфигурацию", normalize_conf(conf))),
    ]
    blocks.extend(banner(view))
    buttons = [
        row(button("Назад к клиенту", f"cli:open:{name}"), button("Главная", "nav:home")),
    ]
    return screen("WireGuard", name, blocks, buttons)


def config_screen(view: View, name: str) -> Rich:
    state = view.state
    client_id = state.owner_client_id if name == "owner" else ""
    if not client_id:
        item = next((entry for entry in view.clients if entry.name == name), None)
        client_id = item.client_id if item is not None else ""
    body = core_config(state.ssh, state.opts, state.link, client_id, bool(state.owner_conf))
    import json

    blocks = [
        pre(json.dumps(body, ensure_ascii=False, indent=2), "json"),
        quote(muted("ровно то, что ядро получает на устройстве при запуске")),
    ]
    blocks.extend(banner(view))
    buttons = [row(button("Назад к клиенту", f"cli:open:{name}"), button("Главная", "nav:home"))]
    return screen("Конфигурация ядра", name, blocks, buttons)


def logs(view: View, lines: list[str], tail: int) -> Rich:
    body = "\n".join(lines) if lines else "журнал пуст"
    blocks = [
        pre(body[-3500:]),
        table([("строк", code(len(lines))), ("запрошено", code(tail))]),
    ]
    blocks.extend(banner(view))
    buttons = [
        row(button("50", "log:tail:50"), button("200", "log:tail:200"), button("500", "log:tail:500")),
        big("Обновить", "log:refresh", "primary"),
        row(button("Сервер", "nav:server"), button("Главная", "nav:home")),
    ]
    return screen("Журнал сервера", "journalctl или docker logs", blocks, buttons)


def maintenance(view: View) -> Rich:
    opts = view.state.opts
    blocks = [
        table(
            [
                ("версия ядра", code(opts.version)),
                ("метод", code(opts.method)),
                ("backend", code(opts.backend)),
                ("каталог на сервере", code("/opt/free-turn-proxy")),
            ]
        ),
        bullet_list(
            [
                bold("обновить ядро") + " " + muted("переустановка с текущими параметрами"),
                bold("перезапустить") + " " + muted("мягкий рестарт сервиса"),
                bold("удалить установку") + " " + muted("полный снос сервера, бот остается"),
            ]
        ),
    ]
    blocks.extend(banner(view))
    buttons = [
        big("Обновить ядро", "maint:update", "primary"),
        big("Перезапустить", "maint:restart"),
        big("Удалить установку", "maint:uninstall", "danger"),
        back_row(),
    ]
    return screen("Обслуживание", "то, что не входит в повседневную работу", blocks, buttons)


def help_screen(view: View) -> Rich:
    blocks = [
        heading("Как это работает", 3),
        numbered(
            [
                "бот входит на ваш сервер по ssh и запускает install.sh",
                "ядро free turn proxy слушает udp порт и ждет turn трафик",
                "клиент на устройстве поднимает локальный wireguard и завернут в rtp/opus",
                "сервер проверяет client id по allowlist и релеит пакеты в wireguard",
            ]
        ),
        heading("Что нужно один раз", 3),
        bullet_list(
            [
                "доступ по ssh, ключ или пароль, root или sudo",
                "параметры установки, порт, режим, обфускация",
                "ссылка на звонок, если провайдер turn требует ее для выдачи кредов",
            ]
        ),
        heading("Ссылка freeturn", 3),
        bullet_list(
            [
                "одна ссылка на android и ios, отдельных сборок больше нет",
                "внутри адрес, ключ обфускации, конфигурация wireguard и client id",
                "ссылку нельзя публиковать, она равносильна ключам доступа",
            ]
        ),
        details(
            "Команды install.sh, которые использует бот",
            table(
                [
                    ("probe", code("состояние узла")),
                    ("apply", code("установка и применение")),
                    ("stop, restart", code("управление сервисом")),
                    ("logs", code("журнал сервиса")),
                    ("client-list", code("список клиентов")),
                    ("client-add", code("новый клиент")),
                    ("client-conf", code("конфигурация клиента")),
                    ("client-remove", code("отзыв доступа")),
                    ("uninstall", code("снос установки")),
                ]
            ),
        ),
        details(
            "Порты по умолчанию",
            bullet_list(
                [
                    "вход ядра: udp " + code(view.state.opts.listen_port),
                    "wireguard: " + code(f"127.0.0.1:{view.state.opts.wg_port}"),
                    "подсеть wireguard: " + code(view.state.opts.wg_net),
                    "клиент слушает " + code(view.state.link.local_listen),
                ]
            ),
        ),
    ]
    blocks.extend(banner(view))
    buttons = [big("Импорт ссылки", "nav:import", "primary"), back_row()]
    return screen("Помощь", "как устроен транспорт и управление", blocks, buttons)


def import_screen(view: View, rows: list[tuple[str, str]] | None = None, raw: str = "", error: str = "") -> Rich:
    blocks = [quote(muted("отправьте ссылку freeturn одним сообщением, бот разберет ее без подключения"))]
    if rows:
        blocks.append(table(rows))
    if raw:
        blocks.append(pre(raw))
        blocks.append(row(copy_button("Скопировать ссылку", raw)))
    if error:
        blocks.append(quote(bold(error)))
    blocks.extend(banner(view))
    buttons = [row(button("Ссылки", "nav:link"), button("Главная", "nav:home"))]
    return screen("Импорт ссылки", "разбор без установки", blocks, buttons)


def prompt(spec: object, error: str = "") -> Rich:
    label = getattr(spec, "label", "Значение")
    text = getattr(spec, "prompt", "отправьте значение")
    hint = getattr(spec, "hint", "")
    blocks = [f"<p>{text}</p>"]
    if hint:
        blocks.append(quote(muted(hint)))
    if error:
        blocks.append(quote(bold(error)))
    blocks.append(quote(muted("сообщение с секретом бот не показывает в списке чатов, но оно остается на серверах telegram")))
    buttons = [row(button("Отмена", "nav:home"), button("Главная", "nav:home"))]
    return screen(label, "ожидается текст", blocks, buttons)


def busy_screen(title: str, step: str = "") -> Rich:
    blocks = [f"<p>{bold(title)}</p>"]
    if step:
        blocks.append(f"<p>{step}</p>")
    blocks.append(muted("дождитесь результата, кнопки вернутся в следующем сообщении"))
    return screen("Выполняется", "операция на сервере", blocks, [])


def error_screen(view: View, title: str, message: str) -> Rich:
    blocks = [quote(bold(message))]
    blocks.extend(banner(view))
    buttons = [row(button("Сервер", "nav:server"), button("Главная", "nav:home"))]
    return screen(title, "операция не выполнена", blocks, buttons)


def denied() -> Rich:
    blocks = [quote(bold("бот обслуживает только своего администратора"))]
    return screen("Доступ закрыт", "чужие команды игнорируются", blocks, [])


def void() -> Rich:
    return screen("Готово", "сообщение обновлено", [], [row(button("Главная", "nav:home"))])
