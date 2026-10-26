from __future__ import annotations

from dataclasses import dataclass

MARKER = "#ob"
PREFIX = "ob"
CANCEL = "cancel"
MAX_VALUE = 400


class InlineError(Exception):
    pass


@dataclass(frozen=True)
class Field:
    ident: str
    label: str
    hint: str
    example: str = ""
    secret: bool = False

    @property
    def prefill(self) -> str:
        return f"{PREFIX} {self.ident} - "


FIELDS: dict[str, Field] = {
    "ssh_host": Field("ssh_host", "адрес сервера", "ip или домен ssh", "203.0.113.10"),
    "ssh_port": Field("ssh_port", "порт ssh", "целое от 1 до 65535", "22"),
    "ssh_user": Field("ssh_user", "пользователь ssh", "имя учетной записи", "root"),
    "ssh_password": Field("ssh_password", "пароль ssh", "пароль входа по ssh", "", True),
    "ssh_key": Field("ssh_key", "приватный ключ", "вставьте ключ целиком", "", True),
    "ssh_sudo": Field("ssh_sudo", "пароль sudo", "пароль для sudo на сервере", "", True),
    "xr_remark": Field("xr_remark", "имя инбаунда", "короткое имя для списка", "reality-443"),
    "xr_port": Field("xr_port", "порт инбаунда", "целое от 1 до 65535", "443"),
    "xr_sni": Field("xr_sni", "server name", "домен для маскировки", "www.cloudflare.com"),
    "xr_dest": Field("xr_dest", "адрес назначения", "host:port цели маскировки", "www.cloudflare.com:443"),
    "xr_short_id": Field("xr_short_id", "short id", "hex до 16 символов", "a1b2c3d4"),
    "xr_private_key": Field("xr_private_key", "приватный ключ reality", "ключ x25519 от ядра", "", True),
    "xr_public_key": Field("xr_public_key", "публичный ключ reality", "ключ x25519 от ядра", ""),
    "xr_path": Field("xr_path", "путь", "путь для ws или xhttp", "/obhod"),
    "xr_host_header": Field("xr_host_header", "заголовок host", "домен для ws или grpc", "example.com"),
    "xr_service": Field("xr_service", "имя сервиса", "serviceName для grpc", "grpc-obhod"),
    "xr_scan_targets": Field("xr_scan_targets", "цели сканирования", "список host:port через запятую или cidr", ""),
    "xr_scan_manual": Field("xr_scan_manual", "своя цель", "host:port или подсеть cidr", "1.1.1.1:443"),
    "xr_client_email": Field("xr_client_email", "имя клиента", "латиница, цифры, точка, дефис", "phone-1"),
    "xr_log_level": Field("xr_log_level", "уровень логов", "debug, info, warning, error", "warning"),
}


def field(ident: str) -> Field:
    item = FIELDS.get(ident)
    if item is None:
        raise InlineError(f"неизвестное поле ввода: {ident}")
    return item


def prefill(ident: str, ctx: str = "-") -> str:
    field(ident)
    return f"{PREFIX} {ident} {ctx} "


def marker(ident: str, ctx: str, value: str) -> str:
    field(ident)
    clean = " ".join(str(value).split())
    return f"{MARKER} {ident} {ctx or '-'} {clean}".strip()


def cancel_marker() -> str:
    return f"{MARKER} {CANCEL} - -"


def parse_marker(text: str) -> tuple[str, str, str] | None:
    raw = (text or "").strip()
    if not raw.startswith(MARKER + " "):
        return None
    parts = raw.split(" ", 3)
    if len(parts) < 3:
        return None
    ident = parts[1]
    ctx = parts[2] if parts[2] != "-" else ""
    value = parts[3] if len(parts) > 3 else ""
    if ident == CANCEL:
        return CANCEL, ctx, ""
    if ident not in FIELDS:
        return None
    return ident, ctx, value


def parse_query(query: str) -> tuple[str, str, str] | None:
    raw = (query or "").strip()
    if not raw:
        return None
    parts = raw.split(None, 3)
    if parts[0] != PREFIX:
        return None
    if len(parts) == 1:
        return "", "", ""
    ident = parts[1]
    if ident not in FIELDS:
        return None
    ctx = ""
    value = ""
    if len(parts) > 2:
        third = parts[2]
        if third == "-":
            value = parts[3] if len(parts) > 3 else ""
        elif third.isdigit():
            ctx = third
            value = parts[3] if len(parts) > 3 else ""
        else:
            value = " ".join(parts[2:])
    return ident, ctx, value


def clean_value(ident: str, value: str) -> str:
    item = field(ident)
    text = " ".join(str(value or "").split())
    if ident == "ssh_key":
        text = str(value or "").strip()
    if ident in {"xr_scan_targets", "xr_scan_manual"}:
        text = ", ".join(part.strip() for part in str(value or "").replace(";", ",").split(",") if part.strip())
    if len(text) > MAX_VALUE:
        raise InlineError(f"{item.label}: не длиннее {MAX_VALUE} символов")
    return text


def _article(rid: str, title: str, description: str, text: str, src: str) -> dict:
    ident = rid if len(rid) <= 64 else rid[:64]
    if src == "mt":
        return {
            "_": "inputBotInlineResult",
            "id": ident,
            "type": "article",
            "title": title,
            "description": description,
            "send_message": {"_": "inputBotInlineMessageText", "no_webpage": True, "message": text},
        }
    return {
        "type": "article",
        "id": ident,
        "title": title,
        "description": description,
        "input_message_content": {"message_text": text, "disable_web_page_preview": True},
    }


def results_for(query: str, src: str = "bot", current: dict[str, str] | None = None) -> list[dict]:
    parsed = parse_query(query)
    if parsed is None:
        return []
    ident, ctx, value = parsed
    out: list[dict] = []
    if not ident:
        for item in FIELDS.values():
            shown = (current or {}).get(item.ident, "")
            description = item.hint if not shown else f"сейчас: {shown}"
            out.append(
                _article(
                    f"pick-{item.ident}",
                    item.label,
                    description,
                    marker(item.ident, "-", shown) if shown else f"{PREFIX} {item.ident} - ",
                    src,
                )
            )
        return out
    item = field(ident)
    if not value:
        out.append(
            _article(
                f"hint-{item.ident}",
                f"{item.label}: введите значение",
                item.hint + (f", пример {item.example}" if item.example else ""),
                marker(ident, ctx, (current or {}).get(ident, "")),
                src,
            )
        )
        out.append(_article(f"cancel-{item.ident}", "отмена ввода", "вернуться без изменений", cancel_marker(), src))
        return out
    clean = clean_value(ident, value)
    shown = "скрыто" if item.secret and clean else clean
    out.append(
        _article(
            f"set-{item.ident}",
            f"сохранить: {item.label}",
            shown or "пустое значение",
            marker(ident, ctx, clean),
            src,
        )
    )
    if item.ident in {"ssh_password", "ssh_key", "ssh_sudo", "xr_private_key"}:
        out.append(
            _article(
                f"wipe-{item.ident}",
                "очистить значение",
                "записать пустое значение",
                marker(ident, ctx, ""),
                src,
            )
        )
    out.append(_article(f"cancel-{item.ident}", "отмена ввода", "вернуть пустое значение", cancel_marker(), src))
    return out
