from __future__ import annotations

import re
from dataclasses import dataclass

from . import i18n

MARKER = "#ob"
PREFIX = "ob"
CANCEL = "cancel"
MAX_VALUE = 400


class InlineError(Exception):
    pass


@dataclass(frozen=True)
class Field:
    ident: str
    label_key: str
    hint_key: str
    example: str = ""
    secret: bool = False

    def label(self, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
        return i18n.t(self.label_key, lang)

    def hint(self, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
        return i18n.t(self.hint_key, lang)

    @property
    def prefill(self) -> str:
        return f"{PREFIX} {self.ident} - "


FIELDS: dict[str, Field] = {
    "ssh_new_port": Field("ssh_new_port", "FLD_SSH_NEW_PORT", "FLH_SSH_NEW_PORT", "2222"),
    "ssh_pubkey": Field("ssh_pubkey", "FLD_SSH_PUBKEY", "FLH_SSH_PUBKEY", "ssh-ed25519 AAAA"),
    "xr_remark": Field("xr_remark", "FLD_XR_REMARK", "FLH_XR_REMARK", "reality-443"),
    "xr_port": Field("xr_port", "FLD_XR_PORT", "FLH_XR_PORT", "443"),
    "xr_sni": Field("xr_sni", "FLD_XR_SNI", "FLH_XR_SNI", "www.cloudflare.com"),
    "xr_dest": Field("xr_dest", "FLD_XR_DEST", "FLH_XR_DEST", "www.cloudflare.com:443"),
    "xr_short_id": Field("xr_short_id", "FLD_XR_SHORT_ID", "FLH_XR_SHORT_ID", "a1b2c3d4"),
    "xr_spider_x": Field("xr_spider_x", "FLD_XR_SPIDER_X", "FLH_XR_SPIDER_X", "/"),
    "xr_fingerprint": Field("xr_fingerprint", "FLD_XR_FINGERPRINT", "FLH_XR_FINGERPRINT", "chrome"),
    "xr_alpn": Field("xr_alpn", "FLD_XR_ALPN", "FLH_XR_ALPN", "h2,http/1.1"),
    "xr_cert_file": Field("xr_cert_file", "FLD_XR_CERT_FILE", "FLH_XR_CERT_FILE", "/etc/ssl/fullchain.pem"),
    "xr_key_file": Field("xr_key_file", "FLD_XR_KEY_FILE", "FLH_XR_KEY_FILE", "/etc/ssl/key.pem"),
    "xr_path": Field("xr_path", "FLD_XR_PATH", "FLH_XR_PATH", "/obhod"),
    "xr_host_header": Field("xr_host_header", "FLD_XR_HOST_HEADER", "FLH_XR_HOST_HEADER", "example.com"),
    "xr_service": Field("xr_service", "FLD_XR_SERVICE", "FLH_XR_SERVICE", "grpc-obhod"),
    "xr_padding": Field("xr_padding", "FLD_XR_PADDING", "FLH_XR_PADDING", "60-40-0"),
    "xr_mldsa65_seed": Field("xr_mldsa65_seed", "FLD_XR_MLDSA_SEED", "FLH_XR_MLDSA_SEED", "", True),
    "xr_mldsa65_verify": Field("xr_mldsa65_verify", "FLD_XR_MLDSA_VERIFY", "FLH_XR_MLDSA_VERIFY", ""),
    "xr_client_email": Field("xr_client_email", "FLD_XR_CLIENT_EMAIL", "FLH_XR_CLIENT_EMAIL", "phone-1"),
    "xr_client_flow": Field("xr_client_flow", "FLD_XR_CLIENT_FLOW", "FLH_XR_CLIENT_FLOW", ""),
    "xr_client_limit": Field("xr_client_limit", "FLD_XR_CLIENT_LIMIT", "FLH_XR_CLIENT_LIMIT", "2"),
    "xr_client_expiry": Field("xr_client_expiry", "FLD_XR_CLIENT_EXPIRY", "FLH_XR_CLIENT_EXPIRY", "30"),
    "xr_client_quota": Field("xr_client_quota", "FLD_XR_CLIENT_QUOTA", "FLH_XR_CLIENT_QUOTA", "100"),
    "xr_client_comment": Field("xr_client_comment", "FLD_XR_CLIENT_COMMENT", "FLH_XR_CLIENT_COMMENT", "family"),
    "xr_scan_targets": Field("xr_scan_targets", "FLD_XR_SCAN_TARGETS", "FLH_XR_SCAN_TARGETS", ""),
    "xr_scan_manual": Field("xr_scan_manual", "FLD_XR_SCAN_MANUAL", "FLH_XR_SCAN_MANUAL", "1.1.1.1:443"),
    "xr_scan_sni": Field("xr_scan_sni", "FLD_XR_SCAN_SNI", "FLH_XR_SCAN_SNI", "www.google.com"),
    "xr_scan_xver": Field("xr_scan_xver", "FLD_XR_SCAN_XVER", "FLH_XR_SCAN_XVER", "0"),
    "xr_log_level": Field("xr_log_level", "FLD_XR_LOG_LEVEL", "FLH_XR_LOG_LEVEL", "warning"),
    "xr_sub_port": Field("xr_sub_port", "FLD_XR_SUB_PORT", "FLH_XR_SUB_PORT", "2096"),
    "xr_sub_address": Field("xr_sub_address", "FLD_XR_SUB_ADDRESS", "FLH_XR_SUB_ADDRESS", "203.0.113.10"),
    "xr_sub_domain": Field("xr_sub_domain", "FLD_XR_SUB_DOMAIN", "FLH_XR_SUB_DOMAIN", "sub.example.com"),
    "xr_sub_cert": Field("xr_sub_cert", "FLD_XR_SUB_CERT", "FLH_XR_SUB_CERT", "/etc/ssl/fullchain.pem"),
    "xr_sub_key": Field("xr_sub_key", "FLD_XR_SUB_KEY", "FLH_XR_SUB_KEY", "/etc/ssl/key.pem"),
    "xr_sub_refresh": Field("xr_sub_refresh", "FLD_XR_SUB_REFRESH", "FLH_XR_SUB_REFRESH", "12"),
    "xr_sub_title": Field("xr_sub_title", "FLD_XR_SUB_TITLE", "FLH_XR_SUB_TITLE", "OBHOD"),
    "xr_ban_ip": Field("xr_ban_ip", "FLD_XR_BAN_IP", "FLH_XR_BAN_IP", "203.0.113.10"),
    "xr_bantime": Field("xr_bantime", "FLD_XR_BANTIME", "FLH_XR_BANTIME", "30"),
    "xr_ssh_bantime": Field("xr_ssh_bantime", "FLD_XR_SSH_BANTIME", "FLH_XR_SSH_BANTIME", "3d"),
    "xr_ssh_maxretry": Field("xr_ssh_maxretry", "FLD_XR_SSH_MAXRETRY", "FLH_XR_SSH_MAXRETRY", "3"),
    "xr_ignoreip": Field("xr_ignoreip", "FLD_XR_IGNOREIP", "FLH_XR_IGNOREIP", "127.0.0.1/8, ::1"),
    "xr_scan_candidates": Field("xr_scan_candidates", "FLD_XR_SCAN_CANDIDATES", "FLH_XR_SCAN_CANDIDATES", "www.google.com:443"),
    "xr_dns_servers": Field("xr_dns_servers", "FLD_XR_DNS_SERVERS", "FLH_XR_DNS_SERVERS", "1.1.1.1, 8.8.8.8"),
    "xr_api_port": Field("xr_api_port", "FLD_XR_API_PORT", "FLH_XR_API_PORT", "62789"),
    "xr_access_log": Field("xr_access_log", "FLD_XR_ACCESS_LOG", "FLH_XR_ACCESS_LOG", "/var/log/xray/access.log"),
}


def field(ident: str) -> Field:
    item = FIELDS.get(ident)
    if item is None:
        raise InlineError(f"unknown input field: {ident}")
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


CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_value(ident: str, value: str, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    item = field(ident)
    raw = CONTROL.sub("", str(value or ""))
    text = " ".join(raw.split())
    if ident == "ssh_pubkey":
        text = raw.strip()
    if ident in {"xr_scan_targets", "xr_scan_manual", "xr_scan_candidates", "xr_dns_servers"}:
        text = ", ".join(part.strip() for part in raw.replace(";", ",").split(",") if part.strip())
    if len(text) > MAX_VALUE:
        raise InlineError(i18n.t("INL_TOO_LONG", lang, label=item.label(lang), limit=MAX_VALUE))
    return text


def article(rid: str, title: str, description: str, text: str, src: str) -> dict:
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


def results_for(query: str, src: str = "bot", current: dict[str, str] | None = None, lang: str = i18n.DEFAULT_LANGUAGE) -> list[dict]:
    parsed = parse_query(query)
    if parsed is None:
        return []
    ident, ctx, value = parsed
    out: list[dict] = []
    if not ident:
        for item in FIELDS.values():
            shown = (current or {}).get(item.ident, "")
            description = item.hint(lang) if not shown else i18n.t("INL_CURRENT", lang, value=shown)
            out.append(
                article(
                    f"pick-{item.ident}",
                    item.label(lang),
                    description,
                    marker(item.ident, "-", shown) if shown else f"{PREFIX} {item.ident} - ",
                    src,
                )
            )
        return out
    item = field(ident)
    if not value:
        hint = item.hint(lang)
        if item.example:
            hint = i18n.t("INL_HINT_EXAMPLE", lang, hint=hint, example=item.example)
        out.append(article(f"hint-{item.ident}", i18n.t("INL_TYPE_VALUE", lang, label=item.label(lang)), hint, marker(ident, ctx, (current or {}).get(ident, "")), src))
        out.append(article(f"cancel-{item.ident}", i18n.t("INL_CANCEL"), i18n.t("INL_CANCEL_HINT"), cancel_marker(), src))
        return out
    clean = clean_value(ident, value, lang)
    shown = i18n.t("INL_HIDDEN", lang) if item.secret and clean else clean
    out.append(article(f"set-{item.ident}", i18n.t("INL_SAVE", lang, label=item.label(lang)), shown or i18n.t("INL_EMPTY_VALUE", lang), marker(ident, ctx, clean), src))
    if item.secret:
        out.append(article(f"wipe-{item.ident}", i18n.t("INL_WIPE"), i18n.t("INL_WIPE_HINT"), marker(ident, ctx, ""), src))
    out.append(article(f"cancel-{item.ident}", i18n.t("INL_CANCEL"), i18n.t("INL_CANCEL_RESET"), cancel_marker(), src))
    return out
