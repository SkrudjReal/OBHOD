from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

from .models import (
    DEFAULT_MTU,
    MODE_TCP,
    MODE_UDP,
    LinkSettings,
    ServerOptions,
    SshSettings,
)

SCHEME = "freeturn://"
LINK_VERSION = 1
DEFAULT_KCP = {
    "nodelay": 1,
    "interval": 20,
    "resend": 2,
    "nc": 1,
    "sndwnd": 512,
    "rcvwnd": 512,
    "mtu": 1200,
    "acknodelay": True,
}


class LinkError(Exception):
    pass


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64url(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise LinkError("link payload is not valid base64url") from None


def normalize_conf(conf: str) -> str:
    out: list[str] = []
    for raw in (conf or "").replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith(";"):
            continue
        if line.lower().startswith("mtu") and "=" in line:
            continue
        out.append(line)
    return "\n".join(out)


def conf_endpoint(conf: str) -> str:
    for line in normalize_conf(conf).split("\n"):
        if line.lower().startswith("endpoint"):
            return line.split("=", 1)[-1].strip()
    return ""


def conf_address(conf: str) -> str:
    for line in normalize_conf(conf).split("\n"):
        if line.lower().startswith("address"):
            return line.split("=", 1)[-1].strip()
    return ""


KCP_RANGE = {
    "nodelay": (0, 1),
    "interval": (10, 5000),
    "resend": (0, 32),
    "nc": (0, 1),
    "sndwnd": (32, 65535),
    "rcvwnd": (32, 65535),
    "mtu": (576, 1500),
}


def _clamp(raw: Any, low: int, high: int, fallback: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return fallback
    return max(low, min(high, value))


def kcp_profile(raw: dict[str, Any] | None) -> dict[str, Any]:
    data = dict(DEFAULT_KCP)
    for key, value in (raw or {}).items():
        if key not in data or value is None:
            continue
        if key == "acknodelay":
            data[key] = bool(value)
            continue
        low, high = KCP_RANGE[key]
        data[key] = _clamp(value, low, high, int(data[key]))
    return data


def kcp_args(raw: dict[str, Any] | None) -> list[str]:
    profile = kcp_profile(raw)
    return [
        f"--kcp-nodelay={profile['nodelay']}",
        f"--kcp-interval={profile['interval']}",
        f"--kcp-resend={profile['resend']}",
        f"--kcp-nc={profile['nc']}",
        f"--kcp-sndwnd={profile['sndwnd']}",
        f"--kcp-rcvwnd={profile['rcvwnd']}",
        f"--kcp-mtu={profile['mtu']}",
        f"--kcp-acknodelay={'true' if profile['acknodelay'] else 'false'}",
    ]


def kcp_is_default(raw: dict[str, Any] | None) -> bool:
    return kcp_profile(raw) == DEFAULT_KCP


@dataclass
class LinkPayload:
    provider: str = "vk"
    peer: str = ""
    transport: str = ""
    mode: str = ""
    bond: bool = False
    obf: str = ""
    key: str = ""
    timing: int = 0
    n: int = 0
    spc: int = 0
    cid: str = ""
    listen: str = ""
    dns: str = ""
    dnss: str = ""
    mcap: bool = False
    kcp: dict[str, Any] | None = None
    name: str = ""
    vk: str = ""
    wg: str = ""

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"v": LINK_VERSION, "provider": self.provider, "peer": self.peer}
        if self.transport:
            body["transport"] = self.transport
        if self.mode:
            body["mode"] = self.mode
        if self.bond:
            body["bond"] = True
        if self.obf and self.obf != "none":
            body["obf"] = self.obf
            body["key"] = self.key
            if self.timing:
                body["timing"] = self.timing
        if self.n:
            body["n"] = self.n
        if self.spc:
            body["spc"] = self.spc
        if self.cid:
            body["cid"] = self.cid
        if self.listen:
            body["listen"] = self.listen
        if self.dns:
            body["dns"] = self.dns
        if self.dnss:
            body["dnss"] = self.dnss
        if self.mcap:
            body["mcap"] = True
        if self.kcp:
            body["kcp"] = self.kcp
        if self.name:
            body["name"] = self.name
        if self.vk:
            body["vk"] = self.vk
        if self.wg:
            body["wg"] = self.wg
        return body

    def encode(self) -> str:
        raw = json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return SCHEME + _b64url(raw)


def build_link(
    peer: str,
    opts: ServerOptions,
    client_settings: LinkSettings,
    client_id: str,
    client_name: str,
    wg_conf: str = "",
) -> str:
    tcp_mode = client_settings.mode == MODE_TCP
    payload = LinkPayload(
        provider="vk",
        peer=peer,
        transport="" if client_settings.transport == "tcp" else client_settings.transport,
        mode=MODE_TCP if tcp_mode else "",
        bond=bool(tcp_mode and client_settings.bond and not wg_conf),
        obf=opts.obf_profile,
        key=opts.obf_key,
        timing=client_settings.timing_ms if opts.obf_profile != "none" else 0,
        n=client_settings.threads,
        spc=client_settings.streams_per_cred,
        cid=client_id,
        listen=client_settings.local_listen,
        dns=client_settings.dns_mode if client_settings.dns_mode != "auto" else "",
        dnss=client_settings.dns_servers,
        mcap=client_settings.manual_captcha,
        kcp=None if not tcp_mode or kcp_is_default(opts.kcp) else kcp_profile(opts.kcp),
        name=client_name,
        vk=(client_settings.call_link or "").strip(),
        wg=normalize_conf(wg_conf),
    )
    return payload.encode()


def parse_link(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if not text.lower().startswith(SCHEME):
        raise LinkError("link must start with freeturn://")
    payload = text[len(SCHEME):]
    if not payload:
        raise LinkError("link payload is empty")
    body = _unb64url(payload)
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise LinkError("link payload is not valid json") from None
    if not isinstance(data, dict):
        raise LinkError("link payload must be a json object")
    if int(data.get("v", -1)) != LINK_VERSION:
        raise LinkError("unsupported link version")
    if not str(data.get("provider", "")):
        raise LinkError("link has no provider")
    if not str(data.get("peer", "")):
        raise LinkError("link has no peer")
    return data


def link_summary(data: dict[str, Any]) -> list[tuple[str, str]]:
    rows = [
        ("peer", str(data.get("peer", ""))),
        ("provider", str(data.get("provider", ""))),
        ("transport", str(data.get("transport", "tcp"))),
        ("mode", str(data.get("mode", MODE_UDP))),
        ("obfuscation", str(data.get("obf", "none"))),
        ("streams", str(data.get("n", "-"))),
        ("streams per cred", str(data.get("spc", "-"))),
        ("client id", str(data.get("cid", "-"))),
        ("name", str(data.get("name", "-"))),
        ("listen", str(data.get("listen", "-"))),
        ("dns mode", str(data.get("dns", "auto"))),
        ("dns servers", str(data.get("dnss", "-"))),
        ("bond", "yes" if data.get("bond") else "no"),
        ("timing", str(data.get("timing", 0))),
        ("manual captcha", "yes" if data.get("mcap") else "no"),
        ("call link", str(data.get("vk", "-"))),
    ]
    if data.get("kcp"):
        rows.append(("kcp", json.dumps(data["kcp"], separators=(",", ":"))))
    if data.get("wg"):
        rows.append(("wg config", f"{len(str(data['wg']))} chars"))
    return rows


link_rows = link_summary


def core_config(
    ssh: SshSettings,
    opts: ServerOptions,
    client: LinkSettings,
    client_id: str,
    has_wg: bool,
) -> dict[str, Any]:
    tcp_mode = client.mode == MODE_TCP and not has_wg
    body: dict[str, Any] = {
        "peer": f"{ssh.host}:{opts.listen_port}",
        "clientId": client_id,
        "subUrl": "",
        "provider": "vk",
        "routes": False,
        "turn": {
            "n": client.threads,
            "transport": client.transport,
            "host": "",
            "port": "",
        },
        "proxy": {
            "mode": MODE_TCP if tcp_mode else MODE_UDP,
            "listen": client.local_listen,
        },
        "vk": {
            "links": [client.call_link] if client.call_link else [],
            "streamsPerCred": client.streams_per_cred,
            "manualCaptcha": client.manual_captcha,
            "autoCaptcha": True,
            "advancedCaptcha": False,
            "platform": "mobile",
        },
        "obf": {
            "profile": opts.obf_profile,
            "key": opts.obf_key if opts.obf_profile != "none" else "",
            "timingMs": client.timing_ms if opts.obf_profile != "none" else 0,
        },
        "dns": {
            "mode": client.dns_mode,
            "servers": [part for part in client.dns_servers.split(",") if part],
        },
        "log": {"debug": False},
        "tunnel": {
            "mode": "awg" if has_wg else "none",
            "config": "",
            "mtu": DEFAULT_MTU,
        },
    }
    if tcp_mode:
        body["proxy"]["bond"] = bool(client.bond)
        body["kcp"] = kcp_profile(opts.kcp)
    return body


@dataclass
class WgSummary:
    address: str = ""
    endpoint: str = ""
    mtu: int = DEFAULT_MTU
    dns: str = ""
    peers: int = 0
    has_psk: bool = False
    fields: list[tuple[str, str]] = field(default_factory=list)


def wg_summary(conf: str) -> WgSummary:
    summary = WgSummary()
    section = ""
    for line in normalize_conf(conf).split("\n"):
        if line.startswith("["):
            section = line.strip("[]").lower()
            if section == "peer":
                summary.peers += 1
            continue
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        low = key.lower()
        if section == "interface":
            if low == "address":
                summary.address = value
            elif low == "dns":
                summary.dns = value
            elif low == "mtu":
                summary.mtu = int(value) if value.isdigit() else DEFAULT_MTU
        elif section == "peer":
            if low == "endpoint":
                summary.endpoint = value
            elif low == "presharedkey":
                summary.has_psk = bool(value)
    summary.fields = [
        ("address", summary.address or "-"),
        ("endpoint", summary.endpoint or "-"),
        ("dns", summary.dns or "-"),
        ("mtu", str(summary.mtu)),
        ("peers", str(summary.peers)),
        ("preshared key", "yes" if summary.has_psk else "no"),
    ]
    return summary
