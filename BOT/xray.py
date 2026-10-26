from __future__ import annotations

import base64
import json
import re
import secrets
import uuid as uuidlib
from dataclasses import dataclass, field
from typing import Any

PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks")
NETWORKS = ("tcp", "ws", "grpc", "httpupgrade", "xhttp")
SECURITIES = ("reality", "tls", "none")
FLOWS = ("", "xtls-rprx-vision")
SS_METHODS = (
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-256-gcm",
    "aes-128-gcm",
    "chacha20-poly1305",
)
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized")
DEFAULT_DEST = "www.cloudflare.com:443"
DEFAULT_SNI = "www.cloudflare.com"
DEFAULT_TAG_PREFIX = "in"
EMAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHORT_ID_RE = re.compile(r"^[0-9a-f]{0,16}$")

P = 2 ** 255 - 19
A24 = 121665
BASE_POINT = bytes([9] + [0] * 31)


class XrayError(Exception):
    pass


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))


def _clamp(scalar: bytes) -> int:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(bytes(k), "little")


def x25519(scalar: bytes, point: bytes) -> bytes:
    if len(scalar) != 32 or len(point) != 32:
        raise XrayError("x25519 needs 32 byte keys")
    k = _clamp(scalar)
    u = int.from_bytes(point, "little") & ((1 << 255) - 1)
    x1 = u
    x2, z2, x3, z3 = 1, 0, u, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = pow((da + cb) % P, 2, P)
        z3 = (x1 * pow((da - cb) % P, 2, P)) % P
        x2 = (aa * bb) % P
        z2 = (e * ((aa + A24 * e) % P)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def x25519_keypair() -> tuple[str, str]:
    private = bytearray(secrets.token_bytes(32))
    private[0] &= 248
    private[31] &= 127
    private[31] |= 64
    raw = bytes(private)
    public = x25519(raw, BASE_POINT)
    return _b64url(raw), _b64url(public)


def parse_x25519_output(text: str) -> tuple[str, str]:
    private = ""
    public = ""
    for line in (text or "").splitlines():
        low = line.lower()
        value = line.split(":", 1)[1].strip() if ":" in line else ""
        if not value:
            continue
        if "private" in low and not private:
            private = value
        elif "public" in low and not public:
            public = value
    if not private or not public:
        raise XrayError("xray x25519 не вернул пару ключей")
    try:
        if len(_unb64url(private)) != 32 or len(_unb64url(public)) != 32:
            raise XrayError("ключи x25519 неверной длины")
    except (ValueError, IndexError):
        raise XrayError("ключи x25519 не разобраны") from None
    return private, public


def gen_uuid() -> str:
    return str(uuidlib.uuid4())


def gen_short_id(length: int = 8) -> str:
    length = max(2, min(16, int(length)))
    return secrets.token_hex((length + 1) // 2)[:length]


def gen_email(prefix: str = "user") -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]", "", prefix or "user") or "user"
    return f"{clean}-{secrets.token_hex(3)}"


def gen_ss_password(method: str) -> str:
    size = 32 if "256" in method else 16
    raw = secrets.token_bytes(size)
    if method.startswith("2022"):
        return base64.b64encode(raw).decode("ascii")
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def valid_email(value: object) -> str:
    text = str(value or "").strip()
    if not EMAIL_RE.match(text):
        raise XrayError("имя клиента: буквы, цифры, точка, дефис, подчёркивание, до 64")
    return text


def valid_short_id(value: object) -> str:
    text = str(value or "").strip().lower()
    if not SHORT_ID_RE.match(text):
        raise XrayError("short id: до 16 hex символов")
    return text


def split_authority(value: str) -> tuple[str, int]:
    text = (value or "").strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest.lstrip(":")
    elif text.count(":") == 1:
        host, port = text.split(":", 1)
    else:
        host, port = text, ""
    try:
        number = int(port or 0)
    except ValueError:
        raise XrayError("порт должен быть числом") from None
    if not 1 <= number <= 65535:
        raise XrayError("порт должен быть 1..65535")
    return host.strip(), number


def join_authority(host: str, port: int) -> str:
    host = (host or "").strip().strip("[]")
    return f"[{host}]:{int(port)}" if ":" in host else f"{host}:{int(port)}"


@dataclass
class XrayClient:
    email: str = ""
    ident: str = ""
    flow: str = ""
    password: str = ""
    total_gb: int = 0
    expiry_ms: int = 0
    limit_ip: int = 0
    enable: bool = True
    comment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "ident": self.ident,
            "flow": self.flow,
            "password": self.password,
            "total_gb": int(self.total_gb),
            "expiry_ms": int(self.expiry_ms),
            "limit_ip": int(self.limit_ip),
            "enable": bool(self.enable),
            "comment": self.comment,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "XrayClient":
        data = raw or {}
        return XrayClient(
            email=str(data.get("email", "")),
            ident=str(data.get("ident", "")),
            flow=str(data.get("flow", "")),
            password=str(data.get("password", "")),
            total_gb=int(data.get("total_gb", 0) or 0),
            expiry_ms=int(data.get("expiry_ms", 0) or 0),
            limit_ip=int(data.get("limit_ip", 0) or 0),
            enable=bool(data.get("enable", True)),
            comment=str(data.get("comment", "")),
        )

    def entry(self, protocol: str) -> dict[str, Any]:
        if protocol == "vless":
            body: dict[str, Any] = {"id": self.ident, "email": self.email}
            if self.flow:
                body["flow"] = self.flow
        elif protocol == "vmess":
            body = {"id": self.ident, "email": self.email, "security": "auto"}
        elif protocol == "trojan":
            body = {"password": self.password, "email": self.email}
        elif protocol == "shadowsocks":
            body = {"password": self.password, "email": self.email}
        else:
            raise XrayError(f"неизвестный протокол: {protocol}")
        if self.limit_ip:
            body["limitIp"] = int(self.limit_ip)
        if self.total_gb:
            body["totalGB"] = int(self.total_gb) * 1024 ** 3
        if self.expiry_ms:
            body["expiryTime"] = int(self.expiry_ms)
        body["enable"] = bool(self.enable)
        if self.comment:
            body["comment"] = self.comment
        return body


@dataclass
class XrayInbound:
    id: int = 0
    remark: str = ""
    protocol: str = "vless"
    port: int = 443
    listen: str = ""
    network: str = "tcp"
    security: str = "reality"
    tag: str = ""
    enable: bool = True
    clients: list[XrayClient] = field(default_factory=list)
    dest: str = DEFAULT_DEST
    sni: str = DEFAULT_SNI
    private_key: str = ""
    public_key: str = ""
    short_ids: list[str] = field(default_factory=list)
    spider_x: str = ""
    fingerprint: str = "chrome"
    alpn: list[str] = field(default_factory=list)
    path: str = "/"
    host_header: str = ""
    service_name: str = ""
    ss_method: str = "2022-blake3-aes-128-gcm"
    ss_password: str = ""

    def client(self, email: str) -> XrayClient | None:
        for item in self.clients:
            if item.email == email:
                return item
        return None

    def make_client(self, email: str) -> XrayClient:
        name = valid_email(email)
        if self.client(name) is not None:
            raise XrayError("клиент с таким именем уже есть")
        client = XrayClient(email=name)
        if self.protocol in {"vless", "vmess"}:
            client.ident = gen_uuid()
        if self.protocol == "vless" and self.security in {"reality", "tls"} and self.network == "tcp":
            client.flow = "xtls-rprx-vision"
        if self.protocol in {"trojan", "shadowsocks"}:
            client.password = gen_ss_password(self.ss_method) if self.protocol == "shadowsocks" else secrets.token_urlsafe(16)
        self.clients.append(client)
        return client

    def remove_client(self, email: str) -> bool:
        before = len(self.clients)
        self.clients = [item for item in self.clients if item.email != email]
        return len(self.clients) != before

    def settings(self) -> dict[str, Any]:
        entries = [client.entry(self.protocol) for client in self.clients]
        if self.protocol == "vless":
            return {"clients": entries, "decryption": "none", "fallbacks": []}
        if self.protocol == "vmess":
            return {"clients": entries}
        if self.protocol == "trojan":
            return {"clients": entries, "fallbacks": []}
        if self.protocol == "shadowsocks":
            return {
                "method": self.ss_method,
                "password": self.ss_password,
                "network": "tcp,udp",
                "clients": [{"password": item.password, "email": item.email, "enable": item.enable} for item in self.clients],
            }
        raise XrayError(f"неизвестный протокол: {self.protocol}")

    def stream(self) -> dict[str, Any]:
        stream: dict[str, Any] = {"network": self.network, "security": self.security}
        if self.network == "tcp":
            stream["tcpSettings"] = {"acceptProxyProtocol": False, "header": {"type": "none"}}
        if self.network == "ws":
            stream["wsSettings"] = {"path": self.path or "/", "host": self.host_header, "headers": {"Host": self.host_header} if self.host_header else {}}
        if self.network == "grpc":
            stream["grpcSettings"] = {"serviceName": self.service_name or self.tag or self.remark, "multiMode": False}
        if self.network == "httpupgrade":
            stream["httpupgradeSettings"] = {"path": self.path or "/", "host": self.host_header}
        if self.network == "xhttp":
            stream["xhttpSettings"] = {"path": self.path or "/", "host": self.host_header, "mode": "auto"}
        if self.security == "reality":
            names = [item for item in {self.sni, self.host_header} if item]
            stream["realitySettings"] = {
                "show": False,
                "xver": 0,
                "dest": self.dest,
                "serverNames": names or [DEFAULT_SNI],
                "privateKey": self.private_key,
                "shortIds": self.short_ids or [""],
                "settings": {
                    "publicKey": self.public_key,
                    "fingerprint": self.fingerprint,
                    "serverName": "",
                    "spiderX": self.spider_x,
                },
            }
        elif self.security == "tls":
            stream["tlsSettings"] = {
                "serverName": self.sni,
                "alpn": self.alpn or ["h2", "http/1.1"],
                "settings": {"allowInsecure": False, "fingerprint": self.fingerprint},
            }
        return stream

    def to_json(self) -> dict[str, Any]:
        return {
            "tag": self.tag or f"{DEFAULT_TAG_PREFIX}-{self.port}",
            "listen": self.listen,
            "port": int(self.port),
            "protocol": self.protocol,
            "settings": self.settings(),
            "streamSettings": self.stream(),
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": int(self.id),
            "remark": self.remark,
            "protocol": self.protocol,
            "port": int(self.port),
            "listen": self.listen,
            "network": self.network,
            "security": self.security,
            "tag": self.tag,
            "enable": bool(self.enable),
            "clients": [item.to_dict() for item in self.clients],
            "dest": self.dest,
            "sni": self.sni,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "short_ids": list(self.short_ids),
            "spider_x": self.spider_x,
            "fingerprint": self.fingerprint,
            "alpn": list(self.alpn),
            "path": self.path,
            "host_header": self.host_header,
            "service_name": self.service_name,
            "ss_method": self.ss_method,
            "ss_password": self.ss_password,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "XrayInbound":
        data = raw or {}
        return XrayInbound(
            id=int(data.get("id", 0) or 0),
            remark=str(data.get("remark", "")),
            protocol=str(data.get("protocol", "vless")),
            port=int(data.get("port", 443) or 443),
            listen=str(data.get("listen", "")),
            network=str(data.get("network", "tcp")),
            security=str(data.get("security", "reality")),
            tag=str(data.get("tag", "")),
            enable=bool(data.get("enable", True)),
            clients=[XrayClient.from_dict(item) for item in data.get("clients") or [] if isinstance(item, dict)],
            dest=str(data.get("dest", DEFAULT_DEST)),
            sni=str(data.get("sni", DEFAULT_SNI)),
            private_key=str(data.get("private_key", "")),
            public_key=str(data.get("public_key", "")),
            short_ids=[str(item) for item in data.get("short_ids") or []],
            spider_x=str(data.get("spider_x", "")),
            fingerprint=str(data.get("fingerprint", "chrome")),
            alpn=[str(item) for item in data.get("alpn") or []],
            path=str(data.get("path", "/")),
            host_header=str(data.get("host_header", "")),
            service_name=str(data.get("service_name", "")),
            ss_method=str(data.get("ss_method", "2022-blake3-aes-128-gcm")),
            ss_password=str(data.get("ss_password", "")),
        )


REALITY_NETWORKS = ("tcp", "grpc", "xhttp")


def reality_allows(network: str) -> bool:
    return network in REALITY_NETWORKS


def new_inbound(
    protocol: str = "vless",
    port: int = 443,
    network: str = "tcp",
    security: str = "reality",
    remark: str = "",
) -> XrayInbound:
    if protocol not in PROTOCOLS:
        raise XrayError("протокол: vless, vmess, trojan, shadowsocks")
    if network not in NETWORKS:
        raise XrayError("сеть: " + ", ".join(NETWORKS))
    if security not in SECURITIES:
        raise XrayError("безопасность: " + ", ".join(SECURITIES))
    if protocol in {"vmess", "shadowsocks"} and security == "reality":
        raise XrayError("reality доступен только для vless и trojan")
    if security == "reality" and not reality_allows(network):
        raise XrayError("reality работает только с сетями tcp, grpc и xhttp")
    inbound = XrayInbound(
        protocol=protocol,
        port=int(port),
        network=network,
        security=security,
        remark=remark or f"{protocol}-{port}",
    )
    inbound.tag = f"in-{port}-{network}-{protocol}"
    if security == "reality":
        private, public = x25519_keypair()
        inbound.private_key = private
        inbound.public_key = public
        inbound.short_ids = [gen_short_id()]
        inbound.sni = DEFAULT_SNI
        inbound.dest = DEFAULT_DEST
    if security == "tls":
        inbound.alpn = ["h2", "http/1.1"]
    if protocol == "shadowsocks":
        inbound.ss_password = gen_ss_password(inbound.ss_method)
    return inbound


def config_json(inbounds: list[XrayInbound], log_level: str = "warning") -> dict[str, Any]:
    active = [item for item in inbounds if item.enable]
    return {
        "log": {"loglevel": log_level, "access": "none", "error": ""},
        "inbounds": [item.to_json() for item in active],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIPv4v6"}},
            {"protocol": "blackhole", "tag": "blocked", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "AsAscii",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
            ],
        },
    }


def config_text(inbounds: list[XrayInbound], log_level: str = "warning") -> str:
    return json.dumps(config_json(inbounds, log_level), ensure_ascii=False, indent=2, sort_keys=False)


def _remark_suffix(inbound: XrayInbound, email: str, network: str) -> str:
    base = inbound.remark or f"{inbound.protocol}-{inbound.port}"
    parts = [base, email]
    if inbound.security != "none":
        parts.append(inbound.security)
    if network:
        parts.append(network)
    return "-".join(item for item in parts if item)


def _reality_params(inbound: XrayInbound, params: dict[str, str]) -> None:
    params["security"] = "reality"
    params["sni"] = inbound.sni or DEFAULT_SNI
    params["pbk"] = inbound.public_key
    params["sid"] = (inbound.short_ids or [""])[0]
    params["fp"] = inbound.fingerprint or "chrome"
    params["spx"] = inbound.spider_x or ""
    params["pqv"] = ""


def _network_params(inbound: XrayInbound, params: dict[str, str]) -> None:
    params["type"] = inbound.network
    if inbound.network == "ws":
        params["path"] = inbound.path or "/"
        if inbound.host_header:
            params["host"] = inbound.host_header
    elif inbound.network in {"httpupgrade", "xhttp"}:
        params["path"] = inbound.path or "/"
        if inbound.host_header:
            params["host"] = inbound.host_header
    elif inbound.network == "grpc":
        params["serviceName"] = inbound.service_name or inbound.tag
        params["mode"] = "gun"
    elif inbound.network == "tcp":
        params["headerType"] = "none"


def _query(params: dict[str, str]) -> str:
    pairs = [f"{key}={value}" for key, value in params.items() if value != ""]
    return "&".join(pairs)


def vless_link(inbound: XrayInbound, client: XrayClient, address: str, port: int | None = None) -> str:
    params: dict[str, str] = {}
    _network_params(inbound, params)
    if inbound.security == "reality":
        _reality_params(inbound, params)
    elif inbound.security == "tls":
        params["security"] = "tls"
        params["sni"] = inbound.sni
        params["fp"] = inbound.fingerprint or "chrome"
        if inbound.alpn:
            params["alpn"] = ",".join(inbound.alpn)
    else:
        params["security"] = "none"
    params["encryption"] = "none"
    if client.flow and inbound.network == "tcp" and inbound.security in {"reality", "tls"}:
        params["flow"] = client.flow
    host = join_authority(address, port or inbound.port)
    remark = _remark_suffix(inbound, client.email, inbound.network)
    return f"vless://{client.ident}@{host}?{_query(params)}#{_remark_url(remark)}"


def trojan_link(inbound: XrayInbound, client: XrayClient, address: str, port: int | None = None) -> str:
    params: dict[str, str] = {}
    _network_params(inbound, params)
    if inbound.security == "reality":
        _reality_params(inbound, params)
    elif inbound.security == "tls":
        params["security"] = "tls"
        params["sni"] = inbound.sni
        params["fp"] = inbound.fingerprint or "chrome"
        if inbound.alpn:
            params["alpn"] = ",".join(inbound.alpn)
    else:
        params["security"] = "none"
    if client.flow and inbound.network == "tcp" and inbound.security == "reality":
        params["flow"] = client.flow
    host = join_authority(address, port or inbound.port)
    remark = _remark_suffix(inbound, client.email, inbound.network)
    password = _quote_userinfo(client.password)
    return f"trojan://{password}@{host}?{_query(params)}#{_remark_url(remark)}"


def vmess_link(inbound: XrayInbound, client: XrayClient, address: str, port: int | None = None) -> str:
    body: dict[str, Any] = {
        "v": "2",
        "ps": _remark_suffix(inbound, client.email, inbound.network),
        "add": address,
        "port": str(port or inbound.port),
        "id": client.ident,
        "aid": "0",
        "scy": "auto",
        "net": inbound.network,
        "type": "none",
        "host": inbound.host_header,
        "path": inbound.path if inbound.network in {"ws", "httpupgrade", "xhttp"} else "",
        "tls": "tls" if inbound.security == "tls" else "",
        "sni": inbound.sni if inbound.security == "tls" else "",
        "alpn": ",".join(inbound.alpn) if inbound.security == "tls" else "",
        "fp": inbound.fingerprint if inbound.security in {"tls", "reality"} else "",
    }
    if inbound.network == "grpc":
        body["path"] = inbound.service_name or inbound.tag
    raw = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode("utf-8")).decode("ascii")


def ss_link(inbound: XrayInbound, client: XrayClient, address: str, port: int | None = None) -> str:
    params: dict[str, str] = {}
    if inbound.network != "tcp":
        _network_params(inbound, params)
    if inbound.security == "tls":
        params["security"] = "tls"
        params["sni"] = inbound.sni
        params["fp"] = inbound.fingerprint or "chrome"
    method = inbound.ss_method
    if method.startswith("2022"):
        userinfo = ":".join(_quote_userinfo(item) for item in (method, inbound.ss_password, client.password))
    else:
        userinfo = base64.urlsafe_b64encode(f"{method}:{client.password}".encode()).decode().rstrip("=")
    host = join_authority(address, port or inbound.port)
    remark = _remark_suffix(inbound, client.email, inbound.network)
    query = f"?{_query(params)}" if _query(params) else ""
    return f"ss://{userinfo}@{host}{query}#{_remark_url(remark)}"


def link_for(inbound: XrayInbound, client: XrayClient, address: str, port: int | None = None) -> str:
    if inbound.protocol == "vless":
        return vless_link(inbound, client, address, port)
    if inbound.protocol == "trojan":
        return trojan_link(inbound, client, address, port)
    if inbound.protocol == "vmess":
        return vmess_link(inbound, client, address, port)
    if inbound.protocol == "shadowsocks":
        return ss_link(inbound, client, address, port)
    raise XrayError(f"нет ссылки для протокола {inbound.protocol}")


def links_for(inbound: XrayInbound, address: str, port: int | None = None) -> list[tuple[str, str]]:
    return [(item.email, link_for(inbound, item, address, port)) for item in inbound.clients]


def _quote_userinfo(value: str) -> str:
    from urllib.parse import quote

    return quote(value or "", safe="")


def _remark_url(value: str) -> str:
    from urllib.parse import quote

    return quote(value or "", safe="")


def parse_link(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if text.startswith("vmess://"):
        try:
            body = json.loads(base64.b64decode(text[len("vmess://"):] + "===").decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise XrayError("vmess ссылка не разобрана") from None
        if not isinstance(body, dict):
            raise XrayError("vmess ссылка не объект")
        return {"protocol": "vmess", **body}
    for scheme in ("vless", "trojan", "ss"):
        if text.startswith(scheme + "://"):
            from urllib.parse import parse_qs, unquote, urlparse

            parsed = urlparse(text)
            params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
            return {
                "protocol": scheme,
                "host": parsed.hostname or "",
                "port": parsed.port or 0,
                "user": unquote(parsed.username or ""),
                "remark": unquote(parsed.fragment or ""),
                "params": params,
            }
    raise XrayError("ссылка должна начинаться с vless://, vmess://, trojan:// или ss://")


def summary(inbound: XrayInbound) -> list[tuple[str, str]]:
    rows = [
        ("протокол", inbound.protocol),
        ("порт", str(inbound.port)),
        ("сеть", inbound.network),
        ("безопасность", inbound.security),
        ("клиентов", str(len(inbound.clients))),
    ]
    if inbound.security == "reality":
        rows.append(("dest", inbound.dest))
        rows.append(("sni", inbound.sni))
        rows.append(("short id", (inbound.short_ids or [""])[0]))
    if inbound.network in {"ws", "httpupgrade", "xhttp"}:
        rows.append(("path", inbound.path))
    if inbound.network == "grpc":
        rows.append(("service", inbound.service_name or inbound.tag))
    return rows


XRAY_VERSION = "v26.10.21"
SCAN_DEFAULTS = (
    "www.cloudflare.com:443",
    "www.microsoft.com:443",
    "www.amazon.com:443",
    "aws.amazon.com:443",
    "www.samsung.com:443",
    "www.nvidia.com:443",
    "www.amd.com:443",
    "www.intel.com:443",
    "www.sony.com:443",
    "dl.google.com:443",
)


@dataclass
class XrayState:
    inbounds: list[XrayInbound] = field(default_factory=list)
    version: str = XRAY_VERSION
    log_level: str = "warning"
    scan_targets: list[str] = field(default_factory=lambda: list(SCAN_DEFAULTS))
    scan_results: list[dict[str, Any]] = field(default_factory=list)
    last_core: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "inbounds": [item.to_dict() for item in self.inbounds],
            "version": self.version,
            "log_level": self.log_level,
            "scan_targets": list(self.scan_targets),
            "scan_results": list(self.scan_results),
            "last_core": dict(self.last_core),
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "XrayState":
        data = raw or {}
        return XrayState(
            inbounds=[XrayInbound.from_dict(item) for item in data.get("inbounds") or [] if isinstance(item, dict)],
            version=str(data.get("version", XRAY_VERSION) or XRAY_VERSION),
            log_level=str(data.get("log_level", "warning") or "warning"),
            scan_targets=[str(item) for item in data.get("scan_targets") or SCAN_DEFAULTS],
            scan_results=[item for item in data.get("scan_results") or [] if isinstance(item, dict)],
            last_core=dict(data.get("last_core") or {}),
        )

    def inbound(self, ident: object) -> XrayInbound | None:
        try:
            key = int(ident)
        except (TypeError, ValueError):
            return None
        for item in self.inbounds:
            if item.id == key:
                return item
        return None

    def by_remark(self, remark: str) -> XrayInbound | None:
        for item in self.inbounds:
            if item.remark == remark:
                return item
        return None

    def next_id(self) -> int:
        used = {item.id for item in self.inbounds}
        value = 1
        while value in used:
            value += 1
        return value

    def add(self, inbound: XrayInbound) -> XrayInbound:
        for item in self.inbounds:
            if item.port == inbound.port:
                raise XrayError(f"порт {inbound.port} уже занят инбаундом {item.remark}")
        inbound.id = self.next_id()
        self.inbounds.append(inbound)
        return inbound

    def remove(self, ident: object) -> bool:
        item = self.inbound(ident)
        if item is None:
            return False
        self.inbounds.remove(item)
        return True

    def ports(self) -> list[int]:
        return [item.port for item in self.inbounds]

    def enabled(self) -> list[XrayInbound]:
        return [item for item in self.inbounds if item.enable]

    def public_key_of(self, ident: object) -> str:
        item = self.inbound(ident)
        return item.public_key if item else ""

    def set_reality_keys(self, ident: object, private: str, public: str) -> None:
        item = self.inbound(ident)
        if item is None:
            raise XrayError("инбаунд не найден")
        item.private_key = private
        item.public_key = public

    def adopt_scan(self, ident: object, host: str, sni: str, port: int) -> XrayInbound:
        item = self.inbound(ident)
        if item is None:
            raise XrayError("инбаунд не найден")
        host = host.strip()
        sni = sni.strip()
        if not host:
            raise XrayError("адрес цели не задан")
        item.dest = f"{host}:{int(port or 443)}"
        if sni:
            item.sni = sni
        return item

    def to_config(self) -> str:
        return config_text(self.inbounds, self.log_level)
