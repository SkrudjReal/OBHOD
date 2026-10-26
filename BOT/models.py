from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any


ROOT = "ROOT"
SUDO_NOPASS = "SUDO_NOPASS"
SUDO_PASS = "SUDO_PASS"

AUTH_PASSWORD = "PASSWORD"
AUTH_KEY = "SSH_KEY"

METHOD_DOCKER = "docker"
METHOD_SYSTEMD = "systemd"

BACKEND_NEW = "new"
BACKEND_EXTERNAL = "external"

MODE_UDP = "udp"
MODE_TCP = "tcp"

OBF_PROFILES = ("rtpopus3", "rtpopus2", "rtpopus", "none")
TRANSPORTS = ("tcp", "udp")
DNS_MODES = ("auto", "plain", "doh")

DEFAULT_LISTEN_PORT = 56000
DEFAULT_WG_PORT = 51820
DEFAULT_WG_NET = "10.13.13.0/24"
DEFAULT_LOCAL_LISTEN = "127.0.0.1:9000"
CORE_VERSION = "v4.1.0"
CORE_VERSION_LATEST = "latest"
VERSION_CHOICES = (CORE_VERSION, CORE_VERSION_LATEST)
DEFAULT_THREADS = 12
DEFAULT_STREAMS_PER_CRED = 12
DEFAULT_MTU = 1280


def normalize_version(raw: object) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if text in {"latest", "local"}:
        return text
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?", text):
        return text
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?", text):
        return "v" + text
    return ""


@dataclass
class SshSettings:
    host: str = ""
    port: int = 22
    user: str = "root"
    auth: str = AUTH_PASSWORD
    password: str = ""
    key: str = ""
    passphrase: str = ""
    sudo_password: str = ""
    fingerprint: str = ""
    mode: str = ROOT
    root_mode: str = ROOT

    def is_ready(self) -> bool:
        if not self.host:
            return False
        if self.auth == AUTH_KEY:
            return bool(self.key.strip())
        return bool(self.password)

    @property
    def configured(self) -> bool:
        if not self.host:
            return False
        if self.auth == AUTH_KEY:
            return bool(self.key.strip())
        return bool(self.password)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "SshSettings":
        data = raw or {}
        return SshSettings(
            host=str(data.get("host", "")),
            port=int(data.get("port", 22) or 22),
            user=str(data.get("user", "root") or "root"),
            auth=str(data.get("auth", AUTH_PASSWORD)),
            password=str(data.get("password", "")),
            key=str(data.get("key", "")),
            passphrase=str(data.get("passphrase", "")),
            sudo_password=str(data.get("sudo_password", "")),
            fingerprint=str(data.get("fingerprint", "")),
            mode=str(data.get("mode", ROOT) or ROOT),
            root_mode=str(data.get("root_mode", ROOT)),
        )


@dataclass
class ServerOptions:
    host: str = ""
    method: str = METHOD_DOCKER
    backend: str = BACKEND_NEW
    listen_port: int = DEFAULT_LISTEN_PORT
    wg_port: int = DEFAULT_WG_PORT
    wg_net: str = DEFAULT_WG_NET
    connect: str = ""
    mode: str = MODE_UDP
    obf_profile: str = "rtpopus3"
    obf_key: str = ""
    version: str = CORE_VERSION
    kcp: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def from_probe(self, remote: "RemoteConfig") -> None:
        if remote.method:
            self.method = remote.method
        if remote.backend:
            self.backend = remote.backend
        if remote.connect:
            self.connect = remote.connect
        if remote.listen_port:
            self.listen_port = remote.listen_port
        if remote.wg_port:
            self.wg_port = remote.wg_port
        if remote.wg_net:
            self.wg_net = remote.wg_net
        if remote.mode:
            self.mode = remote.mode
        if remote.obf_profile:
            self.obf_profile = remote.obf_profile
        if remote.obf_key:
            self.obf_key = remote.obf_key
        pinned = normalize_version(remote.version)
        if pinned:
            self.version = pinned

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "ServerOptions":
        data = raw or {}
        return ServerOptions(
            host=str(data.get("host", "")),
            method=str(data.get("method", METHOD_DOCKER)),
            backend=str(data.get("backend", BACKEND_NEW)),
            listen_port=int(data.get("listen_port", DEFAULT_LISTEN_PORT) or DEFAULT_LISTEN_PORT),
            wg_port=int(data.get("wg_port", DEFAULT_WG_PORT) or DEFAULT_WG_PORT),
            wg_net=str(data.get("wg_net", DEFAULT_WG_NET) or DEFAULT_WG_NET),
            connect=str(data.get("connect", "")),
            mode=str(data.get("mode", MODE_UDP)),
            obf_profile=str(data.get("obf_profile", "rtpopus3") or "rtpopus3"),
            obf_key=str(data.get("obf_key", "")),
            version=normalize_version(data.get("version")) or CORE_VERSION,
            kcp=dict(data.get("kcp") or {}),
        )


@dataclass
class LinkSettings:
    threads: int = DEFAULT_THREADS
    streams_per_cred: int = DEFAULT_STREAMS_PER_CRED
    transport: str = "tcp"
    mode: str = MODE_UDP
    bond: bool = False
    timing_ms: int = 0
    local_listen: str = DEFAULT_LOCAL_LISTEN
    dns_mode: str = "auto"
    dns_servers: str = ""
    manual_captcha: bool = False
    call_link: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "LinkSettings":
        data = raw or {}
        return LinkSettings(
            threads=int(data.get("threads", DEFAULT_THREADS) or DEFAULT_THREADS),
            streams_per_cred=int(data.get("streams_per_cred", DEFAULT_STREAMS_PER_CRED) or DEFAULT_STREAMS_PER_CRED),
            transport=str(data.get("transport", "tcp") or "tcp"),
            mode=str(data.get("mode", MODE_UDP) or MODE_UDP),
            bond=bool(data.get("bond", False)),
            timing_ms=int(data.get("timing_ms", 0) or 0),
            local_listen=str(data.get("local_listen", DEFAULT_LOCAL_LISTEN) or DEFAULT_LOCAL_LISTEN),
            dns_mode=str(data.get("dns_mode", "auto") or "auto"),
            dns_servers=str(data.get("dns_servers", "")),
            manual_captcha=bool(data.get("manual_captcha", False)),
            call_link=str(data.get("call_link", "")),
        )


@dataclass
class RemoteConfig:
    method: str = ""
    backend: str = ""
    connect: str = ""
    host: str = ""
    listen_port: int = 0
    wg_port: int = 0
    wg_net: str = ""
    mode: str = ""
    obf_profile: str = ""
    obf_key: str = ""
    version: str = ""

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "RemoteConfig | None":
        if not isinstance(raw, dict):
            return None
        return RemoteConfig(
            method=str(raw.get("method", "")),
            backend=str(raw.get("backend", "")),
            connect=str(raw.get("connect", "")),
            host=str(raw.get("host", "")),
            listen_port=int(raw.get("listen_port", 0) or 0),
            wg_port=int(raw.get("wg_port", 0) or 0),
            wg_net=str(raw.get("wg_net", "")),
            mode=str(raw.get("mode", "")),
            obf_profile=str(raw.get("obf_profile", "")),
            obf_key=str(raw.get("obf_key", "")),
            version=str(raw.get("version", "")),
        )


@dataclass
class ProbeResult:
    installed: bool = False
    running: bool = False
    euid: int = -1
    arch: str = ""
    method: str = ""
    version: str = ""
    config: RemoteConfig | None = None

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "ProbeResult":
        return ProbeResult(
            installed=bool(raw.get("installed", False)),
            running=bool(raw.get("running", False)),
            euid=int(raw.get("euid", -1) or -1),
            arch=str(raw.get("arch", "")),
            method=str(raw.get("method") or ""),
            version=str(raw.get("version") or ""),
            config=RemoteConfig.from_dict(raw.get("config")),
        )


@dataclass
class ClientInfo:
    name: str = ""
    client_id: str = ""
    is_self: bool = False
    ip: str = ""
    pub: str = ""
    handshake: int = 0

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "ClientInfo":
        return ClientInfo(
            name=str(raw.get("name", "")),
            client_id=str(raw.get("client_id", "")),
            is_self=bool(raw.get("self", False)),
            ip=str(raw.get("ip", "")),
            pub=str(raw.get("pub", "")),
            handshake=int(raw.get("hs", 0) or 0),
        )


@dataclass
class ApplyOutcome:
    owner_client_id: str = ""
    owner_conf: str = ""
    obf_key: str = ""
    link: str = ""
    needs_restart: bool = False
    owner_pub: str = ""


@dataclass
class ClientAccess:
    info: ClientInfo = field(default_factory=ClientInfo)
    conf: str = ""
    link: str = ""


@dataclass
class ShareInfo:
    backend: str = ""
    host: str = ""
    port: int = 0
    mode: str = ""
    obf_profile: str = ""
    obf_key: str = ""
