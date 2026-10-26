from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from BOT.control import ERROR_CODES, PROTO, apply_argv, parse_response
from BOT.links import DEFAULT_KCP, LinkPayload, build_link, kcp_args, kcp_profile
from BOT.models import (
    ClientInfo,
    LinkSettings,
    ProbeResult,
    ServerOptions,
    ShareInfo,
)
from tests.fakes import make_state

ANDROID = Path(os.environ.get("FREETURN_ANDROID_DIR", "/home/user/turn-proxy-android"))
SRC = ANDROID / "app" / "src" / "main" / "java" / "com" / "freeturn" / "app"
COMMAND_KT = SRC / "domain" / "server" / "ServerCommand.kt"
RESULT_KT = SRC / "domain" / "server" / "ServerControlResult.kt"
DATA_KT = SRC / "data" / "control" / "ControlData.kt"
LINK_KT = SRC / "data" / "share" / "FreeturnLink.kt"
CONTROL_KT = SRC / "domain" / "server" / "ServerControl.kt"

FROZEN_FLAGS = {
    "--method",
    "--backend",
    "--listen-port",
    "--connect",
    "--wg-port",
    "--wg-net",
    "--mode",
    "--obf-profile",
    "--obf-key",
    "--kcp-nodelay",
    "--kcp-interval",
    "--kcp-resend",
    "--kcp-nc",
    "--kcp-sndwnd",
    "--kcp-rcvwnd",
    "--kcp-mtu",
    "--kcp-acknodelay",
    "--update",
    "--bin",
}
FROZEN_COMMANDS = {
    "probe",
    "apply",
    "stop",
    "logs",
    "client-list",
    "client-add",
    "client-conf",
    "client-remove",
    "uninstall",
}
NON_APPLY_FLAGS = {"--tail", "--name", "--target"}
FROZEN_LINK_KEYS = [
    "v",
    "provider",
    "peer",
    "transport",
    "mode",
    "bond",
    "obf",
    "key",
    "timing",
    "n",
    "spc",
    "cid",
    "listen",
    "dns",
    "dnss",
    "mcap",
    "kcp",
    "name",
    "vk",
    "wg",
]
FROZEN_ERRORS = {
    "bad_arg",
    "needs_root",
    "not_installed",
    "unsupported_arch",
    "no_systemd",
    "docker_failed",
    "download_failed",
    "wg_unsupported",
    "wg_install_failed",
    "wg_conflict",
    "backend_locked",
    "port_busy",
    "subnet_conflict",
    "subnet_full",
    "host_unknown",
    "exists",
    "not_found",
    "owner_protected",
    "start_failed",
    "sudo_auth_failed",
    "sudo_requiretty",
    "proto_mismatch",
    "host_key_changed",
    "transport",
    "internal",
    "unknown",
}
FROZEN_JSON_KEYS = {
    "installed",
    "running",
    "euid",
    "arch",
    "method",
    "version",
    "config",
    "listen_port",
    "wg_port",
    "wg_net",
    "obf_profile",
    "obf_key",
    "mode",
    "backend",
    "connect",
    "host",
    "owner",
    "client_id",
    "conf_b64",
    "needs_restart",
    "pub",
    "name",
    "self",
    "ip",
    "hs",
    "clients",
    "share",
    "port",
    "lines",
    "client",
}


def android_text(path: Path) -> str:
    if not path.is_file():
        pytest.skip(f"android source not available at {path}")
    return path.read_text(encoding="utf-8")


def flags_in(text: str) -> set[str]:
    out = {"--" + name for name in re.findall(r'"--([a-z0-9-]+)=', text)}
    out |= {"--" + name for name in re.findall(r'add\(\s*"--([a-z0-9-]+)"\s*\)', text)}
    return out


def commands_in(text: str) -> set[str]:
    out = set(re.findall(r'listOf\("([a-z][a-z-]+)"', text))
    out |= set(re.findall(r'add\("([a-z][a-z-]+)"\)', text))
    return out


def our_flags() -> set[str]:
    out: set[str] = set()
    cases = [
        ServerOptions(obf_key="a" * 64),
        ServerOptions(obf_key="a" * 64, version="latest", method="systemd", host="vpn.example.org"),
        ServerOptions(obf_profile="none", obf_key="", mode="udp"),
        ServerOptions(backend="external", connect="127.0.0.1:51820", obf_key="a" * 64),
        ServerOptions(obf_key="a" * 64, mode="tcp", kcp=DEFAULT_KCP),
    ]
    for opts in cases:
        for token in apply_argv(opts):
            out.add(token.split("=", 1)[0])
    out.add("--update")
    return out


def test_rpc_commands_match_android() -> None:
    text = android_text(COMMAND_KT)
    found = commands_in(text)
    assert FROZEN_COMMANDS == found


def test_apply_flags_match_android() -> None:
    text = android_text(COMMAND_KT)
    theirs = flags_in(text)
    assert theirs
    assert FROZEN_FLAGS == theirs - NON_APPLY_FLAGS
    ours = our_flags()
    extras = {"--host", "--version"}
    assert ours == (FROZEN_FLAGS - {"--bin"}) | extras
    assert not (extras & theirs)


def test_kcp_flags_and_defaults_match_android() -> None:
    text = android_text(SRC / "data" / "config" / "KcpProfile.kt")
    profile = text[text.index("data class KcpProfile") :]
    defaults = {
        "nodelay": int(re.search(r"noDelay: Int = (\d+)", profile).group(1)),
        "interval": int(re.search(r"interval: Int = (\d+)", profile).group(1)),
        "resend": int(re.search(r"resend: Int = (\d+)", profile).group(1)),
        "nc": int(re.search(r"\bnc: Int = (\d+)", profile).group(1)),
        "sndwnd": int(re.search(r"sndWnd: Int = (\d+)", profile).group(1)),
        "rcvwnd": int(re.search(r"rcvWnd: Int = (\d+)", profile).group(1)),
        "mtu": int(re.search(r"mtu: Int = (\d+)", profile).group(1)),
        "acknodelay": re.search(r"ackNoDelay: Boolean = (true|false)", profile).group(1) == "true",
    }
    assert defaults == DEFAULT_KCP
    assert kcp_profile(None) == DEFAULT_KCP
    assert kcp_args(None) == [
        "--kcp-nodelay=1",
        "--kcp-interval=20",
        "--kcp-resend=2",
        "--kcp-nc=1",
        "--kcp-sndwnd=512",
        "--kcp-rcvwnd=512",
        "--kcp-mtu=1200",
        "--kcp-acknodelay=true",
    ]


def test_error_codes_match_android() -> None:
    text = android_text(RESULT_KT)
    body = text[text.index("enum class ServerErrorCode") : text.index("companion object")]
    theirs = {name.lower() for name in re.findall(r"\b([A-Z][A-Z_]+)\b", body)}
    assert theirs == FROZEN_ERRORS
    assert set(ERROR_CODES) == theirs


def test_json_field_names_match_android() -> None:
    text = android_text(DATA_KT)
    serial = set(re.findall(r'@SerialName\("([a-z0-9_]+)"\)', text))
    plain = set(re.findall(r"^\s*val ([a-z_][A-Za-z]*):", text, re.M))
    assert {"listen_port", "wg_port", "wg_net", "obf_profile", "obf_key"} <= serial
    assert {"client_id", "conf_b64", "needs_restart"} <= serial
    normalized = {re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), name) for name in plain}
    found = serial | normalized
    assert FROZEN_JSON_KEYS <= found


def test_probe_payload_parses_android_fields() -> None:
    payload = {
        "installed": True,
        "running": True,
        "euid": 0,
        "arch": "aarch64",
        "method": "systemd",
        "version": "4.1.0",
        "config": {
            "method": "systemd",
            "backend": "external",
            "connect": "10.0.0.1:51820",
            "host": "vpn.example.org",
            "listen_port": 56000,
            "wg_port": 51820,
            "wg_net": "10.13.13.0/24",
            "mode": "tcp",
            "obf_profile": "rtpopus3",
            "obf_key": "a" * 64,
            "version": "4.1.0",
        },
    }
    probe = ProbeResult.from_dict(payload)
    assert probe.installed and probe.running
    assert probe.arch == "aarch64"
    assert probe.config is not None
    assert probe.config.listen_port == 56000
    assert probe.config.obf_profile == "rtpopus3"
    assert probe.config.connect == "10.0.0.1:51820"


def test_client_list_payload_parses_android_fields() -> None:
    client = ClientInfo.from_dict(
        {"name": "owner", "client_id": "a" * 32, "self": True, "ip": "10.13.13.2", "pub": "cHVi", "hs": 1700000000}
    )
    assert client.is_self and client.handshake == 1700000000
    share = ShareInfo(
        backend="new", host="203.0.113.10", port=56000, mode="udp", obf_profile="rtpopus3", obf_key="b" * 64
    )
    assert share.port == 56000


def test_proto_version_matches_android() -> None:
    text = android_text(SRC / "data" / "control" / "ControlResponse.kt")
    assert re.search(r"PROTO_VERSION\s*=\s*3", text)
    assert PROTO == 3
    good = parse_response('{"proto":3,"result":"ok","data":{}}')
    assert good.ok


def test_link_key_order_matches_android() -> None:
    text = android_text(LINK_KT)
    order = re.findall(r'sb\.field\("([a-z]+)"', text)
    assert order == FROZEN_LINK_KEYS
    payload = LinkPayload(
        provider="vk",
        peer="203.0.113.10:56000",
        transport="udp",
        mode="tcp",
        bond=True,
        obf="rtpopus3",
        key="a" * 64,
        timing=20,
        n=12,
        spc=12,
        cid="c" * 32,
        listen="127.0.0.1:9000",
        dns="doh",
        dnss="1.1.1.1",
        mcap=True,
        kcp=dict(DEFAULT_KCP),
        name="owner",
        vk="https://vk.ru/call/join/AbCdEf",
        wg="PrivateKey = x",
    )
    assert list(payload.to_dict()) == FROZEN_LINK_KEYS


def test_share_link_scheme_and_version_match_android() -> None:
    text = android_text(LINK_KT)
    assert 'SCHEME = "freeturn://"' in text
    assert re.search(r"VERSION = 1\b", text)
    state = make_state()
    link = build_link("203.0.113.10:56000", state.opts, LinkSettings(), "c" * 32, "owner", "")
    assert link.startswith("freeturn://")
    assert "=" not in link.split("://", 1)[1]


def test_ssh_launch_shape_matches_android() -> None:
    text = android_text(CONTROL_KT)
    assert '"bash -s -- ' in text
    assert "sudo -n" in text
    assert "sudo -k -S -p ''" in text
    preflight = android_text(SRC / "domain" / "server" / "ServerControl.kt")
    assert "FT_SUDO_NOPASS" in preflight
    assert "FT_SUDO_PASS" in preflight


def test_script_asset_name_matches_android() -> None:
    text = android_text(CONTROL_KT)
    assert 'SCRIPT_ASSET = "install.sh"' in text
    from tests.fakes import ROOT

    assert (ROOT / "Storage" / "install.sh").is_file()


def test_vendored_script_declares_same_proto() -> None:
    from tests.fakes import ROOT

    body = (ROOT / "Storage" / "install.sh").read_text(encoding="utf-8")
    assert "PROTO_VERSION=3" in body
    for command in FROZEN_COMMANDS:
        assert command in body


def test_bot_only_flags_are_understood_by_the_vendored_script() -> None:
    from tests.fakes import ROOT

    body = (ROOT / "Storage" / "install.sh").read_text(encoding="utf-8")
    for flag in ("--host=*)", "--version=*)"):
        assert flag in body
