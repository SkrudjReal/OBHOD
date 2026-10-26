from __future__ import annotations

import base64
import json

import pytest

from BOT.links import (
    LinkError,
    build_link,
    conf_address,
    conf_endpoint,
    core_config,
    kcp_profile,
    link_summary,
    normalize_conf,
    parse_link,
    wg_summary,
)
from BOT.models import LinkSettings, ServerOptions, SshSettings

WG = """[Interface]
PrivateKey = aGVsbG8=
Address = 10.13.13.2/24
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = d29ybGQ=
PresharedKey = cHNr
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.10:51820
PersistentKeepalive = 25
"""


def opts() -> ServerOptions:
    return ServerOptions(listen_port=56000, obf_profile="rtpopus3", obf_key="b" * 64, wg_port=51820, wg_net="10.13.13.0/24")


def client() -> LinkSettings:
    return LinkSettings(threads=12, streams_per_cred=12, transport="tcp", mode="udp", local_listen="127.0.0.1:9000", call_link="https://vk.ru/call/join/AbCdEf")


def test_kcp_profile_defaults() -> None:
    profile = kcp_profile(None)
    assert profile["nodelay"] == 1
    assert profile["interval"] == 20
    assert profile["resend"] == 2
    assert profile["nc"] == 1
    assert profile["sndwnd"] == 512
    assert profile["rcvwnd"] == 512
    assert profile["mtu"] == 1200
    assert profile["acknodelay"] is True


def test_kcp_profile_overrides_and_clamps() -> None:
    profile = kcp_profile({"interval": 999, "mtu": 4, "nodelay": 0, "resend": "x"})
    assert profile["interval"] <= 5000
    assert profile["mtu"] >= 576
    assert profile["nodelay"] == 0
    assert profile["resend"] == 2


def test_normalize_conf_strips_noise() -> None:
    raw = "\r\n" + WG.replace("\n", "\r\n") + "\n\n\n"
    out = normalize_conf(raw)
    assert "\r" not in out
    assert out.startswith("[Interface]")
    assert "MTU" not in out
    assert out.splitlines()[-1] == "PersistentKeepalive = 25"


def test_normalize_conf_drops_comments() -> None:
    out = normalize_conf("# hello\n[Interface]\nAddress = 10.0.0.1/32\n")
    assert "#" not in out
    assert "Address" in out


def test_conf_endpoint_and_address() -> None:
    assert conf_endpoint(WG) == "203.0.113.10:51820"
    assert conf_address(WG) == "10.13.13.2/24"


def test_wg_summary() -> None:
    summary = wg_summary(WG)
    assert summary.endpoint == "203.0.113.10:51820"
    assert summary.address == "10.13.13.2/24"
    assert summary.mtu == 1280
    assert summary.dns == "1.1.1.1"
    assert summary.peers == 1
    assert summary.has_psk is True
    keys = dict(summary.fields)
    assert "endpoint" in keys


def test_build_and_parse_roundtrip() -> None:
    link = build_link("203.0.113.10:56000", opts(), client(), "cid-1", "owner", wg_conf=WG)
    assert link.startswith("freeturn://")
    data = parse_link(link)
    assert data["v"] == 1
    assert data["provider"] == "vk"
    assert data["peer"] == "203.0.113.10:56000"
    assert data["obf"] == "rtpopus3"
    assert data["key"] == "b" * 64
    assert data["cid"] == "cid-1"
    assert data["name"] == "owner"
    assert data["n"] == 12
    assert data["spc"] == 12
    assert data["listen"] == "127.0.0.1:9000"
    assert data["vk"] == "https://vk.ru/call/join/AbCdEf"
    assert "Endpoint = 203.0.113.10:51820" in data["wg"]


def test_link_payload_is_base64url_json() -> None:
    link = build_link("203.0.113.10:56000", opts(), client(), "cid-1", "owner")
    body = link[len("freeturn://"):]
    assert "+" not in body and "/" not in body and "=" not in body
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    assert json.loads(raw)["peer"] == "203.0.113.10:56000"


def test_build_link_single_scheme_for_both_platforms() -> None:
    link = build_link("203.0.113.10:56000", opts(), client(), "cid-1", "owner")
    data = parse_link(link)
    assert "ios" not in json.dumps(data)
    assert "platform" not in data
    assert link.count("freeturn://") == 1


def test_bond_only_for_tcp_without_wg() -> None:
    settings = client()
    settings.mode = "tcp"
    settings.bond = True
    with_bond = parse_link(build_link("h:1", opts(), settings, "c", "n"))
    assert with_bond["bond"] is True
    with_wg = parse_link(build_link("h:1", opts(), settings, "c", "n", wg_conf=WG))
    assert "bond" not in with_wg


def test_none_profile_drops_key_and_timing() -> None:
    options = ServerOptions(obf_profile="none", obf_key="")
    data = parse_link(build_link("h:1", options, client(), "c", "n"))
    assert "key" not in data
    assert "timing" not in data


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "https://example.com",
        "freeturn://",
        "freeturn://notbase64!!",
        "freeturn://" + base64.urlsafe_b64encode(b"{}").decode().rstrip("="),
        "freeturn://" + base64.urlsafe_b64encode(json.dumps({"v": 2, "provider": "vk", "peer": "h:1"}).encode()).decode().rstrip("="),
        "freeturn://" + base64.urlsafe_b64encode(json.dumps({"v": 1, "peer": "h:1"}).encode()).decode().rstrip("="),
        "freeturn://" + base64.urlsafe_b64encode(json.dumps({"v": 1, "provider": "vk"}).encode()).decode().rstrip("="),
    ],
)
def test_parse_rejects(raw: str) -> None:
    with pytest.raises(LinkError):
        parse_link(raw)


def test_link_summary_rows() -> None:
    data = parse_link(build_link("h:1", opts(), client(), "cid", "nm", wg_conf=WG))
    rows = dict(link_summary(data))
    assert rows["peer"] == "h:1"
    assert rows["client id"] == "cid"
    assert rows["obfuscation"] == "rtpopus3"
    assert "wg config" in rows


def test_core_config_udp_shape() -> None:
    body = core_config(SshSettings(host="203.0.113.10"), opts(), client(), "cid", True)
    assert body["peer"] == "203.0.113.10:56000"
    assert body["clientId"] == "cid"
    assert body["tunnel"]["mode"] == "awg"
    assert body["obf"]["profile"] == "rtpopus3"
    assert body["proxy"]["mode"] == "udp"
    assert body["proxy"]["listen"] == "127.0.0.1:9000"
    assert body["dns"]["servers"] == []
    assert "kcp" not in body


def test_core_config_tcp_mode_without_wg() -> None:
    settings = client()
    settings.mode = "tcp"
    body = core_config(SshSettings(host="h"), opts(), settings, "cid", False)
    assert body["proxy"]["mode"] == "tcp"
    assert body["kcp"]["nodelay"] == 1
    assert body["proxy"]["bond"] is False
    assert body["tunnel"]["mode"] == "none"
