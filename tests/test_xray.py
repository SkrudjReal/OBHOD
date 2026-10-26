from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from BOT.xray import (
    DEFAULT_DEST,
    DEFAULT_SNI,
    NETWORKS,
    PROTOCOLS,
    SECURITIES,
    SS_METHODS,
    XrayClient,
    XrayError,
    XrayInbound,
    XrayState,
    config_json,
    config_text,
    gen_email,
    gen_short_id,
    gen_ss_password,
    gen_uuid,
    join_authority,
    link_for,
    links_for,
    new_inbound,
    parse_link,
    parse_x25519_output,
    split_authority,
    summary,
    trojan_link,
    valid_email,
    valid_short_id,
    vless_link,
    vmess_link,
    ss_link,
    x25519,
    x25519_keypair,
)


def pad(value: str) -> str:
    return value + "=" * (-len(value) % 4)


SCALAR = bytes.fromhex("77076d0a7318a57d3c16c17251b2a7d0" "5b1e4b7d0a1a2b3c4d5e6f708192a3b4")


def test_uuid_shape() -> None:
    value = gen_uuid()
    assert len(value) == 36
    assert value.count("-") == 4
    assert value != gen_uuid()


def test_short_id_is_hex() -> None:
    value = gen_short_id()
    assert len(value) == 8
    assert valid_short_id(value) == value


def test_short_id_rejects_odd_values() -> None:
    for bad in ("zz", "-1", "x" * 20):
        with pytest.raises(XrayError):
            valid_short_id(bad)


def test_email_validation() -> None:
    assert valid_email("phone-1") == "phone-1"
    assert valid_email(" a.b ") == "a.b"
    with pytest.raises(XrayError):
        valid_email("плохое имя")
    with pytest.raises(XrayError):
        valid_email("")


def test_gen_email_and_password() -> None:
    assert gen_email("test").startswith("test-")
    for method in SS_METHODS:
        secret = gen_ss_password(method)
        assert 16 <= len(secret) <= 64


def test_x25519_scalar_mult_vector() -> None:
    scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    point = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    expected = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    assert x25519(scalar, point) == expected


def test_x25519_base_point_vector() -> None:
    bob_private = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    bob_public = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert x25519(bob_private, bytes([9] + [0] * 31)) == bob_public


def test_x25519_shared_secret_is_symmetric() -> None:
    import base64

    private_a, public_a = x25519_keypair()
    private_b, public_b = x25519_keypair()
    raw_a = base64.urlsafe_b64decode(private_a + "=")
    raw_b = base64.urlsafe_b64decode(private_b + "=")
    raw_pub_a = base64.urlsafe_b64decode(public_a + "=")
    raw_pub_b = base64.urlsafe_b64decode(public_b + "=")
    assert x25519(raw_a, raw_pub_b) == x25519(raw_b, raw_pub_a)


def test_keypair_shape() -> None:
    private, public = x25519_keypair()
    assert len(private) == 43 and len(public) == 43
    assert private != public


def test_parse_x25519_output() -> None:
    private, public = x25519_keypair()
    text = f"Private key: {private}\nPublic key: {public}\n"
    assert parse_x25519_output(text) == (private, public)
    with pytest.raises(XrayError):
        parse_x25519_output("nothing here")


def test_split_and_join_authority() -> None:
    assert split_authority("example.com:443") == ("example.com", 443)
    with pytest.raises(XrayError):
        split_authority("example.com")
    assert split_authority("[2001:db8::1]:8443") == ("2001:db8::1", 8443)
    assert join_authority("example.com", 443) == "example.com:443"
    assert join_authority("2001:db8::1", 443) == "[2001:db8::1]:443"


def test_new_inbound_reality_defaults() -> None:
    inbound = new_inbound("vless", 443, "tcp", "reality")
    assert inbound.security == "reality"
    assert inbound.private_key and inbound.public_key
    assert inbound.short_ids
    assert inbound.sni == DEFAULT_SNI
    assert inbound.dest == DEFAULT_DEST
    assert inbound.tag == "in-443-tcp-vless"


def test_reality_rejects_unsupported_networks() -> None:
    for network in ("ws", "httpupgrade"):
        with pytest.raises(XrayError):
            new_inbound("vless", 443, network, "reality")
    for network in ("tcp", "grpc", "xhttp"):
        assert new_inbound("vless", 443, network, "reality").security == "reality"


def test_new_inbound_rejects_bad_pairs() -> None:
    with pytest.raises(XrayError):
        new_inbound("unknown", 443, "tcp", "none")
    with pytest.raises(XrayError):
        new_inbound("vless", 443, "smoke", "none")
    with pytest.raises(XrayError):
        new_inbound("vless", 443, "tcp", "quantum")
    with pytest.raises(XrayError):
        new_inbound("vmess", 443, "tcp", "reality")


@pytest.mark.parametrize("protocol", PROTOCOLS)
@pytest.mark.parametrize("network", NETWORKS)
def test_stream_matches_network(protocol: str, network: str) -> None:
    security = "reality" if protocol in {"vless", "trojan"} and network in {"tcp", "grpc", "xhttp"} else "none"
    if network == "ws" and protocol in {"vless", "trojan"}:
        security = "tls"
    inbound = new_inbound(protocol, 8443, network, security)
    stream = inbound.stream()
    assert stream["network"] == network
    assert stream["security"] == security
    if network == "ws":
        assert stream["wsSettings"]["path"] == "/"
    if network == "grpc":
        assert stream["grpcSettings"]["serviceName"]
    if network == "xhttp":
        assert stream["xhttpSettings"]["mode"] == "auto"


def test_settings_per_protocol() -> None:
    for protocol in PROTOCOLS:
        inbound = new_inbound(protocol, 8443, "tcp", "none" if protocol in {"vmess", "shadowsocks"} else "reality")
        client = inbound.make_client("owner")
        body = inbound.settings()
        if protocol == "vless":
            assert body["decryption"] == "none"
            assert body["clients"][0]["id"] == client.ident
        if protocol == "vmess":
            assert body["clients"][0]["security"] == "auto"
        if protocol == "trojan":
            assert body["clients"][0]["password"] == client.password
        if protocol == "shadowsocks":
            assert body["method"] == inbound.ss_method
            assert body["clients"][0]["password"] == client.password


def test_flow_only_for_vision_capable() -> None:
    reality = new_inbound("vless", 443, "tcp", "reality")
    assert reality.make_client("a").flow == "xtls-rprx-vision"
    ws = new_inbound("vless", 8443, "ws", "tls")
    assert ws.make_client("a").flow == ""
    plain = new_inbound("vless", 8444, "tcp", "none")
    assert plain.make_client("a").flow == ""


def test_duplicate_client_is_refused() -> None:
    inbound = new_inbound("vless", 443, "tcp", "reality")
    inbound.make_client("owner")
    with pytest.raises(XrayError):
        inbound.make_client("owner")
    assert inbound.remove_client("owner") is True
    assert inbound.remove_client("owner") is False


def test_client_limits_are_encoded() -> None:
    client = XrayClient(email="a", ident="b", total_gb=5, expiry_ms=1700000000000, limit_ip=2)
    entry = client.entry("vless")
    assert entry["totalGB"] == 5 * 1024 ** 3
    assert entry["expiryTime"] == 1700000000000
    assert entry["limitIp"] == 2
    assert entry["enable"] is True


def test_vless_link_has_reality_params() -> None:
    inbound = new_inbound("vless", 443, "tcp", "reality")
    client = inbound.make_client("owner")
    link = vless_link(inbound, client, "203.0.113.10")
    assert link.startswith("vless://" + client.ident + "@203.0.113.10:443")
    params = parse_qs(urlparse(link).query)
    assert params["security"] == ["reality"]
    assert params["type"] == ["tcp"]
    assert params["pbk"] == [inbound.public_key]
    assert params["sid"] == [inbound.short_ids[0]]
    assert params["sni"] == [DEFAULT_SNI]
    assert params["flow"] == ["xtls-rprx-vision"]
    assert params["fp"] == ["chrome"]


def test_vless_link_without_tls_has_security_none() -> None:
    inbound = new_inbound("vless", 8443, "tcp", "none")
    client = inbound.make_client("owner")
    params = parse_qs(urlparse(vless_link(inbound, client, "h")).query)
    assert params["security"] == ["none"]
    assert "pbk" not in params
    assert "flow" not in params


def test_ws_link_carries_path_and_host() -> None:
    inbound = new_inbound("vless", 8443, "ws", "tls")
    inbound.path = "/obhod"
    inbound.host_header = "cdn.example.com"
    client = inbound.make_client("owner")
    params = parse_qs(urlparse(vless_link(inbound, client, "h")).query)
    assert params["type"] == ["ws"]
    assert params["path"] == ["/obhod"]
    assert params["host"] == ["cdn.example.com"]
    assert params["security"] == ["tls"]
    assert params["sni"] == [inbound.sni]


def test_grpc_link_uses_service_name() -> None:
    inbound = new_inbound("vless", 8443, "grpc", "tls")
    inbound.service_name = "grpc-obhod"
    client = inbound.make_client("owner")
    params = parse_qs(urlparse(vless_link(inbound, client, "h")).query)
    assert params["serviceName"] == ["grpc-obhod"]


def test_trojan_link_quotes_password() -> None:
    inbound = new_inbound("trojan", 443, "tcp", "reality")
    client = inbound.make_client("owner")
    client.password = "pa ss/word"
    link = trojan_link(inbound, client, "host")
    assert link.startswith("trojan://pa%20ss%2Fword@host:443")
    assert parse_qs(urlparse(link).query)["security"] == ["reality"]


def test_vmess_link_is_json() -> None:
    inbound = new_inbound("vmess", 8443, "ws", "none")
    inbound.path = "/x"
    client = inbound.make_client("owner")
    link = vmess_link(inbound, client, "host")
    body = json.loads(base64.b64decode(pad(link[len("vmess://"):])).decode())
    assert body["id"] == client.ident
    assert body["net"] == "ws"
    assert body["path"] == "/x"
    assert body["port"] == "8443"


def test_ss_link_2022_uses_inbound_password() -> None:
    inbound = new_inbound("shadowsocks", 8443, "tcp", "none")
    client = inbound.make_client("owner")
    link = ss_link(inbound, client, "host")
    assert link.startswith("ss://")
    userinfo = unquote(link[len("ss://"):].split("#")[0].split("@")[0])
    assert userinfo == f"{inbound.ss_method}:{inbound.ss_password}:{client.password}"


def test_ss_link_classic_uses_client_password() -> None:
    inbound = new_inbound("shadowsocks", 8443, "tcp", "none")
    inbound.ss_method = "aes-256-gcm"
    client = inbound.make_client("owner")
    link = ss_link(inbound, client, "host")
    body = base64.urlsafe_b64decode(pad(link[len("ss://"):].split("#")[0].split("@")[0])).decode()
    assert body == f"aes-256-gcm:{client.password}"


def test_link_for_dispatches() -> None:
    for protocol, prefix in (("vless", "vless://"), ("trojan", "trojan://"), ("vmess", "vmess://"), ("shadowsocks", "ss://")):
        inbound = new_inbound(protocol, 8443, "tcp", "none" if protocol in {"vmess", "shadowsocks"} else "reality")
        client = inbound.make_client("owner")
        assert link_for(inbound, client, "h").startswith(prefix)


def test_link_remark_contains_names() -> None:
    inbound = new_inbound("vless", 443, "tcp", "reality")
    client = inbound.make_client("phone")
    link = vless_link(inbound, client, "h")
    assert "phone" in unquote(urlparse(link).fragment)


def test_links_for_returns_all_clients() -> None:
    inbound = new_inbound("vless", 443, "tcp", "reality")
    inbound.make_client("a")
    inbound.make_client("b")
    links = links_for(inbound, "host")
    assert [name for name, _ in links] == ["a", "b"]


def test_parse_link_roundtrip() -> None:
    inbound = new_inbound("vless", 443, "tcp", "reality")
    client = inbound.make_client("owner")
    parsed = parse_link(vless_link(inbound, client, "example.com"))
    assert parsed["protocol"] == "vless"
    assert parsed["host"] == "example.com"
    assert parsed["port"] == 443
    assert parsed["user"] == client.ident
    with pytest.raises(XrayError):
        parse_link("http://example.com")


def test_config_json_structure() -> None:
    inbound = new_inbound("vless", 443, "tcp", "reality")
    inbound.make_client("owner")
    config = config_json([inbound])
    assert config["log"]["loglevel"] == "warning"
    assert len(config["inbounds"]) == 1
    assert config["inbounds"][0]["port"] == 443
    assert config["outbounds"][0]["protocol"] == "freedom"
    assert config["routing"]["rules"][0]["outboundTag"] == "blocked"
    text = config_text([inbound])
    assert json.loads(text)["inbounds"][0]["protocol"] == "vless"


def test_config_skips_disabled() -> None:
    first = new_inbound("vless", 443, "tcp", "reality")
    second = new_inbound("trojan", 8443, "tcp", "reality")
    second.enable = False
    config = config_json([first, second])
    assert len(config["inbounds"]) == 1


def test_state_add_remove_and_ports() -> None:
    state = XrayState()
    first = state.add(new_inbound("vless", 443, "tcp", "reality"))
    assert first.id == 1
    with pytest.raises(XrayError):
        state.add(new_inbound("trojan", 443, "tcp", "reality"))
    second = state.add(new_inbound("trojan", 8443, "tcp", "reality"))
    assert second.id == 2
    assert state.ports() == [443, 8443]
    assert state.remove(1) is True
    assert state.remove(1) is False
    assert state.next_id() == 1


def test_state_enabled_filter() -> None:
    state = XrayState()
    first = state.add(new_inbound("vless", 443, "tcp", "reality"))
    first.enable = False
    assert state.enabled() == []
    assert len(state.to_config()) > 10


def test_state_dict_roundtrip() -> None:
    state = XrayState()
    inbound = state.add(new_inbound("vless", 443, "tcp", "reality"))
    inbound.make_client("owner")
    again = XrayState.from_dict(state.to_dict())
    assert again.inbounds[0].clients[0].email == "owner"
    assert again.inbounds[0].private_key == inbound.private_key
    assert again.version == state.version
    assert again.scan_targets == state.scan_targets


def test_state_adopt_scan() -> None:
    state = XrayState()
    inbound = state.add(new_inbound("vless", 443, "tcp", "reality"))
    state.adopt_scan(inbound.id, "www.microsoft.com", "www.microsoft.com", 443)
    assert inbound.dest == "www.microsoft.com:443"
    assert inbound.sni == "www.microsoft.com"
    with pytest.raises(XrayError):
        state.adopt_scan(inbound.id, "", "", 443)
    with pytest.raises(XrayError):
        state.adopt_scan(99, "a", "a", 443)


def test_state_set_reality_keys() -> None:
    state = XrayState()
    inbound = state.add(new_inbound("vless", 443, "tcp", "reality"))
    state.set_reality_keys(inbound.id, "priv", "pub")
    assert state.public_key_of(inbound.id) == "pub"
    with pytest.raises(XrayError):
        state.set_reality_keys(7, "a", "b")


def test_summary_rows() -> None:
    inbound = new_inbound("vless", 443, "ws", "tls")
    rows = dict(summary(inbound))
    assert rows["протокол"] == "vless"
    assert rows["сеть"] == "ws"
    assert "path" in rows


def test_inbound_dict_roundtrip() -> None:
    inbound = new_inbound("shadowsocks", 8443, "xhttp", "none")
    inbound.make_client("a")
    again = XrayInbound.from_dict(inbound.to_dict())
    assert again.ss_method == inbound.ss_method
    assert again.network == "xhttp"
    assert again.clients[0].email == "a"


def test_scan_defaults_are_host_port() -> None:
    state = XrayState()
    assert len(state.scan_targets) == 10
    for item in state.scan_targets:
        assert ":" in item


def test_protocol_tables_are_consistent() -> None:
    assert set(PROTOCOLS) == {"vless", "vmess", "trojan", "shadowsocks"}
    assert "reality" in SECURITIES
    assert "xhttp" in NETWORKS
