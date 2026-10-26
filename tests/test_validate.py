from __future__ import annotations

import pytest

from BOT import validate
from BOT.validate import ValidationError


def test_port_accepts_number_and_string() -> None:
    assert validate.port(22) == 22
    assert validate.port(" 56000 ") == 56000


@pytest.mark.parametrize("bad", [0, 65536, -1, "abc", "", None, "1.5"])
def test_port_rejects(bad: object) -> None:
    with pytest.raises(ValidationError):
        validate.port(bad)


def test_hex64() -> None:
    assert validate.hex64("a" * 64) == "a" * 64
    assert validate.hex64(("AB" * 32).upper()) == "ab" * 32
    with pytest.raises(ValidationError):
        validate.hex64("a" * 63)
    with pytest.raises(ValidationError):
        validate.hex64("z" * 64)


def test_host() -> None:
    assert validate.host("example.com") == "example.com"
    assert validate.host(" 203.0.113.10 ") == "203.0.113.10"
    assert validate.host("fe80::1") == "fe80::1"
    for bad in ["", "he sto", "host/../x", "-leading", "a b"]:
        with pytest.raises(ValidationError):
            validate.host(bad)


def test_name() -> None:
    assert validate.name("owner") == "owner"
    assert validate.name("dev-1_2.x") == "dev-1_2.x"
    for bad in ["", "..", "a b", "x" * 33, "-x", "юзер"]:
        with pytest.raises(ValidationError):
            validate.name(bad)


def test_hostport() -> None:
    assert validate.hostport("127.0.0.1:51820") == "127.0.0.1:51820"
    assert validate.hostport("[::1]:51820") == "[::1]:51820"
    for bad in ["127.0.0.1", "host:0", "host:70000", ":51820"]:
        with pytest.raises(ValidationError):
            validate.hostport(bad)


def test_net() -> None:
    assert validate.net("10.13.13.0/24") == "10.13.13.0/24"
    with pytest.raises(ValidationError):
        validate.net("10.13.13.1/24")
    with pytest.raises(ValidationError):
        validate.net("10.13.13.0/33")


def test_version() -> None:
    assert validate.version("latest") == "latest"
    assert validate.version("local") == "local"
    assert validate.version("v4.1.0") == "v4.1.0"
    with pytest.raises(ValidationError):
        validate.version("4;rm -rf /")


def test_call_link() -> None:
    good = "https://vk.ru/call/join/AbCdEf"
    assert validate.call_link(good) == good
    assert validate.call_link("") == ""
    with pytest.raises(ValidationError):
        validate.call_link("https://example.com/call/join/x")


def test_positive_int() -> None:
    assert validate.positive_int("12", 1, 128, "потоки") == 12
    with pytest.raises(ValidationError):
        validate.positive_int("0", 1, 128, "потоки")
    with pytest.raises(ValidationError):
        validate.positive_int("x", 1, 128, "потоки")


def test_dns_servers() -> None:
    assert validate.dns_servers("1.1.1.1, 8.8.8.8") == "1.1.1.1,8.8.8.8"
    assert validate.dns_servers("") == ""
    with pytest.raises(ValidationError):
        validate.dns_servers("1.1.1.1,999.1.1.1")


def test_local_listen() -> None:
    assert validate.local_listen("127.0.0.1:9000") == "127.0.0.1:9000"
    with pytest.raises(ValidationError):
        validate.local_listen("9000")


def test_one_of() -> None:
    assert validate.one_of("udp", ("udp", "tcp"), "mode") == "udp"
    with pytest.raises(ValidationError):
        validate.one_of("icmp", ("udp", "tcp"), "mode")
