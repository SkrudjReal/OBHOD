from __future__ import annotations

import asyncio
import ipaddress
import ssl
import subprocess
from pathlib import Path

import pytest

from BOT import scan as scanner
from BOT.scan import (
    CONCURRENCY,
    DISCOVER_TIMEOUT,
    DISCOVER_MAX_IPS,
    SCAN_MAX_TOTAL,
    ScanError,
    ScanResult,
    best_candidate,
    enumerate_cidr,
    normalize_host,
    parse_certificate,
    probe,
    proxy_header,
    rank,
    scan_targets,
    split_target,
)


def test_limits_match_3xui_defaults() -> None:
    assert CONCURRENCY == 32
    assert DISCOVER_TIMEOUT == 4.0
    assert DISCOVER_MAX_IPS == 256
    assert SCAN_MAX_TOTAL == 512
    assert len(scanner.DEFAULT_CANDIDATES) == 10
    assert "www.cloudflare.com:443" in scanner.DEFAULT_CANDIDATES


def test_split_target_variants() -> None:
    assert split_target("example.com:443") == ("example.com", 443)
    assert split_target("example.com") == ("example.com", 443)
    assert split_target(" 1.2.3.4:8443 ") == ("1.2.3.4", 8443)
    assert split_target("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert split_target("2001:db8::1") == ("2001:db8::1", 443)
    with pytest.raises(ScanError):
        split_target("host:bad")
    with pytest.raises(ScanError):
        split_target("")
    with pytest.raises(ScanError):
        split_target("host:99999")


def test_normalize_host() -> None:
    assert normalize_host(" Example.COM ") == "Example.COM"
    assert normalize_host("[::1]") == "::1"
    with pytest.raises(ScanError):
        normalize_host("")
    with pytest.raises(ScanError):
        normalize_host("a b")


def test_private_detection() -> None:
    assert scanner.blocked_ip(ipaddress.ip_address("10.0.0.1")) is True
    assert scanner.blocked_ip(ipaddress.ip_address("127.0.0.1")) is True
    assert scanner.blocked_ip(ipaddress.ip_address("192.168.1.1")) is True
    assert scanner.blocked_ip(ipaddress.ip_address("8.8.8.8")) is False
    assert scanner.blocked_ip(ipaddress.ip_address("169.254.1.1")) is True


def test_enumerate_cidr_limits() -> None:
    assert enumerate_cidr("10.0.0.0/30") == ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert len(enumerate_cidr("10.0.0.0/8")) == DISCOVER_MAX_IPS
    with pytest.raises(ScanError):
        enumerate_cidr("not-a-cidr")
    with pytest.raises(ScanError):
        enumerate_cidr("10.0.0.0/33")
    assert enumerate_cidr("2001:db8::/120")[:2] == ["2001:db8::", "2001:db8::1"]


def test_enumerate_cidr_bounds() -> None:
    hosts = enumerate_cidr("10.1.0.0/24")
    assert len(hosts) <= DISCOVER_MAX_IPS
    assert hosts[0] == "10.1.0.0"


def test_proxy_header_v1() -> None:
    body = proxy_header(1, ("10.0.0.1", 1234), ("10.0.0.2", 443))
    assert body == b"PROXY TCP4 10.0.0.1 10.0.0.2 1234 443\r\n"


def test_proxy_header_v2() -> None:
    body = proxy_header(2, ("10.0.0.1", 1234), ("10.0.0.2", 443))
    assert body[:12] == b"\r\n\r\n\x00\r\nQUIT\n"
    assert body[12] == 0x21
    assert len(body) == 16 + 12


def test_rank_prefers_feasible_and_fast() -> None:
    results = [
        ScanResult(target="slow:443", feasible=True, latency_ms=120),
        ScanResult(target="fast:443", feasible=True, latency_ms=20),
        ScanResult(target="dead:443", feasible=False, latency_ms=5),
    ]
    ordered = rank(results)
    assert [item.target for item in ordered] == ["fast:443", "slow:443", "dead:443"]


def test_rank_dedups_by_target() -> None:
    results = [
        ScanResult(target="a:443", feasible=False, latency_ms=5),
        ScanResult(target="a:443", feasible=True, latency_ms=90),
    ]
    ordered = rank(results)
    assert len(ordered) == 1
    assert ordered[0].feasible is True


def test_best_candidate() -> None:
    assert best_candidate([]) is None
    results = [ScanResult(target="a:443", feasible=False), ScanResult(target="b:443", feasible=True, latency_ms=40)]
    assert best_candidate(results).target == "b:443"


def test_result_roundtrip() -> None:
    item = ScanResult(target="a:443", host="a", feasible=True, latency_ms=12, server_names=["a"])
    again = ScanResult.from_dict(item.to_dict())
    assert again.target == item.target
    assert again.server_names == ["a"]
    assert item.line().startswith("ok a:443")


def test_result_line_for_failure() -> None:
    item = ScanResult(target="a:443", reason="нет связи")
    line = item.line()
    assert line.startswith("no")
    assert "нет связи" in line


def test_parse_certificate_requires_bytes() -> None:
    with pytest.raises(ScanError):
        parse_certificate(b"")
    with pytest.raises(ScanError):
        parse_certificate(b"\x30\x03\x01\x01")


async def test_probe_blocks_private_targets() -> None:
    result = await probe("127.0.0.1", 443, "localhost")
    assert result.private_target is True
    assert result.feasible is False
    assert result.reason


async def test_probe_reports_connection_error() -> None:
    result = await probe("127.0.0.1", 1, "localhost", allow_private=True)
    assert result.feasible is False
    assert result.reason
    assert result.latency_ms >= 0


async def test_scan_targets_requires_input() -> None:
    with pytest.raises(ScanError):
        await scan_targets(["  "])
    with pytest.raises(ScanError):
        await scan_targets([])


async def test_scan_targets_marks_bad_cidr() -> None:
    results = await scan_targets(["10.0.0.0/33"], concurrency=2)
    assert len(results) == 1
    assert results[0].feasible is False
    assert results[0].reason


async def test_scan_targets_respects_total_limit() -> None:
    targets = [f"10.9.{index}.0/30" for index in range(4)]
    results = await scan_targets(targets, concurrency=8)
    assert len(results) <= SCAN_MAX_TOTAL


def test_certificate_walker_on_openssl_cert(tmp_path: Path) -> None:
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "2",
                "-subj",
                "/CN=scanner.example.com",
                "-addext",
                "subjectAltName=DNS:scanner.example.com,DNS:alt.example.com",
            ],
            check=True,
            capture_output=True,
        )
        der = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl недоступен")
    parsed = parse_certificate(der)
    assert parsed.subject_cn == "scanner.example.com"
    assert "alt.example.com" in parsed.dns_names
    assert parsed.not_after
    assert parsed.issuer_cn == "scanner.example.com"


def test_parse_certificate_garbage() -> None:
    with pytest.raises(ScanError):
        parse_certificate(b"\x30\x82\x01\x00" + b"\x00" * 16)


async def test_probe_against_local_tls_server(tmp_path: Path) -> None:
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "2",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl недоступен")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read(4096)
        except (OSError, asyncio.IncompleteReadError):
            pass
        writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await probe("127.0.0.1", port, "localhost", allow_private=True)
    finally:
        server.close()
        await server.wait_closed()
    assert result.tls_version in {"1.3", "1.2"}
    assert result.cert_subject == "localhost"
    assert result.h2 is False or result.h2 is True
    assert result.feasible is False
    assert result.reason


def test_scan_result_feasibility_rule() -> None:
    item = ScanResult(target="a:443", tls13=True, h2=True, x25519=True, cert_valid=True)
    assert scanner.feasible_of(item) is True
    item.h2 = False
    assert scanner.feasible_of(item) is False
