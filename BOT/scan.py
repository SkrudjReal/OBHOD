from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

SCAN_TIMEOUT = 10.0
DISCOVER_TIMEOUT = 4.0
CONCURRENCY = 32
DISCOVER_MAX_IPS = 256
SCAN_MAX_TOTAL = 512
PROXY_V1 = 1
PROXY_V2 = 2

DEFAULT_CANDIDATES = (
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

OID_CN = bytes.fromhex("550403")
OID_SAN = bytes.fromhex("551d11")
OID_KEY_USAGE = bytes.fromhex("551d0f")
OID_ORG = bytes.fromhex("55040a")

TAG_CONSTRUCTED = 0x20
TAG_CLASS_CONTEXT = 0x80


class ScanError(Exception):
    pass


def blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def normalize_host(value: object) -> str:
    text = str(value or "").strip().strip("[]")
    if not text:
        raise ScanError("нужен адрес или домен")
    if any(char.isspace() for char in text):
        raise ScanError("в адресе не должно быть пробелов")
    if len(text) > 253:
        raise ScanError("адрес слишком длинный")
    return text


def split_target(target: str) -> tuple[str, int]:
    text = (target or "").strip()
    if not text:
        raise ScanError("нужен target вида host:port")
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port_text = rest.lstrip(":")
    elif text.count(":") == 1:
        host, port_text = text.split(":", 1)
    else:
        host, port_text = text, "443"
    host = normalize_host(host)
    try:
        port = int(port_text or 443)
    except ValueError:
        raise ScanError("порт должен быть числом") from None
    if not 1 <= port <= 65535:
        raise ScanError("порт должен быть 1..65535")
    return host, port


def enumerate_cidr(cidr: str, limit: int = DISCOVER_MAX_IPS) -> list[str]:
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError as exc:
        raise ScanError(f"неверная подсеть: {exc}") from None
    out: list[str] = []
    for address in net:
        out.append(str(address))
        if len(out) >= limit:
            break
    return out


def tls_version_name(version: str | None) -> str:
    mapping = {
        "TLSv1.3": "1.3",
        "TLSv1.2": "1.2",
        "TLSv1.1": "1.1",
        "TLSv1": "1.0",
    }
    return mapping.get(version or "", version or "")


def _tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset + 2 > len(data):
        raise ScanError("обрезанный DER")
    tag = data[offset]
    length = data[offset + 1]
    head = 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or offset + 2 + count > len(data):
            raise ScanError("обрезанная длина DER")
        length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
        head += count
    start = offset + head
    end = start + length
    if end > len(data):
        raise ScanError("обрезанный DER")
    return tag, start, end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    offset = start
    while offset < end:
        tag, s, e = _tlv(data, offset)
        out.append((tag, s, e))
        offset = e
    return out


def _decode_string(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


def _decode_time(tag: int, raw: bytes) -> str:
    text = raw.decode("ascii", "replace")
    try:
        if tag == 0x17 and len(text) >= 13:
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900
            month, day = int(text[2:4]), int(text[4:6])
            hour, minute, second = int(text[6:8]), int(text[8:10]), int(text[10:12])
        elif tag == 0x18 and len(text) >= 15:
            year, month, day = int(text[0:4]), int(text[4:6]), int(text[6:8])
            hour, minute, second = int(text[8:10]), int(text[10:12]), int(text[12:14])
        else:
            return ""
    except ValueError:
        return ""
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"


@dataclass
class Certificate:
    subject_cn: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    not_after: str = ""
    dns_names: list[str] = field(default_factory=list)
    chain_bytes: int = 0


def parse_certificate(der: bytes) -> Certificate:
    cert = Certificate(chain_bytes=len(der))
    tag, start, end = _tlv(der, 0)
    if tag != 0x30:
        raise ScanError("сертификат не SEQUENCE")
    parts = _children(der, start, end)
    if not parts:
        raise ScanError("пустой сертификат")
    tbs_tag, tbs_start, tbs_end = parts[0]
    tbs = _children(der, tbs_start, tbs_end)
    index = 0
    if tbs and (tbs[0][0] & 0xE0) == (TAG_CLASS_CONTEXT | TAG_CONSTRUCTED):
        index = 1
    if len(tbs) < index + 6:
        raise ScanError("короткий tbsCertificate")
    issuer = _children(der, tbs[index + 2][1], tbs[index + 2][2])
    validity = tbs[index + 3]
    subject = _children(der, tbs[index + 4][1], tbs[index + 4][2])
    cert.subject_cn = _name_value(der, subject, OID_CN)
    cert.issuer_cn = _name_value(der, issuer, OID_CN)
    cert.issuer_org = _name_value(der, issuer, OID_ORG)
    times = _children(der, validity[1], validity[2])
    if len(times) >= 2:
        cert.not_after = _decode_time(times[1][0], der[times[1][1] : times[1][2]])
    for entry in tbs[index + 5 :]:
        if (entry[0] & 0xE0) != (TAG_CLASS_CONTEXT | TAG_CONSTRUCTED):
            continue
        if (entry[0] & 0x1F) != 3:
            continue
        inner = _children(der, entry[1], entry[2])
        if not inner:
            continue
        for ext in _children(der, inner[0][1], inner[0][2]):
            fields = _children(der, ext[1], ext[2])
            if len(fields) < 2:
                continue
            oid = der[fields[0][1] : fields[0][2]]
            if oid != OID_SAN:
                continue
            value = fields[-1]
            names = _children(der, value[1], value[2])
            if names and names[0][0] == 0x30:
                names = _children(der, names[0][1], names[0][2])
            cert.dns_names = [_decode_string(der[item[1] : item[2]]) for item in names if item[0] == 0x82]
    return cert


def _name_value(der: bytes, entries: list[tuple[int, int, int]], oid: bytes) -> str:
    for rdn in entries:
        for attribute in _children(der, rdn[1], rdn[2]):
            parts = _children(der, attribute[1], attribute[2])
            if len(parts) < 2:
                continue
            if der[parts[0][1] : parts[0][2]] == oid:
                return _decode_string(der[parts[1][1] : parts[1][2]])
    return ""


@dataclass
class ScanResult:
    target: str = ""
    host: str = ""
    ip: str = ""
    port: int = 443
    feasible: bool = False
    private_target: bool = False
    tls13: bool = False
    tls_version: str = ""
    h2: bool = False
    alpn: str = ""
    x25519: bool = False
    curve_id: str = ""
    cert_valid: bool = False
    cert_chain_valid: bool = False
    cert_chain_bytes: int = 0
    cert_subject: str = ""
    cert_issuer: str = ""
    not_after: str = ""
    server_names: list[str] = field(default_factory=list)
    latency_ms: int = 0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "ip": self.ip,
            "port": int(self.port),
            "feasible": bool(self.feasible),
            "private_target": bool(self.private_target),
            "tls13": bool(self.tls13),
            "tls_version": self.tls_version,
            "h2": bool(self.h2),
            "alpn": self.alpn,
            "x25519": bool(self.x25519),
            "curve_id": self.curve_id,
            "cert_valid": bool(self.cert_valid),
            "cert_chain_valid": bool(self.cert_chain_valid),
            "cert_chain_bytes": int(self.cert_chain_bytes),
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "not_after": self.not_after,
            "server_names": list(self.server_names),
            "latency_ms": int(self.latency_ms),
            "reason": self.reason,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "ScanResult":
        data = raw or {}
        return ScanResult(
            target=str(data.get("target", "")),
            host=str(data.get("host", "")),
            ip=str(data.get("ip", "")),
            port=int(data.get("port", 443) or 443),
            feasible=bool(data.get("feasible", False)),
            private_target=bool(data.get("private_target", False)),
            tls13=bool(data.get("tls13", False)),
            tls_version=str(data.get("tls_version", "")),
            h2=bool(data.get("h2", False)),
            alpn=str(data.get("alpn", "")),
            x25519=bool(data.get("x25519", False)),
            curve_id=str(data.get("curve_id", "")),
            cert_valid=bool(data.get("cert_valid", False)),
            cert_chain_valid=bool(data.get("cert_chain_valid", False)),
            cert_chain_bytes=int(data.get("cert_chain_bytes", 0) or 0),
            cert_subject=str(data.get("cert_subject", "")),
            cert_issuer=str(data.get("cert_issuer", "")),
            not_after=str(data.get("not_after", "")),
            server_names=[str(item) for item in data.get("server_names") or []],
            latency_ms=int(data.get("latency_ms", 0) or 0),
            reason=str(data.get("reason", "")),
        )

    def line(self) -> str:
        mark = "ok" if self.feasible else "no"
        bits = [mark, self.target]
        if self.tls_version:
            bits.append("tls" + self.tls_version)
        if self.alpn:
            bits.append(self.alpn)
        if self.latency_ms:
            bits.append(f"{self.latency_ms}ms")
        if self.cert_subject:
            bits.append(self.cert_subject)
        if self.reason:
            bits.append(self.reason)
        return " ".join(bits)


def feasible_of(result: ScanResult) -> bool:
    return bool(result.tls13 and result.h2 and result.x25519 and result.cert_valid)


def proxy_header(kind: int, local: tuple[str, int], remote: tuple[str, int]) -> bytes:
    if kind >= PROXY_V2:
        head = bytes([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21])
        try:
            src = ipaddress.ip_address(local[0]).packed
            dst = ipaddress.ip_address(remote[0]).packed
        except ValueError:
            return b""
        family = 0x11 if len(src) == 4 else 0x21
        addresses = src + dst + local[1].to_bytes(2, "big") + remote[1].to_bytes(2, "big")
        return head + bytes([family]) + len(addresses).to_bytes(2, "big") + addresses
    try:
        src_ip = ipaddress.ip_address(local[0])
        dst_ip = ipaddress.ip_address(remote[0])
    except ValueError:
        return b""
    family = "TCP4" if src_ip.version == 4 else "TCP6"
    line = f"PROXY {family} {src_ip} {dst_ip} {local[1]} {remote[1]}\r\n"
    return line.encode("ascii")


def _context(verify: bool, hostname: str, only_x25519: bool, alpn: bool) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
        if not hostname:
            ctx.check_hostname = False
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, OSError):
        pass
    if only_x25519 and hasattr(ctx, "set_ecdh_curve"):
        try:
            ctx.set_ecdh_curve("X25519")
        except (ValueError, ssl.SSLError):
            return ctx
    return ctx


async def probe(
    host: str,
    port: int = 443,
    sni: str = "",
    timeout: float = SCAN_TIMEOUT,
    xver: int = 0,
    allow_private: bool = False,
    bulk: bool = False,
) -> ScanResult:
    result = ScanResult(target=f"{host}:{port}", host=sni or host, port=port)
    try:
        address = ipaddress.ip_address(host)
        result.ip = str(address)
        if blocked_ip(address) and not allow_private:
            result.private_target = True
            result.reason = "приватный или локальный адрес заблокирован"
            return result
    except ValueError:
        pass
    start = time.monotonic()
    try:
        info = await asyncio.wait_for(_connect_info(host, port, sni or host, timeout, xver), timeout=timeout + 2)
    except (asyncio.TimeoutError, OSError, ssl.SSLError, ScanError) as exc:
        result.reason = f"соединение не удалось: {type(exc).__name__}: {exc}"
        return result
    result.ip = info.get("ip", result.ip)
    result.latency_ms = int((time.monotonic() - start) * 1000)
    result.tls_version = tls_version_name(info.get("version"))
    result.tls13 = info.get("version") == "TLSv1.3"
    result.alpn = info.get("alpn") or ""
    result.h2 = result.alpn == "h2"
    cert = info.get("cert")
    if isinstance(cert, Certificate):
        result.cert_chain_bytes = cert.chain_bytes
        result.cert_subject = cert.subject_cn or (cert.dns_names[0] if cert.dns_names else "")
        result.cert_issuer = cert.issuer_org or cert.issuer_cn
        result.not_after = cert.not_after
        result.server_names = [name for name in cert.dns_names if name and not name.startswith("*.")]
        if not sni and result.server_names:
            result.host = result.server_names[0]
            result.target = f"{result.host}:{port}"
    else:
        result.reason = "сертификат не получен"
    if bulk and not result.tls_version:
        return result
    result.x25519 = await _supports_x25519(host, port, result.host, timeout, xver)
    result.curve_id = "X25519" if result.x25519 else ""
    verify_host = result.host or sni
    if verify_host:
        chain_ok, name_ok, why = await _verify(host, port, verify_host, timeout, xver)
        result.cert_chain_valid = chain_ok
        result.cert_valid = chain_ok and name_ok
        if not result.cert_valid and not result.reason:
            result.reason = why or "сертификат не проходит проверку"
    else:
        result.reason = result.reason or "в сертификате нет пригодного домена"
    result.feasible = feasible_of(result)
    if not result.feasible and not result.reason:
        if not result.tls13:
            result.reason = "сервер не согласовал TLS 1.3"
        elif not result.h2:
            result.reason = "сервер не согласовал HTTP/2"
        elif not result.x25519:
            result.reason = "сервер не согласовал X25519"
    return result


async def _connect_info(host: str, port: int, sni: str, timeout: float, xver: int) -> dict[str, Any]:
    ctx = _context(False, sni, False, True)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    info: dict[str, Any] = {}
    try:
        peer = writer.get_extra_info("peername")
        if peer:
            info["ip"] = str(peer[0])
        if xver:
            local = writer.get_extra_info("sockname") or ("0.0.0.0", 0)
            header = proxy_header(xver, (local[0], local[1]), (peer[0] if peer else host, peer[1] if peer else port))
            if header:
                writer.write(header)
                await writer.drain()
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=sni or None)
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    writer.write(pending)
                    await writer.drain()
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                except asyncio.TimeoutError:
                    raise ScanError("таймаут TLS рукопожатия") from None
                if not chunk:
                    raise ScanError("соединение закрыто во время рукопожатия")
                incoming.write(chunk)
        tail = outgoing.read()
        if tail:
            writer.write(tail)
            await writer.drain()
        info["version"] = obj.version()
        info["alpn"] = obj.selected_alpn_protocol()
        der = obj.getpeercert(binary_form=True)
        if der:
            try:
                info["cert"] = parse_certificate(der)
            except ScanError as exc:
                info["cert_error"] = str(exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass
    return info


async def _supports_x25519(host: str, port: int, sni: str, timeout: float, xver: int) -> bool:
    ctx = _context(False, sni, True, False)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return False
    try:
        if xver:
            local = writer.get_extra_info("sockname") or ("0.0.0.0", 0)
            peer = writer.get_extra_info("peername") or (host, port)
            header = proxy_header(xver, (local[0], local[1]), (peer[0], peer[1]))
            if header:
                writer.write(header)
                await writer.drain()
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=sni or None)
        while True:
            try:
                obj.do_handshake()
                return True
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    writer.write(pending)
                    await writer.drain()
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    return False
                incoming.write(chunk)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


async def _verify(host: str, port: int, sni: str, timeout: float, xver: int) -> tuple[bool, bool, str]:
    def run_check(check_hostname: bool) -> tuple[bool, str]:
        ctx = _context(True, sni or host, False, True)
        ctx.check_hostname = check_hostname
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as tls:
                tls.getpeercert()
                return True, ""

    loop = asyncio.get_running_loop()
    try:
        chain_ok, _ = await loop.run_in_executor(None, run_check, False)
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        return False, False, f"цепочка сертификата не проверена: {exc}"
    try:
        await loop.run_in_executor(None, run_check, True)
        return chain_ok, True, ""
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        return chain_ok, False, f"имя в сертификате не совпало: {exc}"


def rank(results: list[ScanResult]) -> list[ScanResult]:
    best: dict[str, ScanResult] = {}
    order: list[str] = []
    for item in results:
        if item is None:
            continue
        existing = best.get(item.target)
        if existing is None:
            best[item.target] = item
            order.append(item.target)
        elif _better(item, existing):
            best[item.target] = item
    out = [best[key] for key in order]
    out.sort(key=lambda r: (not r.feasible, r.latency_ms if r.latency_ms else 10 ** 9))
    return out


def _better(candidate: ScanResult, current: ScanResult) -> bool:
    if candidate.feasible != current.feasible:
        return candidate.feasible
    return candidate.latency_ms > 0 and (current.latency_ms == 0 or candidate.latency_ms < current.latency_ms)


async def scan_targets(
    targets: list[str],
    sni: str = "",
    xver: int = 0,
    allow_private: bool = False,
    concurrency: int = CONCURRENCY,
) -> list[ScanResult]:
    tokens = [item.strip() for item in targets if str(item).strip()]
    if not tokens:
        raise ScanError("нужен хотя бы один target")
    tasks: list[tuple[str, int, str, float, bool]] = []
    invalid: list[ScanResult] = []
    for token in tokens:
        if len(tasks) >= SCAN_MAX_TOTAL:
            break
        if "/" in token:
            try:
                ips = enumerate_cidr(token)
            except ScanError as exc:
                invalid.append(ScanResult(target=token, reason=str(exc)))
                continue
            for ip in ips:
                if len(tasks) >= SCAN_MAX_TOTAL:
                    break
                tasks.append((ip, 443, "", DISCOVER_TIMEOUT, True))
            continue
        try:
            host, port = split_target(token)
        except ScanError as exc:
            invalid.append(ScanResult(target=token, reason=str(exc)))
            continue
        if _is_ip(host):
            tasks.append((host, port, sni, DISCOVER_TIMEOUT, False))
        else:
            tasks.append((host, port, sni or host, SCAN_TIMEOUT, False))
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    results: list[ScanResult | None] = [None] * len(tasks)

    async def run_one(index: int, host: str, port: int, name: str, timeout: float, bulk: bool) -> None:
        async with sem:
            try:
                item = await probe(host, port, name, timeout, xver, allow_private, bulk)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                item = ScanResult(target=f"{host}:{port}", host=name or host, port=port, reason=f"сбой: {type(exc).__name__}: {exc}")
            if bulk and not item.tls_version:
                results[index] = None
            else:
                results[index] = item

    await asyncio.gather(*(run_one(i, *task) for i, task in enumerate(tasks)))
    clean = [item for item in results if item is not None]
    return rank(clean + invalid)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def best_candidate(results: list[ScanResult]) -> ScanResult | None:
    for item in results:
        if item.feasible:
            return item
    return None
