from __future__ import annotations

import re

PORT_RE = re.compile(r"^[1-9][0-9]{0,4}$")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
HOST_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,39}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
NET_RE = re.compile(r"^((?:0|[1-9][0-9]{0,2})\.){3}(?:0|[1-9][0-9]{0,2})/(1[6-9]|2[0-9])$")
HOSTPORT_RE = re.compile(r"^(\[[0-9a-fA-F:]{2,39}\]|[a-zA-Z0-9.-]{1,253}):([0-9]{1,5})$")
VERSION_RE = re.compile(r"^(latest|local|v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?)$")
CALL_LINK_RE = re.compile(r"^https://(vk\.(ru|com)|vk\.me)/(call/join|join)/[A-Za-z0-9_-]{4,64}/?$")


class ValidationError(Exception):
    pass


def port(value: object) -> int:
    text = str(value).strip()
    if not PORT_RE.match(text) or int(text) > 65535:
        raise ValidationError("port must be 1..65535")
    return int(text)


def hex64(value: object) -> str:
    text = str(value).strip()
    if not HEX64_RE.match(text):
        raise ValidationError("key must be 64 hex characters")
    return text.lower()


def host(value: object) -> str:
    text = str(value).strip()
    if IPV6_RE.match(text):
        return text
    if not HOST_RE.match(text):
        raise ValidationError("host must be a name or an ip address")
    if re.fullmatch(r"[0-9.]+", text):
        octets = text.split(".")
        if len(octets) != 4 or any(not part.isdigit() or int(part) > 255 for part in octets):
            raise ValidationError("ip address must have four octets in 0..255")
        return text
    labels = text.split(".")
    if any(not label or label[0] == "-" or label[-1] == "-" for label in labels):
        raise ValidationError("host labels must start and end with a letter or digit")
    return text


def name(value: object) -> str:
    text = str(value).strip()
    if not NAME_RE.match(text):
        raise ValidationError("name must start with a letter or digit and hold [A-Za-z0-9._-], up to 32 chars")
    return text


def hostport(value: object) -> str:
    text = str(value).strip()
    match = HOSTPORT_RE.match(text)
    if not match:
        raise ValidationError("address must be host:port or [ipv6]:port")
    port(match.group(2))
    return text


def net(value: object) -> str:
    text = str(value).strip()
    match = NET_RE.match(text)
    if not match:
        raise ValidationError("subnet must be a network address with /16../29")
    ip = text.split("/", 1)[0]
    octets = [int(part) for part in ip.split(".")]
    if any(part > 255 for part in octets):
        raise ValidationError("subnet octets must be 0..255")
    prefix = int(text.split("/", 1)[1])
    packed = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    host_mask = (1 << (32 - prefix)) - 1
    if packed & host_mask:
        raise ValidationError("subnet must not carry host bits")
    return text


def version(value: object) -> str:
    text = str(value).strip()
    if not VERSION_RE.match(text):
        raise ValidationError("version must be latest, local or vX.Y.Z")
    return text


def call_link(value: object) -> str:
    text = str(value).strip()
    if not text:
        return ""
    if not CALL_LINK_RE.match(text):
        raise ValidationError("call link must look like https://vk.ru/call/join/CODE")
    return text


def user(value: object) -> str:
    text = str(value).strip()
    if not USER_RE.match(text):
        raise ValidationError("user must be 1..32 chars of [a-z_][a-z0-9_-]*")
    return text


def private_key(value: object) -> str:
    text = (value or "").replace("\r\n", "\n").strip()
    if len(text) < 64:
        raise ValidationError("private key is too short")
    if "PRIVATE KEY" not in text:
        raise ValidationError("private key must contain a BEGIN and END line")
    if "BEGIN" not in text or "END" not in text:
        raise ValidationError("private key must contain a BEGIN and END line")
    return text + "\n"


def positive_int(value: object, low: int, high: int, label: str) -> int:
    text = str(value).strip()
    if not text.lstrip("-").isdigit():
        raise ValidationError(f"{label} must be a number")
    number = int(text)
    if number < low or number > high:
        raise ValidationError(f"{label} must be {low}..{high}")
    return number


def dns_servers(value: object) -> str:
    text = str(value).strip()
    if not text:
        return ""
    parts = [part.strip() for part in text.replace(";", ",").split(",") if part.strip()]
    for part in parts:
        candidate = part
        if candidate.count(":") == 1:
            candidate = candidate.split(":", 1)[0]
        host(candidate)
    return ",".join(parts)


def local_listen(value: object) -> str:
    text = str(value).strip()
    match = HOSTPORT_RE.match(text)
    if not match:
        raise ValidationError("listen address must be ip:port")
    port(match.group(2))
    return text


def one_of(value: object, allowed: tuple[str, ...], label: str) -> str:
    text = str(value).strip().lower()
    if text not in allowed:
        raise ValidationError(f"{label} must be one of: " + ", ".join(allowed))
    return text
