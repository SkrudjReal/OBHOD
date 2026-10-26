from __future__ import annotations

import secrets
from dataclasses import dataclass

from . import validate
from .config import ConfigError
from .models import (
    AUTH_KEY,
    AUTH_PASSWORD,
    BACKEND_EXTERNAL,
    BACKEND_NEW,
    CORE_VERSION,
    CORE_VERSION_LATEST,
    OBF_PROFILES,
    normalize_version,
)
from .store import State
from .validate import ValidationError


@dataclass(frozen=True)
class FieldSpec:
    key: str
    label: str
    prompt: str
    hint: str
    secret: bool = False


FIELDS: dict[str, FieldSpec] = {
    "ssh_host": FieldSpec("ssh_host", "Адрес сервера", "отправьте ip или домен сервера", "например 203.0.113.10", False),
    "ssh_port": FieldSpec("ssh_port", "Порт SSH", "отправьте порт ssh", "по умолчанию 22", False),
    "ssh_user": FieldSpec("ssh_user", "Пользователь SSH", "отправьте имя пользователя", "обычно root", False),
    "ssh_password": FieldSpec("ssh_password", "Пароль SSH", "отправьте пароль пользователя", "сообщение не сохраняется в истории", True),
    "ssh_key": FieldSpec("ssh_key", "Приватный ключ", "отправьте приватный ключ целиком", "вместе со строками BEGIN и END", True),
    "ssh_passphrase": FieldSpec("ssh_passphrase", "Пароль ключа", "отправьте пароль приватного ключа", "если ключ без пароля, отправьте прочерк", True),
    "ssh_sudo": FieldSpec("ssh_sudo", "Пароль sudo", "отправьте пароль sudo", "нужен, если вход не под root", True),
    "setup_listen": FieldSpec("setup_listen", "Порт входа", "отправьте внешний udp порт ядра", "по умолчанию 56000", False),
    "setup_wgport": FieldSpec("setup_wgport", "Порт WireGuard", "отправьте локальный порт wireguard", "по умолчанию 51820", False),
    "setup_wgnet": FieldSpec("setup_wgnet", "Подсеть WireGuard", "отправьте подсеть", "по умолчанию 10.13.13.0/24", False),
    "setup_connect": FieldSpec("setup_connect", "Адрес внешнего VPN", "отправьте адрес в формате host:port", "например 127.0.0.1:51820", False),
    "setup_obfkey": FieldSpec("setup_obfkey", "Ключ обфускации", "отправьте 64 hex символа", "пустое значение сгенерирует новый ключ", True),
    "setup_host": FieldSpec("setup_host", "Адрес в ссылке", "отправьте адрес, который попадет в ссылку", "по умолчанию берется адрес ssh, пустое значение вернет его", False),
    "setup_version": FieldSpec("setup_version", "Версия ядра", "отправьте версию ядра", "по умолчанию " + CORE_VERSION + ", latest берет свежий релиз", False),
    "link_threads": FieldSpec("link_threads", "Потоки", "отправьте число потоков turn", "по умолчанию 12", False),
    "link_spc": FieldSpec("link_spc", "Потоки на креды", "отправьте число потоков на один кеш кредов", "по умолчанию 12", False),
    "link_timing": FieldSpec("link_timing", "Задержка мимикрии", "отправьте задержку в миллисекундах", "0 выключает пейсинг", False),
    "link_listen": FieldSpec("link_listen", "Локальный адрес", "отправьте адрес локального прослушивания", "по умолчанию 127.0.0.1:9000", False),
    "link_dnss": FieldSpec("link_dnss", "DNS серверы", "отправьте список dns через запятую", "пустое значение означает dns оператора", False),
    "link_call": FieldSpec("link_call", "Ссылка на звонок", "отправьте ссылку на звонок", "формат https://vk.ru/call/join/CODE", False),
    "client_name": FieldSpec("client_name", "Имя клиента", "отправьте имя клиента", "латиница, цифры, точка, дефис, подчеркивание", False),
}

FIELD_TARGETS: dict[str, str] = {
    "ssh_host": "ssh",
    "ssh_port": "ssh",
    "ssh_user": "ssh",
    "ssh_password": "ssh",
    "ssh_key": "ssh",
    "ssh_passphrase": "ssh",
    "ssh_sudo": "ssh",
    "setup_listen": "setup",
    "setup_wgport": "setup",
    "setup_wgnet": "setup",
    "setup_connect": "setup",
    "setup_obfkey": "setup",
    "setup_host": "setup",
    "setup_version": "setup",
    "link_threads": "client",
    "link_spc": "client",
    "link_timing": "client",
    "link_listen": "client",
    "link_dnss": "client",
    "link_call": "client",
    "client_name": "client_new",
}

CYCLE_FIELDS: dict[str, tuple[str, ...]] = {
    "transport": ("tcp", "udp"),
    "mode": ("udp", "tcp"),
    "dns": ("auto", "plain", "doh"),
}

DNS_SERVERS = ("auto", "1.1.1.1", "8.8.8.8")


class Flows:
    def field(self, key: str) -> FieldSpec:
        spec = FIELDS.get(key)
        if spec is None:
            raise ConfigError(f"неизвестное поле ввода: {key}")
        return spec

    def target(self, key: str) -> str:
        return FIELD_TARGETS.get(key, "home")

    def apply_field(self, state: State, key: str, text: str) -> str:
        value = (text or "").strip()
        if key == "ssh_host":
            state.ssh.host = validate.host(value)
            return f"адрес сервера: {state.ssh.host}"
        if key == "ssh_port":
            state.ssh.port = validate.port(value)
            return f"порт ssh: {state.ssh.port}"
        if key == "ssh_user":
            state.ssh.user = validate.user(value)
            return f"пользователь: {state.ssh.user}"
        if key == "ssh_password":
            state.ssh.password = value
            state.ssh.auth = AUTH_PASSWORD
            return "пароль ssh сохранен"
        if key == "ssh_key":
            state.ssh.key = validate.private_key(value)
            state.ssh.auth = AUTH_KEY
            return "приватный ключ сохранен"
        if key == "ssh_passphrase":
            state.ssh.passphrase = "" if value in {"-", ""} else value
            return "пароль ключа сохранен"
        if key == "ssh_sudo":
            state.ssh.sudo_password = "" if value == "-" else value
            return "пароль sudo сохранен"
        if key == "setup_listen":
            port = validate.port(value)
            if state.opts.backend == BACKEND_NEW and port == state.opts.wg_port:
                raise ValidationError("порт входа совпадает с портом wireguard")
            state.opts.listen_port = port
            return f"порт входа: {port}"
        if key == "setup_wgport":
            port = validate.port(value)
            if port == state.opts.listen_port:
                raise ValidationError("порт wireguard совпадает с портом входа")
            state.opts.wg_port = port
            return f"порт wireguard: {port}"
        if key == "setup_wgnet":
            state.opts.wg_net = validate.net(value)
            return f"подсеть wireguard: {state.opts.wg_net}"
        if key == "setup_connect":
            state.opts.connect = validate.hostport(value)
            state.opts.backend = BACKEND_EXTERNAL
            return f"внешний vpn: {state.opts.connect}"
        if key == "setup_obfkey":
            state.opts.obf_key = validate.hex64(value) if value else secrets.token_hex(32)
            return "ключ обфускации обновлен"
        if key == "setup_host":
            state.opts.host = "" if value in {"-", ""} else validate.host(value)
            return f"адрес в ссылке: {state.opts.host or 'по ssh'}"
        if key == "setup_version":
            state.opts.version = self.pin_version(value)
            return f"версия ядра: {state.opts.version}"
        if key == "link_threads":
            state.link.threads = validate.positive_int(value, 1, 128, "потоки")
            return f"потоки turn: {state.link.threads}"
        if key == "link_spc":
            state.link.streams_per_cred = validate.positive_int(value, 1, 64, "потоки на креды")
            return f"потоки на креды: {state.link.streams_per_cred}"
        if key == "link_timing":
            state.link.timing_ms = validate.positive_int(value, 0, 500, "задержка")
            return f"задержка: {state.link.timing_ms} ms"
        if key == "link_listen":
            state.link.local_listen = validate.local_listen(value)
            return f"локальный адрес: {state.link.local_listen}"
        if key == "link_dnss":
            state.link.dns_servers = validate.dns_servers(value)
            return "dns серверы обновлены"
        if key == "link_call":
            state.link.call_link = validate.call_link(value)
            return "ссылка на звонок сохранена"
        if key == "client_name":
            return f"имя клиента: {validate.name(value)}"
        raise ConfigError(f"неизвестное поле ввода: {key}")

    def pin_version(self, value: object) -> str:
        text = str(value or "").strip()
        if text == CORE_VERSION_LATEST:
            return CORE_VERSION_LATEST
        pinned = normalize_version(text)
        if not pinned or pinned == "local":
            raise ValidationError("версия: vX.Y.Z или latest")
        return pinned

    def set_version(self, state: State, value: object) -> None:
        state.opts.version = self.pin_version(value)

    def toggle_ssh_mode(self, state: State) -> None:
        state.ssh.auth = AUTH_KEY if state.ssh.auth == AUTH_PASSWORD else AUTH_PASSWORD

    def set_backend(self, state: State, value: str) -> None:
        backend = validate.one_of(value, (BACKEND_NEW, BACKEND_EXTERNAL), "backend")
        state.opts.backend = backend
        if backend == BACKEND_NEW and state.opts.mode not in {"udp"}:
            state.opts.mode = "udp"

    def set_method(self, state: State, value: str) -> None:
        state.opts.method = validate.one_of(value, ("docker", "systemd"), "method")

    def set_mode(self, state: State, value: str) -> None:
        mode = validate.one_of(value, ("udp", "tcp"), "mode")
        state.opts.mode = mode
        if mode == "tcp" and state.opts.backend == BACKEND_NEW:
            state.opts.mode = "udp"
            raise ValidationError("свой wireguard работает только в режиме udp")

    def set_obf(self, state: State, value: str) -> None:
        profile = validate.one_of(value, OBF_PROFILES, "профиль обфускации")
        state.opts.obf_profile = profile
        if profile != "none" and not state.opts.obf_key:
            state.opts.obf_key = secrets.token_hex(32)
        if profile == "none":
            state.opts.obf_key = ""

    def generate_obf_key(self, state: State) -> None:
        state.opts.obf_key = secrets.token_hex(32)

    def cycle(self, state: State, name: str) -> None:
        order = CYCLE_FIELDS.get(name)
        if order is None:
            raise ValidationError(f"неизвестный переключатель: {name}")
        if name == "transport":
            index = order.index(state.link.transport) if state.link.transport in order else 0
            state.link.transport = order[(index + 1) % len(order)]
            return
        if name == "mode":
            index = order.index(state.link.mode) if state.link.mode in order else 0
            state.link.mode = order[(index + 1) % len(order)]
            return
        if name == "dns":
            index = order.index(state.link.dns_mode) if state.link.dns_mode in order else 0
            state.link.dns_mode = order[(index + 1) % len(order)]
            return
        raise ValidationError(f"неизвестный переключатель: {name}")

    def toggle_link(self, state: State, name: str) -> None:
        if name == "bond":
            state.link.bond = not state.link.bond
            return
        if name == "mcap":
            state.link.manual_captcha = not state.link.manual_captcha
            return
        raise ValidationError(f"неизвестный переключатель: {name}")

    def validate_server(self, state: State) -> None:
        validate.port(state.opts.listen_port)
        validate.net(state.opts.wg_net)
        if state.opts.backend == BACKEND_EXTERNAL:
            validate.hostport(state.opts.connect)
        else:
            validate.port(state.opts.wg_port)
            if state.opts.listen_port == state.opts.wg_port:
                raise ValidationError("порт входа совпадает с портом wireguard")
        if state.opts.mode == "tcp" and state.opts.backend == BACKEND_NEW:
            raise ValidationError("свой wireguard работает только в режиме udp")
        if state.opts.obf_profile == "none":
            state.opts.obf_key = ""
            return
        if not state.opts.obf_key:
            state.opts.obf_key = secrets.token_hex(32)
        validate.hex64(state.opts.obf_key)
