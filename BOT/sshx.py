from __future__ import annotations

import asyncio
from dataclasses import dataclass

import asyncssh

from .models import AUTH_KEY, SshSettings

PREFLIGHT = (
    "printf '%s\\n' \"$(id -u)\"; "
    "if sudo -n true 2>/dev/null; then printf '%s\\n' SUDO_NOPASS; "
    "elif sudo -n -l >/dev/null 2>&1; then printf '%s\\n' SUDO_NOPASS; "
    "else printf '%s\\n' SUDO_PASS; fi"
)

MODE_ROOT = "ROOT"
MODE_SUDO_NOPASS = "SUDO_NOPASS"
MODE_SUDO_PASS = "SUDO_PASS"


class SshError(Exception):
    def __init__(self, message: str, host_key_changed: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.host_key_changed = host_key_changed


@dataclass
class SshOutput:
    text: str
    code: int = 0


def wrap_sudo(command: str, mode: str) -> str:
    if mode == MODE_SUDO_NOPASS:
        return "sudo -n " + command
    if mode == MODE_SUDO_PASS:
        return "sudo -k -S -p '' " + command
    return command


class SshClient:
    def __init__(self, connect_timeout: float = 20.0, command_timeout: float = 300.0) -> None:
        self.connect_timeout = float(connect_timeout)
        self.command_timeout = float(command_timeout)

    def _keys(self, cfg: SshSettings) -> list[object]:
        if cfg.auth != AUTH_KEY or not cfg.key:
            return []
        try:
            return [asyncssh.import_private_key(cfg.key, cfg.passphrase or None)]
        except (asyncssh.KeyImportError, ValueError) as exc:
            raise SshError(f"не удалось разобрать приватный ключ: {exc}") from None

    async def _connect(self, cfg: SshSettings) -> asyncssh.SSHClientConnection:
        kwargs: dict[str, object] = {
            "host": cfg.host,
            "port": int(cfg.port),
            "username": cfg.user,
            "known_hosts": None,
            "connect_timeout": self.connect_timeout,
            "login_timeout": self.connect_timeout,
            "agent_path": None,
        }
        keys = self._keys(cfg)
        if keys:
            kwargs["client_keys"] = keys
            kwargs["preferred_auth"] = "publickey"
        else:
            kwargs["password"] = cfg.password
            kwargs["preferred_auth"] = "password,keyboard-interactive"
        try:
            return await asyncssh.connect(**kwargs)
        except asyncssh.PermissionDenied:
            raise SshError("сервер отклонил вход, проверьте пользователя и пароль либо ключ") from None
        except (asyncssh.DisconnectError, ConnectionRefusedError, OSError) as exc:
            raise SshError(f"нет связи с сервером: {exc}") from None
        except asyncio.TimeoutError:
            raise SshError("истекло время ожидания подключения") from None
        except asyncssh.Error as exc:
            raise SshError(f"ошибка ssh: {exc}") from None

    async def run(self, cfg: SshSettings, command: str, stdin: bytes | None = None, timeout: float | None = None) -> SshOutput:
        conn = await self._connect(cfg)
        try:
            full = "exec 2>&1\n" + command
            limit = float(timeout or self.command_timeout)
            try:
                result = await conn.run(full, input=stdin, check=False, encoding=None, timeout=limit)
            except asyncio.TimeoutError:
                raise SshError(f"команда не завершилась за {int(limit)} секунд") from None
            except asyncssh.Error as exc:
                raise SshError(f"ошибка выполнения: {exc}") from None
            out = result.stdout or b""
            err = result.stderr or b""
            if isinstance(out, str):
                text = out
            else:
                text = out.decode("utf-8", "replace")
            if isinstance(err, bytes) and err:
                text += err.decode("utf-8", "replace")
            elif isinstance(err, str) and err:
                text += err
            return SshOutput(text=text.strip(), code=int(result.exit_status or 0))
        finally:
            conn.close()
            try:
                await conn.wait_closed()
            except (asyncssh.Error, OSError):
                pass

    async def fingerprint(self, cfg: SshSettings) -> str:
        conn = await self._connect(cfg)
        try:
            key = conn.get_server_host_key()
            if key is None:
                raise SshError("сервер не предъявил ключ")
            return key.get_fingerprint("sha256")
        finally:
            conn.close()
            try:
                await conn.wait_closed()
            except (asyncssh.Error, OSError):
                pass

    async def preflight(self, cfg: SshSettings) -> tuple[SshOutput, str]:
        probe = await self.run(cfg, PREFLIGHT, timeout=min(self.command_timeout, 60))
        return probe, fingerprint_mode(probe.text)


def fingerprint_mode(text: str) -> str:
    euid = -1
    mode = MODE_SUDO_PASS
    for line in text.splitlines():
        token = line.strip()
        if token.isdigit():
            euid = int(token)
        elif token == MODE_SUDO_NOPASS:
            mode = MODE_SUDO_NOPASS
    if euid == 0:
        return MODE_ROOT
    return mode
