from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .links import kcp_args
from .models import (
    CORE_VERSION,
    CORE_VERSION_LATEST,
    ApplyOutcome,
    ClientInfo,
    ProbeResult,
    RemoteConfig,
    ServerOptions,
    ShareInfo,
    SshSettings,
)
from .sshx import MODE_SUDO_PASS, SshClient, SshError, SshOutput, wrap_sudo

PROTO = 3

ERROR_CODES = {
    "bad_arg": "неверные аргументы",
    "needs_root": "нужны права root на сервере",
    "not_installed": "сервер не установлен",
    "unsupported_arch": "архитектура сервера не поддерживается",
    "no_systemd": "на сервере нет systemd",
    "docker_failed": "docker недоступен или упал",
    "download_failed": "не удалось скачать релиз ядра",
    "wg_unsupported": "ядро сервера не поддерживает wireguard",
    "wg_install_failed": "не удалось поднять wireguard",
    "wg_conflict": "конфликт с существующим wireguard",
    "backend_locked": "backend зафиксирован существующей установкой",
    "port_busy": "порт занят на сервере",
    "subnet_conflict": "подсеть пересекается с существующей",
    "subnet_full": "в подсети закончились адреса",
    "host_unknown": "сервер не смог определить свой адрес",
    "exists": "клиент уже существует",
    "not_found": "клиент не найден",
    "owner_protected": "клиента owner удалить нельзя",
    "start_failed": "сервис не запустился",
    "internal": "внутренняя ошибка install.sh",
    "transport": "сбой транспорта до сервера",
    "host_key_changed": "отпечаток сервера изменился",
    "sudo_auth_failed": "sudo требует пароль",
    "sudo_requiretty": "sudo требует tty",
    "proto_mismatch": "версия протокола install.sh не совпадает",
    "unknown": "неизвестная ошибка install.sh",
}


RESET_SCRIPT = """set -u
PREFIX=/opt/free-turn-proxy
CONTAINER=free-turn-proxy
UNIT=free-turn-proxy.service
UNIT_PATH=/etc/systemd/system/free-turn-proxy.service
WG_IFACE=ft-wg0
WG_CONF=/etc/wireguard/ft-wg0.conf
SYSCTL=/etc/sysctl.d/99-free-turn-proxy.conf
say() { printf 'reset %s\\n' "$1"; }
if command -v docker >/dev/null 2>&1 && docker container inspect "$CONTAINER" >/dev/null 2>&1; then
  docker rm -f "$CONTAINER" >/dev/null 2>&1 && say container
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now "$UNIT" >/dev/null 2>&1 && say unit_stopped
  rm -f "$UNIT_PATH"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
fi
rm -f "$UNIT_PATH"
if command -v wg-quick >/dev/null 2>&1; then
  wg-quick down "$WG_IFACE" >/dev/null 2>&1 || true
fi
if command -v ip >/dev/null 2>&1 && ip link show "$WG_IFACE" >/dev/null 2>&1; then
  ip link del "$WG_IFACE" >/dev/null 2>&1 && say interface
fi
if command -v pkill >/dev/null 2>&1; then
  pkill -f "$PREFIX" >/dev/null 2>&1 && say processes
fi
rm -f "$WG_CONF" "$SYSCTL" /usr/local/bin/freeturn
rm -rf "$PREFIX"
say prefix
printf 'reset done\\n'
"""

RESET_LABELS = {
    "container": "контейнер остановлен и удален",
    "unit_stopped": "сервис остановлен и снят с автозапуска",
    "interface": "интерфейс ft-wg0 удален",
    "processes": "процессы ядра завершены",
    "prefix": "каталог установки удален",
}


class ControlError(Exception):
    def __init__(self, message: str, code: str = "internal") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass
class ResetOutcome:
    steps: list[str] = field(default_factory=list)
    response: ControlResponse | None = None
    probe: ProbeResult | None = None


@dataclass
class ControlResponse:
    result: str = "err"
    code: str = ""
    msg: str = ""
    stage: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)
    proto: int = PROTO

    @property
    def ok(self) -> bool:
        return self.result == "ok"

    def raise_for_status(self) -> None:
        if self.ok:
            return
        text = self.msg or ERROR_CODES.get(self.code, self.code) or "неизвестная ошибка"
        if self.stage:
            text = f"{text} (этап {self.stage})"
        raise ControlError(text, self.code or "internal")


def shell_quote(value: object) -> str:
    return shlex.quote(str(value))


def build_argv(name: str, *args: str) -> str:
    parts = [shell_quote(name)]
    for item in args:
        parts.append(shell_quote(item))
    return " ".join(parts)


def apply_argv(opts: ServerOptions) -> list[str]:
    argv = [
        f"--method={opts.method}",
        f"--backend={opts.backend}",
        f"--listen-port={int(opts.listen_port)}",
        f"--mode={opts.mode}",
        f"--obf-profile={opts.obf_profile}",
        f"--version={opts.version}",
    ]
    if opts.host:
        argv.append(f"--host={opts.host}")
    if opts.backend == "external":
        argv.append(f"--connect={opts.connect}")
    else:
        argv.append(f"--wg-port={int(opts.wg_port)}")
        argv.append(f"--wg-net={opts.wg_net}")
    if opts.obf_profile != "none" and opts.obf_key:
        argv.append(f"--obf-key={opts.obf_key}")
    if opts.mode == "tcp":
        argv.extend(kcp_args(opts.kcp))
    return argv


def parse_response(text: str) -> ControlResponse:
    payload = ""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            payload = stripped
    if not payload:
        raise ControlError(text.strip()[:400] or "install.sh не вернул ответ", "transport")
    try:
        raw = json.loads(payload)
    except ValueError:
        raise ControlError(f"ответ не разобран: {payload[:200]}", "transport") from None
    if not isinstance(raw, dict):
        raise ControlError("ответ не является объектом", "transport")
    response = ControlResponse(
        result=str(raw.get("result", "err")),
        code=str(raw.get("code", "")),
        msg=str(raw.get("msg", "")),
        stage=str(raw.get("stage", "")),
        data=raw.get("data") if isinstance(raw.get("data"), dict) else {},
        logs=[str(item) for item in raw.get("logs") or []],
        proto=int(raw.get("proto", 0) or 0),
    )
    if response.proto != PROTO:
        raise ControlError(
            f"install.sh отвечает протоколом {response.proto}, бот ждет {PROTO}",
            "proto_mismatch",
        )
    return response


class ControlClient:
    def __init__(self, cfg: Config, ssh: SshClient | None = None) -> None:
        self.cfg = cfg
        self.script = cfg.require_install_script()
        self.ssh = ssh or SshClient(cfg.connect_timeout, cfg.command_timeout)

    def stdin_payload(self, cfg: SshSettings, body: bytes) -> bytes:
        if cfg.mode == MODE_SUDO_PASS:
            password = (cfg.sudo_password or cfg.password or "").encode("utf-8")
            return password + b"\n" + body
        return body

    def stdin_for(self, cfg: SshSettings) -> bytes:
        return self.stdin_payload(cfg, self.script.encode("utf-8"))

    async def run_script(self, cfg: SshSettings, script: str, timeout: float | None = None) -> SshOutput:
        command = wrap_sudo("bash -s", cfg.mode)
        stdin = self.stdin_payload(cfg, script.encode("utf-8"))
        return await self.ssh.run(cfg, command, stdin=stdin, timeout=timeout or self.cfg.command_timeout)

    async def call(self, cfg: SshSettings, argv: list[str], timeout: float | None = None) -> ControlResponse:
        command = wrap_sudo("bash -s -- " + " ".join(shell_quote(item) for item in argv), cfg.mode)
        out = await self.ssh.run(cfg, command, stdin=self.stdin_for(cfg), timeout=timeout)
        return parse_response(out.text)

    async def connect_check(self, cfg: SshSettings) -> str:
        return await self.ssh.fingerprint(cfg)

    async def detect_mode(self, cfg: SshSettings) -> str:
        probe, mode = await self.ssh.preflight(cfg)
        if probe.code not in {0} and not probe.text:
            raise ControlError("сервер не ответил на проверку прав", "transport")
        return mode

    async def probe(self, cfg: SshSettings) -> ProbeResult:
        response = await self.call(cfg, ["probe"])
        response.raise_for_status()
        return ProbeResult.from_dict(response.data)

    async def apply(self, cfg: SshSettings, opts: ServerOptions, update: bool = False) -> ControlResponse:
        try:
            return await self._apply_once(cfg, opts, update)
        except ControlError as exc:
            if exc.code != "download_failed" or opts.version != CORE_VERSION_LATEST:
                raise
            opts.version = CORE_VERSION
            response = await self._apply_once(cfg, opts, update)
            response.data["fallback"] = True
            response.data["fallback_version"] = CORE_VERSION
            return response

    async def _apply_once(self, cfg: SshSettings, opts: ServerOptions, update: bool = False) -> ControlResponse:
        argv = ["apply", *apply_argv(opts)]
        if update:
            argv.append("--update")
        response = await self.call(cfg, argv, timeout=self.cfg.apply_timeout)
        response.raise_for_status()
        return response

    async def stop(self, cfg: SshSettings) -> ControlResponse:
        response = await self.call(cfg, ["stop"])
        response.raise_for_status()
        return response

    async def restart(self, cfg: SshSettings) -> ControlResponse:
        response = await self.call(cfg, ["restart"])
        response.raise_for_status()
        return response

    async def logs(self, cfg: SshSettings, tail: int = 200) -> list[str]:
        response = await self.call(cfg, ["logs", f"--tail={int(tail)}"])
        response.raise_for_status()
        lines = response.data.get("lines") or []
        return [str(item) for item in lines]

    async def clients(self, cfg: SshSettings) -> tuple[list[ClientInfo], ShareInfo]:
        response = await self.call(cfg, ["client-list"])
        response.raise_for_status()
        raw = response.data.get("clients") or []
        clients = [ClientInfo.from_dict(item) for item in raw if isinstance(item, dict)]
        share_raw = response.data.get("share") or {}
        share = ShareInfo(
            backend=str(share_raw.get("backend", "")),
            host=str(share_raw.get("host", "")),
            port=int(share_raw.get("port", 0) or 0),
            mode=str(share_raw.get("mode", "")),
            obf_profile=str(share_raw.get("obf_profile", "")),
            obf_key=str(share_raw.get("obf_key", "")),
        )
        return clients, share

    def _client_of(self, response: ControlResponse) -> tuple[ClientInfo, str]:
        raw = response.data.get("client") or {}
        info = ClientInfo.from_dict(raw if isinstance(raw, dict) else {})
        return info, str(response.data.get("conf_b64") or "")

    async def client_add(self, cfg: SshSettings, name: str) -> tuple[ClientInfo, str]:
        response = await self.call(cfg, ["client-add", f"--name={name}"])
        response.raise_for_status()
        return self._client_of(response)

    async def client_conf(self, cfg: SshSettings, name: str) -> tuple[ClientInfo, str]:
        response = await self.call(cfg, ["client-conf", f"--name={name}"])
        response.raise_for_status()
        return self._client_of(response)

    async def client_remove(self, cfg: SshSettings, name: str) -> ControlResponse:
        response = await self.call(cfg, ["client-remove", f"--name={name}"])
        response.raise_for_status()
        return response

    async def purge(self, cfg: SshSettings) -> list[str]:
        try:
            await self.uninstall(cfg, target="all", purge=True)
        except ControlError as exc:
            if exc.code == "not_installed":
                return []
            return [f"удаление через install.sh: {exc.message}"]
        return ["установка удалена через install.sh"]

    async def sweep(self, cfg: SshSettings) -> list[str]:
        try:
            out = await self.run_script(cfg, RESET_SCRIPT, timeout=self.cfg.apply_timeout)
        except SshError as exc:
            raise ControlError(f"очистка сервера не выполнена: {exc.message}", "transport") from None
        steps: list[str] = []
        for line in out.text.splitlines():
            token = line.strip()
            if token.startswith("reset "):
                name = token.split(" ", 1)[1].strip()
                if name == "done":
                    continue
                steps.append(RESET_LABELS.get(name, name))
        return steps

    async def hard_reset(
        self,
        cfg: SshSettings,
        opts: ServerOptions,
        on_step: Any = None,
    ) -> ResetOutcome:
        await _note(on_step, "удаление установки через install.sh")
        steps = await self.purge(cfg)
        await _note(on_step, "очистка процессов, интерфейсов и файлов")
        steps.extend(await self.sweep(cfg))
        for step in steps:
            await _note(on_step, step)
        await _note(on_step, "проверка чистоты сервера")
        state = await self.probe(cfg)
        if state.installed:
            raise ControlError("остатки установки не удалены, установка отменена", "internal")
        await _note(on_step, "установка ядра " + str(opts.version))
        response = await self.apply(cfg, opts, update=True)
        await _note(on_step, "проверка состояния после установки")
        probe = await self.probe(cfg)
        if not probe.installed:
            raise ControlError("ядро не установилось после очистки", "start_failed")
        return ResetOutcome(steps=steps, response=response, probe=probe)

    async def uninstall(self, cfg: SshSettings, target: str = "all", purge: bool = True) -> ControlResponse:
        argv = ["uninstall", f"--target={target}"]
        if purge:
            argv.append("--purge")
        response = await self.call(cfg, argv, timeout=self.cfg.apply_timeout)
        response.raise_for_status()
        return response


async def _note(on_step: Any, text: str) -> None:
    if on_step is None:
        return
    result = on_step(text)
    if hasattr(result, "__await__"):
        await result


def decode_conf(payload: str) -> str:
    import base64

    if not payload:
        return ""
    try:
        return base64.b64decode(payload).decode("utf-8", "replace")
    except (ValueError, UnicodeDecodeError):
        return ""


def outcome_of(response: ControlResponse) -> ApplyOutcome:
    owner = response.data.get("owner") or {}
    return ApplyOutcome(
        owner_client_id=str(owner.get("client_id", "")),
        owner_conf=decode_conf(str(owner.get("conf_b64", ""))),
        obf_key=str(response.data.get("obf_key", "")),
        link=str(owner.get("link", "")),
        needs_restart=bool(response.data.get("needs_restart", False)),
        owner_pub=str(owner.get("pub", "")),
    )


def remote_config_of(data: dict[str, Any]) -> RemoteConfig | None:
    return RemoteConfig.from_dict(data.get("config")) if data else None


def missing_binary_error(exc: SshError) -> bool:
    return "No such file" in exc.message
