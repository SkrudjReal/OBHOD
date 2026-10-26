from __future__ import annotations

import json
import shutil
import subprocess
from collections import deque
from pathlib import Path
from typing import Any

import pytest

from BOT.control import (
    RESET_LABELS,
    RESET_SCRIPT,
    ControlClient,
    ControlError,
    ResetOutcome,
    apply_argv,
)
from BOT.models import CORE_VERSION, CORE_VERSION_LATEST, ServerOptions, SshSettings
from BOT.sshx import MODE_ROOT, MODE_SUDO_PASS, SshOutput
from tests.fakes import make_config


def ok(data: dict[str, Any] | None = None) -> str:
    return json.dumps({"proto": 3, "result": "ok", "data": data or {}})


def err(code: str, msg: str = "сбой") -> str:
    return json.dumps({"proto": 3, "result": "err", "code": code, "msg": msg})


PROBE_EMPTY = ok({"installed": False, "running": False, "euid": 0, "arch": "x86_64"})
PROBE_INSTALLED = ok(
    {
        "installed": True,
        "running": True,
        "euid": 0,
        "arch": "x86_64",
        "method": "docker",
        "version": "4.1.0",
        "config": {"method": "docker", "backend": "new", "listen_port": 56000, "version": "4.1.0"},
    }
)
APPLY_OK = ok(
    {
        "owner": {"client_id": "a" * 32, "pub": "cHVi", "conf_b64": "", "link": "freeturn://abc"},
        "obf_key": "b" * 64,
        "needs_restart": False,
    }
)
SWEEP_OUT = (
    "reset container\n"
    "reset unit_stopped\n"
    "reset interface\n"
    "reset processes\n"
    "reset prefix\n"
    "reset done\n"
)


class FakeSsh:
    def __init__(self, replies: list[str] | None = None, sweep: str = SWEEP_OUT) -> None:
        self.replies: deque[str] = deque(replies or [])
        self.sweep = sweep
        self.calls: list[tuple[str, bytes]] = []

    async def run(self, cfg: Any, command: str, stdin: bytes | None = None, timeout: float | None = None) -> SshOutput:
        self.calls.append((command, stdin or b""))
        if "bash -s --" in command:
            text = self.replies.popleft() if self.replies else ok()
            return SshOutput(text=text, code=0)
        return SshOutput(text=self.sweep, code=0)

    def commands(self) -> list[str]:
        return [command for command, _ in self.calls]

    def argv(self) -> list[str]:
        return [command for command in self.commands() if "bash -s --" in command]

    def stdin_of(self, index: int) -> str:
        return self.calls[index][1].decode("utf-8")

    def sweeps(self) -> list[str]:
        return [command for command in self.commands() if command.rstrip() == "bash -s"]


def settings() -> SshSettings:
    return SshSettings(host="203.0.113.10", user="root", password="hunter2", mode=MODE_ROOT)


def client(tmp_path: Path, ssh: FakeSsh) -> ControlClient:
    return ControlClient(make_config(tmp_path), ssh=ssh)


def opts() -> ServerOptions:
    return ServerOptions(obf_key="a" * 64)


def test_reset_script_has_no_comment_lines() -> None:
    for line in RESET_SCRIPT.splitlines():
        assert not line.strip().startswith("#"), line


def test_reset_script_structure() -> None:
    assert "docker rm -f" in RESET_SCRIPT
    assert "systemctl disable --now" in RESET_SCRIPT
    assert "ip link del" in RESET_SCRIPT
    assert "pkill -f" in RESET_SCRIPT
    assert "rm -rf \"$PREFIX\"" in RESET_SCRIPT
    assert RESET_SCRIPT.rstrip().endswith("printf 'reset done\\n'")


def test_reset_script_is_valid_bash(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    assert bash
    target = tmp_path / "reset.sh"
    target.write_text(RESET_SCRIPT, encoding="utf-8")
    result = subprocess.run([bash, "-n", str(target)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_reset_script_runs_without_touching_the_shell(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    assert bash
    target = tmp_path / "reset.sh"
    target.write_text(RESET_SCRIPT, encoding="utf-8")
    result = subprocess.run([bash, str(target)], capture_output=True, text=True, timeout=120)
    assert "reset done" in result.stdout


def test_reset_labels_cover_every_marker() -> None:
    for marker in ("container", "unit_stopped", "interface", "processes", "prefix"):
        assert marker in RESET_LABELS


def test_sweep_parses_markers(tmp_path: Path) -> None:
    ssh = FakeSsh()
    ctl = client(tmp_path, ssh)
    steps = __import__("asyncio").run(ctl.sweep(settings()))
    assert steps == [RESET_LABELS[name] for name in ("container", "unit_stopped", "interface", "processes", "prefix")]
    assert ssh.commands() == ["bash -s"]


def test_sweep_ignores_foreign_output(tmp_path: Path) -> None:
    ssh = FakeSsh(sweep="hello\nreset unknown_marker\nreset done\n")
    ctl = client(tmp_path, ssh)
    steps = __import__("asyncio").run(ctl.sweep(settings()))
    assert steps == ["unknown_marker"]


def test_sweep_transport_failure(tmp_path: Path) -> None:
    class Broken(FakeSsh):
        async def run(self, cfg: Any, command: str, stdin: bytes | None = None, timeout: float | None = None) -> SshOutput:
            raise __import__("BOT.sshx", fromlist=["SshError"]).SshError("нет связи")

    ctl = client(tmp_path, Broken())
    with pytest.raises(ControlError) as exc:
        __import__("asyncio").run(ctl.sweep(settings()))
    assert exc.value.code == "transport"


def test_sweep_uses_sudo_password_prefix(tmp_path: Path) -> None:
    ssh = FakeSsh()
    ctl = client(tmp_path, ssh)
    cfg = settings()
    cfg.mode = MODE_SUDO_PASS
    cfg.sudo_password = "topsecret"
    __import__("asyncio").run(ctl.sweep(cfg))
    assert ssh.calls[0][0] == "sudo -k -S -p '' bash -s"
    assert ssh.calls[0][1].split(b"\n", 1)[0] == b"topsecret"
    assert ssh.calls[0][1].split(b"\n", 1)[1].decode().startswith("set -u")


def test_hard_reset_full_sequence(tmp_path: Path) -> None:
    ssh = FakeSsh([ok(), PROBE_EMPTY, APPLY_OK, PROBE_INSTALLED])
    ctl = client(tmp_path, ssh)
    notes: list[str] = []

    async def step(text: str) -> None:
        notes.append(text)

    outcome: ResetOutcome = __import__("asyncio").run(ctl.hard_reset(settings(), opts(), on_step=step))
    argv = ssh.argv()
    assert len(ssh.sweeps()) == 1
    assert ssh.stdin_of(1).startswith("set -u")
    assert ssh.stdin_of(0).startswith("#!/usr/bin/env bash")
    assert argv[0].startswith("bash -s -- uninstall --target=all --purge")
    assert argv[1] == "bash -s -- probe"
    assert argv[2].startswith("bash -s -- apply ")
    assert "--update" in argv[2]
    assert f"--version={CORE_VERSION}" in argv[2]
    assert argv[3] == "bash -s -- probe"
    assert outcome.probe is not None and outcome.probe.installed
    assert outcome.response is not None and outcome.response.ok
    assert notes[0] == "удаление установки через install.sh"
    assert "очистка процессов, интерфейсов и файлов" in notes
    assert RESET_LABELS["interface"] in notes
    assert notes[-1] == "проверка состояния после установки"


def test_hard_reset_stops_when_leftovers_remain(tmp_path: Path) -> None:
    ssh = FakeSsh([ok(), PROBE_INSTALLED])
    ctl = client(tmp_path, ssh)
    with pytest.raises(ControlError) as exc:
        __import__("asyncio").run(ctl.hard_reset(settings(), opts()))
    assert exc.value.code == "internal"
    assert "остатки" in exc.value.message
    assert not any("--update" in command for command in ssh.argv())


def test_hard_reset_continues_when_purge_reports_not_installed(tmp_path: Path) -> None:
    ssh = FakeSsh([err("not_installed", "сервер не установлен"), PROBE_EMPTY, APPLY_OK, PROBE_INSTALLED])
    ctl = client(tmp_path, ssh)
    outcome = __import__("asyncio").run(ctl.hard_reset(settings(), opts()))
    assert outcome.steps == [RESET_LABELS[name] for name in ("container", "unit_stopped", "interface", "processes", "prefix")]


def test_hard_reset_keeps_going_after_purge_error(tmp_path: Path) -> None:
    ssh = FakeSsh([err("start_failed", "сервис не остановился"), PROBE_EMPTY, APPLY_OK, PROBE_INSTALLED])
    ctl = client(tmp_path, ssh)
    outcome = __import__("asyncio").run(ctl.hard_reset(settings(), opts()))
    assert "удаление через install.sh: сервис не остановился" in outcome.steps


def test_hard_reset_fails_when_core_does_not_come_back(tmp_path: Path) -> None:
    ssh = FakeSsh([ok(), PROBE_EMPTY, APPLY_OK, PROBE_EMPTY])
    ctl = client(tmp_path, ssh)
    with pytest.raises(ControlError) as exc:
        __import__("asyncio").run(ctl.hard_reset(settings(), opts()))
    assert exc.value.code == "start_failed"


def test_hard_reset_uses_pinned_version(tmp_path: Path) -> None:
    ssh = FakeSsh([ok(), PROBE_EMPTY, APPLY_OK, PROBE_INSTALLED])
    ctl = client(tmp_path, ssh)
    custom = ServerOptions(obf_key="a" * 64, version="v4.0.3")
    __import__("asyncio").run(ctl.hard_reset(settings(), custom))
    assert "--version=v4.0.3" in ssh.argv()[-2]


def test_hard_reset_apply_argv_matches_client(tmp_path: Path) -> None:
    ssh = FakeSsh([ok(), PROBE_EMPTY, APPLY_OK, PROBE_INSTALLED])
    ctl = client(tmp_path, ssh)
    __import__("asyncio").run(ctl.hard_reset(settings(), opts()))
    apply_command = ssh.argv()[-2]
    for token in apply_argv(opts()):
        assert token in apply_command
    assert apply_command.rstrip().endswith("--update")


def test_hard_reset_falls_back_to_pinned_version(tmp_path: Path) -> None:
    ssh = FakeSsh([ok(), PROBE_EMPTY, err("download_failed", "нет сети"), APPLY_OK, PROBE_INSTALLED])
    ctl = client(tmp_path, ssh)
    custom = ServerOptions(obf_key="a" * 64, version=CORE_VERSION_LATEST)
    outcome = __import__("asyncio").run(ctl.hard_reset(settings(), custom))
    attempts = [command for command in ssh.argv() if command.rstrip().endswith("--update")]
    assert len(attempts) == 2
    assert "--version=" + CORE_VERSION_LATEST in attempts[0]
    assert "--version=" + CORE_VERSION in attempts[1]
    assert outcome.response.data["fallback"] is True
    assert outcome.response.data["fallback_version"] == CORE_VERSION


def test_hard_reset_fallback_keeps_probe_gate(tmp_path: Path) -> None:
    ssh = FakeSsh([ok(), PROBE_EMPTY, err("download_failed", "нет сети"), APPLY_OK, ok({"installed": False})])
    ctl = client(tmp_path, ssh)
    custom = ServerOptions(obf_key="a" * 64, version=CORE_VERSION_LATEST)
    with pytest.raises(ControlError) as info:
        __import__("asyncio").run(ctl.hard_reset(settings(), custom))
    assert info.value.code == "start_failed"
