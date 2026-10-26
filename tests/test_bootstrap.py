from __future__ import annotations

import asyncio
import io
import tarfile
from pathlib import Path

import pytest

from BOT import bootstrap
from BOT.bootstrap import (
    CHECK_SCRIPT,
    ENV_FILE,
    INSTALL_DIR,
    REFUSAL,
    UNIT_PATH,
    BootstrapError,
    BootstrapPlan,
    check_plan,
    check_root,
    format_checks,
    install_script,
    parse_args,
    payload_archive,
    plan_from,
    unit_text,
    verify_admin,
)
from BOT.sshx import SshOutput


def plan(**kw) -> BootstrapPlan:
    base = dict(host="203.0.113.10", user="root", password="hunter2", token="123:ABC", api_id=12345, api_hash="0" * 32, admin_id=777)
    base.update(kw)
    return BootstrapPlan(**base)


def test_root_check_accepts_root() -> None:
    assert check_root(0) is None


def test_root_check_refuses_user() -> None:
    with pytest.raises(BootstrapError) as info:
        check_root(1000)
    assert info.value.message == REFUSAL
    assert "root" in info.value.message


def test_verify_admin_empty_expected_claims() -> None:
    ok, admin, message = verify_admin(4242, 0)
    assert ok is True
    assert admin == 4242
    assert "закреплен" in message


def test_verify_admin_match() -> None:
    ok, admin, message = verify_admin(777, 777)
    assert ok is True
    assert admin == 777
    assert "совпал" in message


def test_verify_admin_mismatch() -> None:
    ok, admin, message = verify_admin(1, 777)
    assert ok is False
    assert admin == 777
    assert "не совпадает" in message


def test_verify_admin_missing_id() -> None:
    ok, admin, message = verify_admin(0, 777)
    assert ok is False
    assert admin == 777
    assert "не получен" in message


def test_parse_args_flags() -> None:
    args = parse_args(["--ssh-host", "1.2.3.4", "--admin-id=5", "--dev"])
    assert args["ssh_host"] == "1.2.3.4"
    assert args["admin_id"] == "5"
    assert args["dev"] is True


def test_plan_from_args() -> None:
    args = parse_args(["--host", "h", "--port", "2222", "--token", "t", "--api-id", "1", "--api-hash", "x", "--admin-id", "9"])
    built = plan_from(args)
    assert built.host == "h"
    assert built.port == 2222
    assert built.token == "t"
    assert built.api_id == 1
    assert built.admin_id == 9
    assert built.install_dir == INSTALL_DIR


def test_plan_from_defaults() -> None:
    built = plan_from({})
    assert built.port == 22
    assert built.user == "root"
    assert built.dev is False
    assert built.state_dir == bootstrap.STATE_DIR


def test_settings_uses_password_auth() -> None:
    cfg = plan().settings()
    assert cfg.auth == "PASSWORD"
    assert cfg.mode == "ROOT"
    assert cfg.host == "203.0.113.10"


def test_settings_uses_key_auth() -> None:
    cfg = plan(key="-----BEGIN-----").settings()
    assert cfg.auth == "SSH_KEY"
    assert cfg.key


def test_env_text_contains_all_keys() -> None:
    text = plan().env_text()
    for token in ("BOT_TOKEN=123:ABC", "API_ID=12345", "ADMIN_ID=777", "OBHOD_STATE_DIR=", "OBHOD_INSTALL_SCRIPT="):
        assert token in text


def test_install_script_deps_phase() -> None:
    script = install_script(plan(), "deps")
    assert "set -euo pipefail" in script
    assert 'if [ "$(id -u)" != "0" ]' in script
    assert 'command -v "$PY"' in script
    assert "venv" in script
    assert "requirements.txt" in script
    assert "OBHODENV" not in script


def test_install_script_finalize_phase() -> None:
    script = install_script(plan(), "finalize")
    assert "OBHODENV" in script
    assert "BOT_TOKEN=123:ABC" in script
    assert UNIT_PATH in script
    assert "systemctl restart obhod.service" in script
    assert "systemd недоступен" in script


def test_install_script_has_no_comments() -> None:
    for phase in ("deps", "finalize"):
        for line in install_script(plan(), phase).splitlines():
            assert not line.strip().startswith("#")


def test_unit_text() -> None:
    body = unit_text(plan())
    assert "[Service]" in body
    assert "ExecStart=/opt/obhod/.venv/bin/python -m BOT" in body
    assert f"EnvironmentFile={ENV_FILE}" in body
    assert "WantedBy=multi-user.target" in body


def test_payload_archive_contains_bot() -> None:
    blob = payload_archive()
    assert len(blob) > 1000
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as bundle:
        names = bundle.getnames()
    assert any(name.startswith("BOT/") for name in names)
    assert any(name == "Storage/install.sh" for name in names)
    assert "requirements.txt" in names
    assert not any("__pycache__" in name for name in names)
    assert not any(name.startswith("tests/") for name in names)


def test_payload_archive_is_deterministic_enough() -> None:
    first = payload_archive()
    second = payload_archive()
    assert len(first) == len(second)


def _tiny_archive() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        data = b"ok"
        info = tarfile.TarInfo("marker.txt")
        info.size = len(data)
        bundle.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class FakeSsh:
    def __init__(self, code: int = 0, text: str = "готово") -> None:
        self.code = code
        self.text = text
        self.commands: list[str] = []
        self.stdins: list[bytes] = []

    async def run(self, cfg, command, stdin=None, timeout=None):
        self.commands.append(command)
        self.stdins.append(stdin or b"")
        return SshOutput(text=self.text, code=self.code)


def test_bootstrap_happy_path() -> None:
    ssh = FakeSsh()
    plan_value = plan()
    steps = asyncio.run(bootstrap.bootstrap(plan_value, ssh=ssh, payload=b"payload"))
    assert "проверка root пройдена" in steps
    assert "идентификатор совпал" in steps
    assert steps[-1].startswith("дальнейшие шаги")
    assert len(ssh.commands) == 4
    assert "tar -xzf -" in ssh.commands[1]
    assert ssh.stdins[1] == b"payload"


def test_bootstrap_requires_host() -> None:
    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(host=""), ssh=FakeSsh(), payload=b"x"))
    assert "адрес" in info.value.message


def test_bootstrap_requires_token() -> None:
    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(token=""), ssh=FakeSsh(), payload=b"x"))
    assert "токен" in info.value.message


def test_bootstrap_fails_on_push_error() -> None:
    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(), ssh=FakeSsh(code=1, text="нет места"), payload=b"x"))
    assert "нет места" in info.value.message


def test_bootstrap_blocks_on_admin_mismatch() -> None:
    ssh = FakeSsh()

    async def confirm() -> int:
        return 5

    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(), ssh=ssh, payload=b"x", confirm=confirm))
    assert "не совпадает" in info.value.message
    assert len(ssh.commands) == 3


def test_bootstrap_claims_admin_when_empty() -> None:
    ssh = FakeSsh()

    async def confirm() -> int:
        return 1234

    plan_value = plan(admin_id=0)
    steps = asyncio.run(bootstrap.bootstrap(plan_value, ssh=ssh, payload=b"x", confirm=confirm))
    assert plan_value.admin_id == 1234
    assert "администратор закреплен" in steps


def test_bootstrap_sync_confirm() -> None:
    ssh = FakeSsh()
    steps = asyncio.run(bootstrap.bootstrap(plan(admin_id=0), ssh=ssh, payload=b"x", confirm=lambda: 55))
    assert steps
    assert ssh.commands


def test_bootstrap_reports_steps() -> None:
    seen: list[str] = []
    asyncio.run(bootstrap.bootstrap(plan(), ssh=FakeSsh(), payload=b"x", on_step=seen.append))
    assert len(seen) == 7
    assert seen[0] == "проверка root пройдена"


def test_bootstrap_propagates_ssh_error() -> None:
    from BOT.sshx import SshError

    class BrokenSsh:
        async def run(self, cfg, command, stdin=None, timeout=None):
            raise SshError("нет связи")

    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(), ssh=BrokenSsh(), payload=b"x"))
    assert "нет связи" in info.value.message


def test_bootstrap_finalize_error() -> None:
    class HalfSsh(FakeSsh):
        def __init__(self) -> None:
            FakeSsh.__init__(self)
            self.count = 0

        async def run(self, cfg, command, stdin=None, timeout=None):
            self.count += 1
            self.commands.append(command)
            self.stdins.append(stdin or b"")
            if self.count > 3:
                return SshOutput(text="служба не поднялась", code=1)
            return SshOutput(text="ok", code=0)

    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(), ssh=HalfSsh(), payload=b"x"))
    assert "служба" in info.value.message


def test_run_refuses_without_root(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 1000)
    code = bootstrap.run(["--ssh-host", "1.2.3.4"])
    assert code == 1
    assert REFUSAL in capsys.readouterr().err


def test_payload_items_cover_repo() -> None:
    root = Path(__file__).resolve().parent.parent
    for name in bootstrap.PAYLOAD_ITEMS:
        assert (root / name).exists(), name


def test_run_script_true_via_asyncssh(tmp_path: Path) -> None:
    import asyncssh

    from BOT.models import SshSettings
    from BOT.sshx import SshClient

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username: str) -> bool:
            return True

        def password_auth_supported(self) -> bool:
            return True

        def validate_password(self, username: str, password: str) -> bool:
            return password == "hunter2"

    async def handle(process: asyncssh.SSHServerProcess) -> None:
        command = process.command or ""
        try:
            body = await asyncio.wait_for(process.stdin.read(), 3)
        except asyncio.TimeoutError:
            body = b""
        payload = body or b""
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        child = await asyncio.create_subprocess_shell(
            command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await child.communicate(payload)
        process.stdout.write(out)
        try:
            await process.stdout.drain()
        except (ConnectionError, OSError):
            pass
        await asyncio.sleep(0.05)
        process.exit(child.returncode or 0)

    import threading

    key = asyncssh.generate_private_key("ssh-ed25519")
    state: dict[str, object] = {}
    ready = threading.Event()

    def worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def main() -> None:
            closure = asyncio.Event()
            server = await asyncssh.create_server(
                Server,
                "127.0.0.1",
                0,
                server_host_keys=[key],
                process_factory=handle,
                encoding=None,
            )
            state["port"] = server.get_port()
            state["closure"] = closure
            ready.set()
            await closure.wait()
            server.close()
            await server.wait_closed()

        loop.run_until_complete(main())
        loop.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    assert ready.wait(30)
    try:
        cfg = SshSettings(host="127.0.0.1", port=int(state["port"]), user="tester", auth="PASSWORD", password="hunter2", mode="ROOT")
        client = SshClient(connect_timeout=10, command_timeout=60)
        out = asyncio.run(bootstrap.run_script(client, cfg, "printf '%s\\n' готово\n"))
        assert out.code == 0
        assert "готово" in out.text

        class Wrap:
            async def run(self, cfg_inner, command, stdin=None, timeout=None):
                return await client.run(cfg_inner, command, stdin=stdin, timeout=timeout)

        target = tmp_path / "opt"
        blob = payload_archive() if False else _tiny_archive()
        files = asyncio.run(
            bootstrap.push_files(Wrap(), cfg, blob, plan(install_dir=str(target), state_dir=str(tmp_path / "state")))
        )
        assert files.code == 0
        assert (target / "marker.txt").read_text(encoding="utf-8") == "ok"
    finally:
        closure = state.get("closure")
        if isinstance(closure, asyncio.Event):
            closure.set()
        thread.join(timeout=10)


CHECK_OK = (
    "root=yes\n"
    "python=3.13.1\n"
    "systemd=yes\n"
    "tar=yes\n"
    "disk=8388608\n"
    "github=yes\n"
    "telegram=yes\n"
    "check done\n"
)


def test_check_script_has_no_comments() -> None:
    assert "#" not in CHECK_SCRIPT


def test_check_script_runs_bash_syntax() -> None:
    import subprocess

    result = subprocess.run(["bash", "-n"], input=CHECK_SCRIPT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_check_plan_reports_success() -> None:
    checks = asyncio.run(check_plan(FakeSsh(text=CHECK_OK), plan().settings(), plan()))
    assert [item[0] for item in checks] == [
        "root на сервере",
        "python3",
        "systemd",
        "tar",
        "свободное место",
        "github с сервера",
        "telegram с сервера",
    ]
    assert all(item[1] for item in checks)


def test_check_plan_flags_missing_python() -> None:
    text = CHECK_OK.replace("python=3.13.1", "python=none")
    checks = asyncio.run(check_plan(FakeSsh(text=text), plan().settings(), plan()))
    python = [item for item in checks if item[0] == "python3"][0]
    assert python[1] is False
    assert python[2] == "none"


def test_check_plan_flags_root_and_disk() -> None:
    text = CHECK_OK.replace("root=yes", "root=no").replace("disk=8388608", "disk=1024")
    checks = asyncio.run(check_plan(FakeSsh(text=text), plan().settings(), plan()))
    root = [item for item in checks if item[0] == "root на сервере"][0]
    disk = [item for item in checks if item[0] == "свободное место"][0]
    assert root[1] is False
    assert disk[1] is False
    assert "ГБ" in disk[2]


def test_format_checks_lines() -> None:
    lines = format_checks([("root на сервере", True, "yes"), ("python3", False, "none")])
    assert lines == ["ok root на сервере: yes", "нет python3: none"]


def test_check_only_returns_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    ssh = FakeSsh(text=CHECK_OK)
    code = asyncio.run(bootstrap.check_only(plan(), ssh=ssh))
    assert code == 0
    assert "bash -s" in ssh.commands[0]


def test_check_only_returns_one_for_missing_python() -> None:
    ssh = FakeSsh(text=CHECK_OK.replace("python=3.13.1", "python=none"))
    code = asyncio.run(bootstrap.check_only(plan(), ssh=ssh))
    assert code == 1


def test_check_only_requires_host() -> None:
    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.check_only(plan(host=""), ssh=FakeSsh(text=CHECK_OK)))
    assert "адрес" in info.value.message


def test_parse_args_check_flag() -> None:
    args = parse_args(["--ssh-host", "1.2.3.4", "--check"])
    assert args["check"] is True
    assert plan_from(args).check is True
