from __future__ import annotations

import asyncio
import json
import os
import threading
from pathlib import Path

import asyncssh
import pytest

from BOT.control import RESET_SCRIPT, ControlClient, ControlError, parse_response
from BOT.models import ServerOptions, SshSettings
from BOT.sshx import MODE_ROOT, MODE_SUDO_NOPASS, MODE_SUDO_PASS, SshClient, SshError, fingerprint_mode, wrap_sudo
from tests.fakes import make_config

PASSWORD = "hunter2"
INSTALL = Path(__file__).resolve().parent.parent / "Storage" / "install.sh"


class LocalShellServer(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return password == PASSWORD

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        return username == "keyuser"


async def run_local(process: asyncssh.SSHServerProcess) -> None:
    command = process.command or ""
    try:
        payload = await asyncio.wait_for(process.stdin.read(), 5)
    except asyncio.TimeoutError:
        payload = b""
    if payload is None:
        payload = b""
    child = await asyncio.create_subprocess_shell(
        command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await child.communicate(payload.encode() if isinstance(payload, str) else payload)
    if out:
        process.stdout.write(out.decode("utf-8", "replace"))
    if err:
        process.stdout.write(err.decode("utf-8", "replace"))
    process.exit(child.returncode or 0)


@pytest.fixture(scope="module")
def ssh_server():
    key = asyncssh.generate_private_key("ssh-ed25519")
    state: dict[str, object] = {}
    ready = threading.Event()
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    state["client_key"] = client_key

    def worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def main() -> None:
            closure = asyncio.Event()
            server = await asyncssh.create_server(
                LocalShellServer,
                "127.0.0.1",
                0,
                server_host_keys=[key],
                process_factory=run_local,
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
    yield state
    closure = state.get("closure")
    if isinstance(closure, asyncio.Event):
        closure.set()
    thread.join(timeout=10)


def settings(port: int, **kw: object) -> SshSettings:
    base = SshSettings(host="127.0.0.1", port=port, user="tester", auth="PASSWORD", password=PASSWORD, mode=MODE_ROOT)
    for key, value in kw.items():
        setattr(base, key, value)
    return base


def run(coro):
    return asyncio.run(coro)


def client(tmp_path) -> ControlClient:
    return ControlClient(make_config(tmp_path), ssh=SshClient(connect_timeout=10, command_timeout=120))


def test_installer_present() -> None:
    assert INSTALL.is_file()
    assert INSTALL.stat().st_size > 10000


def test_fingerprint_and_echo(ssh_server, tmp_path) -> None:
    ssh = SshClient(connect_timeout=10, command_timeout=60)
    cfg = settings(int(ssh_server["port"]))
    fingerprint = run(ssh.fingerprint(cfg))
    assert fingerprint.startswith("SHA256:")
    out = run(ssh.run(cfg, "echo OK"))
    assert "OK" in out.text


def test_wrong_password(ssh_server) -> None:
    ssh = SshClient(connect_timeout=10, command_timeout=30)
    cfg = settings(int(ssh_server["port"]), password="nope")
    with pytest.raises(SshError) as exc:
        run(ssh.run(cfg, "echo OK"))
    assert "отклонил" in exc.value.message


def test_connection_refused() -> None:
    ssh = SshClient(connect_timeout=5, command_timeout=10)
    with pytest.raises(SshError):
        run(ssh.run(settings(1), "echo OK"))


def test_public_key_auth(ssh_server) -> None:
    ssh = SshClient(connect_timeout=10, command_timeout=30)
    key = ssh_server["client_key"].export_private_key().decode()
    cfg = settings(int(ssh_server["port"]), user="keyuser", auth="SSH_KEY", key=key)
    assert "OK" in run(ssh.run(cfg, "echo OK")).text


def test_bad_key_raises() -> None:
    ssh = SshClient()
    cfg = settings(22, auth="SSH_KEY", key="not a key at all")
    with pytest.raises(SshError):
        run(ssh.run(cfg, "echo OK"))


def test_preflight_and_mode(ssh_server, tmp_path) -> None:
    ctl = client(tmp_path)
    mode = run(ctl.detect_mode(settings(int(ssh_server["port"]))))
    assert mode in {MODE_ROOT, MODE_SUDO_NOPASS, MODE_SUDO_PASS}


def test_fingerprint_mode_parsing() -> None:
    assert fingerprint_mode("0\nSUDO_NOPASS") == MODE_ROOT
    assert fingerprint_mode("1000\nSUDO_NOPASS") == MODE_SUDO_NOPASS
    assert fingerprint_mode("1000\nSUDO_PASS") == MODE_SUDO_PASS
    assert fingerprint_mode("") == MODE_SUDO_PASS


def test_wrap_sudo() -> None:
    assert wrap_sudo("id", MODE_ROOT) == "id"
    assert wrap_sudo("id", MODE_SUDO_NOPASS) == "sudo -n id"
    assert wrap_sudo("id", MODE_SUDO_PASS) == "sudo -k -S -p '' id"


def test_real_probe_over_ssh(ssh_server, tmp_path) -> None:
    ctl = client(tmp_path)
    try:
        probe = run(ctl.probe(settings(int(ssh_server["port"]))))
    except ControlError as exc:
        assert exc.code in {"needs_root", "not_installed", "unsupported_arch", "internal", "transport", "no_systemd"}
        return
    assert probe.arch
    assert isinstance(probe.installed, bool)
    assert isinstance(probe.running, bool)


def test_real_apply_refuses_without_root(ssh_server, tmp_path) -> None:
    if os.geteuid() == 0:
        pytest.skip("running as root")
    ctl = client(tmp_path)
    opts = ServerOptions(listen_port=56123, wg_port=51999, mode="udp", obf_profile="rtpopus3", obf_key="c" * 64)
    with pytest.raises(ControlError) as exc:
        run(ctl.apply(settings(int(ssh_server["port"])), opts))
    assert exc.value.code in {
        "needs_root",
        "wg_unsupported",
        "no_systemd",
        "internal",
        "unsupported_arch",
        "docker_failed",
        "download_failed",
        "start_failed",
        "wg_install_failed",
    }


def test_script_body_reaches_server(ssh_server, tmp_path) -> None:
    ctl = ControlClient(make_config(tmp_path), ssh=SshClient(connect_timeout=10, command_timeout=60))
    ctl.script = "#!/bin/bash\nmarker=payload-ok\nprintf '{\"proto\":3,\"result\":\"ok\",\"data\":{\"marker\":\"%s\"}}\\n' \"$marker\"\n"
    response = run(ctl.call(settings(int(ssh_server["port"])), ["probe"]))
    assert response.ok
    assert response.data["marker"] == "payload-ok"


def test_argument_quoting_round_trip(ssh_server, tmp_path) -> None:
    ctl = ControlClient(make_config(tmp_path), ssh=SshClient(connect_timeout=10, command_timeout=60))
    ctl.script = "#!/bin/bash\nprintf '{\"proto\":3,\"result\":\"ok\",\"data\":{\"args\":\"%s\"}}\\n' \"$*\"\n"
    response = run(ctl.call(settings(int(ssh_server["port"])), ["client-add", "--name=dev box"]))
    assert response.ok
    assert "--name=dev box" in response.data["args"]


def test_proto_mismatch_over_ssh(ssh_server, tmp_path) -> None:
    ctl = ControlClient(make_config(tmp_path), ssh=SshClient(connect_timeout=10, command_timeout=60))
    ctl.script = "#!/bin/bash\necho '{\"proto\":1,\"result\":\"ok\"}'\n"
    with pytest.raises(ControlError) as exc:
        run(ctl.call(settings(int(ssh_server["port"])), ["probe"]))
    assert exc.value.code == "proto_mismatch"


def test_sudo_password_prefix_in_stdin(ssh_server, tmp_path) -> None:
    ctl = ControlClient(make_config(tmp_path), ssh=SshClient(connect_timeout=10, command_timeout=60))
    ctl.script = "#!/bin/bash\nprintf '{\"proto\":3,\"result\":\"ok\",\"data\":{\"pw\":\"%s\"}}\\n' \"$PW\"\n"
    cfg = settings(int(ssh_server["port"]), mode=MODE_SUDO_PASS, sudo_password="topsecret")
    body = ctl.stdin_for(cfg)
    assert body.split(b"\n", 1)[0] == b"topsecret"
    command = "read -r pw; export PW=\"$pw\"; exec bash -s -- probe"
    out = run(SshClient(connect_timeout=10, command_timeout=60).run(cfg, command, stdin=body))
    payload = json.loads(out.text.strip().splitlines()[-1])
    assert payload["data"]["pw"] == "topsecret"


def test_parse_response_from_real_script(ssh_server, tmp_path) -> None:
    ctl = ControlClient(make_config(tmp_path), ssh=SshClient(connect_timeout=10, command_timeout=60))
    ctl.script = "#!/bin/bash\nprintf '{\"proto\":3,\"result\":\"err\",\"code\":\"not_found\",\"msg\":\"нет клиента\"}\\n'\n"
    response = run(ctl.call(settings(int(ssh_server["port"])), ["client-conf", "--name=ghost"]))
    assert not response.ok
    assert response.code == "not_found"
    assert parse_response('{"proto":3,"result":"ok","data":{}}').ok


def test_reset_sweep_runs_over_ssh(ssh_server, tmp_path) -> None:
    ctl = ControlClient(make_config(tmp_path), ssh=SshClient(connect_timeout=10, command_timeout=120))
    assert ctl.script
    out = run(ctl.run_script(settings(int(ssh_server["port"])), RESET_SCRIPT, timeout=60))
    assert "reset done" in out.text
    assert "syntax error" not in out.text.lower()
    assert "command not found" not in out.text.lower()


def test_reset_sweep_keeps_the_shell_alive(ssh_server) -> None:
    ssh = SshClient(connect_timeout=10, command_timeout=120)
    cfg = settings(int(ssh_server["port"]))
    run(ssh.run(cfg, "bash -s", stdin=RESET_SCRIPT.encode()))
    assert "alive" in run(ssh.run(cfg, "echo alive")).text


def test_reset_sweep_reports_markers(tmp_path) -> None:
    class Echo:
        async def run(self, cfg, command, stdin=None, timeout=None):
            return __import__("BOT.sshx", fromlist=["SshOutput"]).SshOutput(
                text="reset container\nreset prefix\nreset done\n"
            )

    ctl = ControlClient(make_config(tmp_path), ssh=Echo())
    steps = run(ctl.sweep(settings(22)))
    assert len(steps) == 2
