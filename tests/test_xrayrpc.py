from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import threading
import time
import zipfile
from pathlib import Path

import pytest

from BOT.xrayrpc import (
    DEFAULT_VERSION,
    PINNED_SHA256,
    XrayControl,
    XrayError,
    XrayResponse,
    asset_of_arch,
    digest_of,
    parse_dgst,
    parse_response,
    parse_xray_version,
    pinned_digest,
    release_asset,
    remote_command,
)

FAKE_CORE = """#!/usr/bin/env python3
import json
import socket
import sys
import time

argv = sys.argv[1:]
if argv[:1] == ["version"]:
    print("Xray 26.10.21 (Xray, Penetrates Everything.)")
    raise SystemExit(0)
if argv[:1] == ["x25519"]:
    print("Private key: cHJpdmF0ZQ")
    print("Public key: cHVibGlj")
    raise SystemExit(0)
if argv[:2] == ["run", "-test"]:
    config = argv[-1]
    body = open(config, "r", encoding="utf-8").read()
    if "\\"inbounds\\"" not in body:
        print("invalid config")
        raise SystemExit(23)
    print("Configuration OK")
    raise SystemExit(0)
if argv[:1] == ["run"]:
    port = 0
    config = argv[-1]
    try:
        data = json.load(open(config, "r", encoding="utf-8"))
        port = int(data["inbounds"][0]["port"])
    except (OSError, ValueError, KeyError, IndexError):
        raise SystemExit(1)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(8)
    print("started", flush=True)
    while True:
        try:
            handle, _ = server.accept()
            handle.close()
        except KeyboardInterrupt:
            break
raise SystemExit(0)
"""

GOOD_CONFIG = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "port": 24443,
            "protocol": "vless",
            "settings": {"clients": [{"id": "11111111-2222-3333-4444-555555555555"}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "none"},
        }
    ],
    "outbounds": [{"protocol": "freedom"}],
}


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def build_zip(target: Path) -> str:
    core = target.parent / "xray"
    core.write_text(FAKE_CORE, encoding="utf-8")
    core.chmod(0o755)
    with zipfile.ZipFile(target, "w") as bundle:
        bundle.write(core, arcname="xray")
        bundle.writestr("geoip.dat", b"geoip")
        bundle.writestr("geosite.dat", b"geosite")
    return hashlib.sha256(target.read_bytes()).hexdigest()


@pytest.fixture()
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    root = tmp_path / "root"
    root.mkdir()
    archive = tmp_path / "core.zip"
    digest = build_zip(archive)
    monkeypatch.setenv("XRAY_ROOT", str(root))
    monkeypatch.setenv("XRAY_NO_SYSTEMD", "1")
    return {"root": str(root), "archive": str(archive), "digest": digest}


def call(*argv: str) -> dict:
    command = remote_command(list(argv))
    out = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=180)
    lines = [line for line in out.stdout.splitlines() if line.startswith("{")]
    assert lines, out.stdout + out.stderr
    return json.loads(lines[-1])


def payload(config: dict) -> str:
    return base64.b64encode(json.dumps(config).encode()).decode()


def test_default_version_matches_fallback() -> None:
    assert DEFAULT_VERSION == "v26.10.21"
    assert pinned_digest("x86_64") == "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978"
    assert PINNED_SHA256["64"] == pinned_digest("x86_64")


def test_asset_mapping() -> None:
    assert asset_of_arch("x86_64") == "64"
    assert asset_of_arch("aarch64") == "arm64-v8a"
    assert asset_of_arch("armv7l") == "arm32-v7a"
    assert asset_of_arch("mips") == ""


def test_release_asset_url() -> None:
    url = release_asset("v26.10.21", "64")
    assert url == "https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip"


def test_parse_dgst_body() -> None:
    body = "MD5= 5adb4bbf\nSHA1= 1068619\nSHA2-256= 0EEC3ED4163C273D8C8BF821F7D219E257921CF584AA3FB970715E458E631978\n"
    assert parse_dgst(body) == "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978"
    assert parse_dgst(body, "MD5") == "5adb4bbf"
    assert parse_dgst("nothing") == ""


def test_parse_xray_version_text() -> None:
    assert parse_xray_version("Xray 26.10.21 (Xray, Penetrates Everything.)") == "26.10.21"
    assert parse_xray_version("") == ""


def test_digest_of() -> None:
    assert digest_of("abc") == hashlib.sha256(b"abc").hexdigest()


def test_remote_command_is_quoted() -> None:
    command = remote_command(["probe"])
    assert "command -v python3" in command
    assert command.count("'") > 0
    apply_command = remote_command(["apply", "--config-b64=eyJ9"])
    assert "--config-b64=eyJ9" in apply_command


def test_parse_response_ok() -> None:
    response = parse_response('log line\n{"proto":3,"result":"ok","data":{"installed":true}}')
    assert response.ok is True
    assert response.data["installed"] is True


def test_parse_response_error() -> None:
    response = parse_response('{"proto":3,"result":"err","code":"download_failed","msg":"нет сети","stage":"download"}')
    assert response.ok is False
    with pytest.raises(XrayError) as info:
        response.raise_for_status()
    assert "нет сети" in info.value.message
    assert info.value.code == "download_failed"


def test_parse_response_proto_mismatch() -> None:
    with pytest.raises(XrayError) as info:
        parse_response('{"proto":2,"result":"ok"}')
    assert info.value.code == "proto_mismatch"


def test_parse_response_garbage() -> None:
    with pytest.raises(XrayError):
        parse_response("no json here")
    with pytest.raises(XrayError):
        parse_response('{"proto":3,')


def test_response_dataclass_defaults() -> None:
    response = XrayResponse()
    assert response.proto == 3
    assert response.ok is False


def test_probe_script_reports_clean_host(sandbox: dict[str, str]) -> None:
    body = call("probe")
    assert body["result"] == "ok"
    data = body["data"]
    assert data["installed"] is False
    assert data["pinned"] == "v26.10.21"
    assert data["systemd"] is False
    assert data["ports"] == []


def test_install_core_from_file_url(sandbox: dict[str, str]) -> None:
    body = call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    assert body["result"] == "ok", body
    assert body["data"]["installed"] is True
    assert body["data"]["version"] == "26.10.21"
    assert body["data"]["downloaded"] is True
    assert Path(sandbox["root"], "usr/local/bin/xray").is_file()


def test_install_core_rejects_bad_digest(sandbox: dict[str, str]) -> None:
    body = call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + "0" * 64)
    assert body["result"] == "err"
    assert body["code"] == "digest_mismatch"


def test_install_core_reports_missing_archive(sandbox: dict[str, str]) -> None:
    body = call("install-core", "--version=v26.10.21", "--url=file:///nonexistent/core.zip", "--sha256=" + "0" * 64)
    assert body["result"] == "err"
    assert body["code"] == "download_failed"


def test_install_core_latest_falls_back_to_pinned(sandbox: dict[str, str]) -> None:
    body = call(
        "install-core",
        "--version=latest",
        "--tag=v26.10.21",
        "--url=file:///nonexistent/latest.zip",
        "--fallback-url=file://" + sandbox["archive"],
        "--fallback-sha256=" + sandbox["digest"],
    )
    assert body["result"] == "ok", body
    assert body["data"]["fallback"] is True
    assert body["data"]["fallback_version"] == "v26.10.21"
    assert body["data"]["version"] == "26.10.21"
    assert any("фолбек" in line for line in body["logs"])
    assert Path(sandbox["root"], "usr/local/bin/xray").is_file()


def test_install_core_latest_reports_fallback_log(sandbox: dict[str, str]) -> None:
    body = call(
        "install-core",
        "--version=latest",
        "--tag=v26.10.21",
        "--url=file://" + sandbox["archive"],
        "--sha256=" + sandbox["digest"],
    )
    assert body["result"] == "ok", body
    assert body["data"]["fallback"] is False
    assert body["data"]["version"] == "26.10.21"
    assert any("последний релиз" in line for line in body["logs"])


def test_install_core_pinned_failure_does_not_fallback(sandbox: dict[str, str]) -> None:
    body = call("install-core", "--version=v26.10.21", "--url=file:///nonexistent/x.zip")
    assert body["result"] == "err"
    assert body["code"] == "download_failed"
    assert not any("фолбек" in line for line in body["logs"])


def test_install_core_latest_fails_when_fallback_unreachable(sandbox: dict[str, str]) -> None:
    body = call(
        "install-core",
        "--version=latest",
        "--tag=v26.10.21",
        "--url=file:///nonexistent/x.zip",
        "--fallback-url=file:///nonexistent/pin.zip",
    )
    assert body["result"] == "err"
    assert body["code"] == "download_failed"
    assert any("фолбек" in line for line in body["logs"])


def test_apply_installs_latest_with_fallback(sandbox: dict[str, str]) -> None:
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "in-1", "listen": "127.0.0.1", "port": free_port(), "protocol": "socks", "settings": {"udp": False}}
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    body = call(
        "apply",
        "--config-b64=" + payload(config),
        "--version=latest",
        "--tag=v26.10.21",
        "--url=file:///nonexistent/latest.zip",
        "--fallback-url=file://" + sandbox["archive"],
        "--fallback-sha256=" + sandbox["digest"],
    )
    assert body["result"] == "ok", body
    assert body["data"]["fallback"] is True
    assert body["data"]["version"] == "26.10.21"


def test_install_core_is_idempotent(sandbox: dict[str, str]) -> None:
    first = call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    assert first["data"]["downloaded"] is True
    second = call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    assert second["result"] == "ok"
    assert second["data"]["downloaded"] is False
    forced = call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"], "--force")
    assert forced["data"]["downloaded"] is True


def test_test_config_validates(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    good = call("test-config", "--config-b64=" + payload(GOOD_CONFIG))
    assert good["result"] == "ok"
    assert good["data"]["valid"] is True
    bad = call("test-config", "--config-b64=" + payload({"outbounds": []}))
    assert bad["result"] == "ok"
    assert bad["data"]["valid"] is False
    rejected = call("apply", "--config-b64=" + payload({"outbounds": []}), "--no-restart")
    assert rejected["result"] == "err"
    assert rejected["code"] == "config_invalid"


def test_apply_requires_inbounds(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("apply", "--config-b64=" + payload({"outbounds": []}))
    assert body["result"] == "err"
    assert body["code"] == "config_invalid"


def test_apply_without_payload(sandbox: dict[str, str]) -> None:
    body = call("apply")
    assert body["result"] == "err"
    assert body["code"] == "config_missing"


def test_apply_start_stop_cycle(sandbox: dict[str, str]) -> None:
    port = free_port()
    config = json.loads(json.dumps(GOOD_CONFIG))
    config["inbounds"][0]["port"] = port
    call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("apply", "--config-b64=" + payload(config), "--version=v26.10.21")
    assert body["result"] == "ok", body
    data = body["data"]
    assert data["applied"] is True
    assert data["ports"] == [port]
    assert data["listening"] == [port]
    assert data["service"] == "active"
    stopped = call("stop")
    assert stopped["result"] == "ok"
    assert stopped["data"]["service"] == "inactive"
    assert stopped["data"]["listening"] == []


def test_apply_no_restart_keeps_service_stopped(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("apply", "--config-b64=" + payload(GOOD_CONFIG), "--no-restart")
    assert body["result"] == "ok"
    assert body["data"]["service"] in {"inactive", "absent"}


def test_restart_without_config(sandbox: dict[str, str]) -> None:
    body = call("restart")
    assert body["result"] == "err"
    assert body["code"] == "not_installed"


def test_x25519_command(sandbox: dict[str, str]) -> None:
    body = call("x25519")
    assert body["result"] == "err"
    call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("x25519")
    assert body["result"] == "ok"
    assert body["data"]["private"] == "cHJpdmF0ZQ"
    assert body["data"]["public"] == "cHVibGlj"


def test_logs_command(sandbox: dict[str, str]) -> None:
    body = call("logs", "--tail=10")
    assert body["result"] == "ok"
    assert isinstance(body["data"]["lines"], list)


def test_uninstall_purges(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    call("apply", "--config-b64=" + payload(GOOD_CONFIG), "--no-restart")
    body = call("uninstall", "--purge")
    assert body["result"] == "ok"
    assert body["data"]["purge"] is True
    state = call("probe")["data"]
    assert state["installed"] is False
    assert state["config_exists"] is False


def test_uninstall_keeps_core_without_purge(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.21", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("uninstall")
    assert body["result"] == "ok"
    assert call("probe")["data"]["installed"] is True


def test_unknown_command(sandbox: dict[str, str]) -> None:
    body = call("bogus")
    assert body["result"] == "err"
    assert body["code"] == "bad_arg"


def test_bad_base64_payload(sandbox: dict[str, str]) -> None:
    body = call("apply", "--config-b64=!!!!")
    assert body["result"] == "err"
    assert body["code"] in {"bad_arg", "config_missing"}


def test_no_command(sandbox: dict[str, str]) -> None:
    command = remote_command([])
    out = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=60)
    body = json.loads([line for line in out.stdout.splitlines() if line.startswith("{")][-1])
    assert body["code"] == "bad_arg"


def test_no_python_launcher() -> None:
    command = remote_command(["probe"])
    out = subprocess.run(
        ["bash", "-c", "PATH=/nonexistent " + command],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert '"code": "no_python"' in out.stdout or "no_python" in out.stdout


def test_control_client_over_fake_ssh(sandbox: dict[str, str]) -> None:
    class FakeSsh:
        def __init__(self) -> None:
            self.commands: list[str] = []

        async def run(self, cfg, command, stdin=None, timeout=None):
            self.commands.append(command)
            out = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=180)
            from BOT.sshx import SshOutput

            return SshOutput(text=out.stdout.strip(), code=out.returncode)

    from BOT.models import SshSettings

    ssh = FakeSsh()
    control = XrayControl(ssh=ssh)
    cfg = SshSettings(host="127.0.0.1", user="root", password="x", mode="ROOT")
    state = asyncio.run(control.probe(cfg))
    assert state.installed is False
    assert state.pinned == "v26.10.21"
    asyncio.run(control.install_core(cfg, url="file://" + sandbox["archive"], sha256=sandbox["digest"]))
    applied = asyncio.run(control.apply(cfg, json.dumps(GOOD_CONFIG), restart=False))
    assert applied.config_exists is True
    valid, output = asyncio.run(control.test_config(cfg, json.dumps(GOOD_CONFIG)))
    assert valid is True
    private, public = asyncio.run(control.x25519(cfg))
    assert private == "cHJpdmF0ZQ"
    assert ssh.commands


def test_control_client_without_core_raises(sandbox: dict[str, str]) -> None:
    class FakeSsh:
        async def run(self, cfg, command, stdin=None, timeout=None):
            from BOT.sshx import SshOutput

            return SshOutput(text='{"proto":3,"result":"err","code":"not_installed","msg":"нет ядра"}', code=1)

    from BOT.models import SshSettings

    control = XrayControl(ssh=FakeSsh())
    cfg = SshSettings(host="127.0.0.1", user="root", password="x", mode="ROOT")
    with pytest.raises(XrayError) as info:
        asyncio.run(control.restart(cfg))
    assert info.value.code == "not_installed"


def test_control_client_transport_error() -> None:
    class FakeSsh:
        async def run(self, cfg, command, stdin=None, timeout=None):
            from BOT.sshx import SshError

            raise SshError("нет связи")

    from BOT.models import SshSettings

    control = XrayControl(ssh=FakeSsh())
    cfg = SshSettings(host="127.0.0.1", user="root", password="x", mode="ROOT")
    with pytest.raises(XrayError) as info:
        asyncio.run(control.probe(cfg))
    assert info.value.code == "transport"


def test_sudo_password_stdin(sandbox: dict[str, str]) -> None:
    seen: list[bytes] = []

    class FakeSsh:
        async def run(self, cfg, command, stdin=None, timeout=None):
            seen.append(stdin or b"")
            from BOT.sshx import SshOutput

            return SshOutput(text='{"proto":3,"result":"ok","data":{}}', code=0)

    from BOT.models import SshSettings

    control = XrayControl(ssh=FakeSsh())
    cfg = SshSettings(host="h", user="root", password="pass", sudo_password="sudo-pass", mode="SUDO_PASS")
    asyncio.run(control.probe(cfg))
    assert seen[0] == b"sudo-pass\n"


def test_remote_script_has_no_python_comments() -> None:
    from BOT.xrayrpc import REMOTE_SCRIPT

    for line in REMOTE_SCRIPT.splitlines():
        assert not line.strip().startswith("#")


def test_script_runs_without_leftovers(sandbox: dict[str, str]) -> None:
    body = call("probe")
    assert body["result"] == "ok"
    assert not Path(sandbox["root"], "usr/local/etc/xray/config.json").exists()


def test_wait_for_ports_helper() -> None:
    deadline = time.time() + 1
    assert deadline > time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=2) as probe_socket:
            assert probe_socket.getpeername()[1] == port


def test_e2e_over_asyncssh(sandbox: dict[str, str], tmp_path: Path) -> None:
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
            payload_bytes = await asyncio.wait_for(process.stdin.read(), 3)
        except asyncio.TimeoutError:
            payload_bytes = b""
        child = await asyncio.create_subprocess_shell(
            command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await child.communicate(payload_bytes if isinstance(payload_bytes, bytes) else b"")
        process.stdout.write(out.decode("utf-8", "replace"))
        process.exit(child.returncode or 0)

    key = asyncssh.generate_private_key("ssh-ed25519")
    state: dict[str, object] = {}
    ready = threading.Event()

    def worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def main() -> None:
            closure = asyncio.Event()
            server = await asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[key], process_factory=handle)
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
        control = XrayControl(ssh=SshClient(connect_timeout=10, command_timeout=120))
        initial = asyncio.run(control.probe(cfg))
        assert initial.installed is False
        installed = asyncio.run(control.install_core(cfg, url="file://" + sandbox["archive"], sha256=sandbox["digest"]))
        assert installed.ok is True
        applied = asyncio.run(control.apply(cfg, json.dumps(GOOD_CONFIG), restart=False))
        assert applied.config_exists is True
        valid, _ = asyncio.run(control.test_config(cfg, json.dumps(GOOD_CONFIG)))
        assert valid is True
        private, public = asyncio.run(control.x25519(cfg))
        assert private and public
        removed = asyncio.run(control.uninstall(cfg, purge=True))
        assert removed.ok is True
        final = asyncio.run(control.probe(cfg))
        assert final.installed is False
    finally:
        closure = state.get("closure")
        if isinstance(closure, asyncio.Event):
            closure.set()
        thread.join(timeout=10)


def test_env_root_prefixing(sandbox: dict[str, str]) -> None:
    body = call("probe")
    assert body["data"]["core_path"].startswith(sandbox["root"])
    assert os.environ["XRAY_ROOT"] == sandbox["root"]


def test_cleanup_removes_sandbox(sandbox: dict[str, str]) -> None:
    target = Path(sandbox["root"])
    shutil.rmtree(target, ignore_errors=True)
    assert not target.exists()
