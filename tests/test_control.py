from __future__ import annotations

import json

import pytest

from BOT.config import Config
from BOT.control import (
    ERROR_CODES,
    ControlClient,
    ControlError,
    ControlResponse,
    apply_argv,
    build_argv,
    decode_conf,
    outcome_of,
    parse_response,
    remote_config_of,
    shell_quote,
)
from BOT.links import kcp_args
from BOT.models import ProbeResult, ServerOptions, SshSettings
from tests.fakes import make_config


def cfg(tmp_path) -> Config:
    return make_config(tmp_path)


def test_shell_quote() -> None:
    assert shell_quote("probe") == "probe"
    assert shell_quote("--name=dev box") == "'--name=dev box'"
    assert shell_quote("") == "''"
    assert shell_quote("a'b") == "'a'\"'\"'b'"


def test_build_argv() -> None:
    assert build_argv("probe") == "probe"
    assert build_argv("client-add", "--name=dev") == "client-add --name=dev"
    assert build_argv("uninstall", "--target=all", "--purge") == "uninstall --target=all --purge"


def test_apply_argv_defaults() -> None:
    argv = apply_argv(ServerOptions(obf_key="a" * 64))
    assert "--method=docker" in argv
    assert "--backend=new" in argv
    assert "--listen-port=56000" in argv
    assert "--wg-port=51820" in argv
    assert "--wg-net=10.13.13.0/24" in argv
    assert "--mode=udp" in argv
    assert "--obf-profile=rtpopus3" in argv
    assert f"--obf-key={'a' * 64}" in argv
    assert "--version=latest" in argv
    assert not any(item.startswith("--kcp") for item in argv)


def test_apply_argv_external_and_host() -> None:
    opts = ServerOptions(backend="external", connect="127.0.0.1:51820", host="vpn.example.org", obf_profile="none", obf_key="")
    argv = apply_argv(opts)
    assert "--connect=127.0.0.1:51820" in argv
    assert "--host=vpn.example.org" in argv
    assert not any(item.startswith("--wg-port") for item in argv)
    assert not any(item.startswith("--obf-key") for item in argv)


def test_apply_argv_tcp_adds_kcp() -> None:
    argv = apply_argv(ServerOptions(mode="tcp", backend="external", connect="127.0.0.1:51820"))
    assert kcp_args(None) == [item for item in argv if item.startswith("--kcp")]


def test_parse_response_ok() -> None:
    raw = "noise\n" + json.dumps({"proto": 3, "result": "ok", "data": {"installed": True}, "logs": ["x"]})
    response = parse_response(raw)
    assert response.ok
    assert response.data["installed"] is True
    assert response.logs == ["x"]


def test_parse_response_picks_last_object() -> None:
    first = json.dumps({"proto": 3, "result": "err", "code": "not_found", "msg": "a"})
    second = json.dumps({"proto": 3, "result": "ok", "data": {}})
    assert parse_response(first + "\n" + second).ok


def test_parse_response_proto_mismatch_raises() -> None:
    with pytest.raises(ControlError) as exc:
        parse_response(json.dumps({"proto": 2, "result": "ok"}))
    assert exc.value.code == "proto_mismatch"


def test_parse_response_garbage_raises() -> None:
    with pytest.raises(ControlError) as exc:
        parse_response("bash: install.sh: No such file or directory")
    assert exc.value.code == "transport"


def test_parse_response_invalid_json_object() -> None:
    with pytest.raises(ControlError):
        parse_response("{broken}")


def test_control_response_status() -> None:
    response = ControlResponse(result="err", code="port_busy", msg="порт занят", stage="apply")
    assert not response.ok
    with pytest.raises(ControlError) as exc:
        response.raise_for_status()
    assert "порт занят" in exc.value.message
    assert "apply" in exc.value.message


def test_error_codes_have_text() -> None:
    for code in ERROR_CODES:
        assert ERROR_CODES[code]


def test_outcome_of_response() -> None:
    import base64

    conf = "[Interface]\nAddress = 10.13.13.2/24\n"
    response = ControlResponse(result="ok")
    response.data = {
        "owner": {"client_id": "cid", "pub": "k", "conf_b64": base64.b64encode(conf.encode()).decode()},
        "obf_key": "a" * 64,
        "needs_restart": True,
    }
    outcome = outcome_of(response)
    assert outcome.owner_client_id == "cid"
    assert outcome.owner_conf == conf
    assert outcome.obf_key == "a" * 64
    assert outcome.needs_restart is True


def test_decode_conf_survives_broken_input() -> None:
    assert decode_conf("") == ""
    assert decode_conf("!!!") == ""


def test_remote_config_of_probe_data() -> None:
    data = {"config": {"method": "systemd", "listen_port": 56000, "obf_profile": "rtpopus2"}}
    remote = remote_config_of(data)
    assert remote is not None
    assert remote.method == "systemd"
    assert remote.obf_profile == "rtpopus2"
    assert remote_config_of({}) is None


def test_stdin_for_root_mode(tmp_path) -> None:
    client = ControlClient(cfg(tmp_path))
    ssh = SshSettings(mode="ROOT")
    body = client.stdin_for(ssh)
    assert body.startswith(b"#!/")
    assert b"proto" in body


def test_stdin_for_sudo_pass(tmp_path) -> None:
    client = ControlClient(cfg(tmp_path))
    ssh = SshSettings(mode="SUDO_PASS", password="pw")
    body = client.stdin_for(ssh)
    assert body.split(b"\n", 1)[0] == b"pw"
    ssh = SshSettings(mode="SUDO_PASS", password="pw", sudo_password="s3cret")
    assert client.stdin_for(ssh).split(b"\n", 1)[0] == b"s3cret"


def test_probe_parses_data(monkeypatch, tmp_path) -> None:
    client = ControlClient(cfg(tmp_path))

    async def fake_call(cfg_obj, argv, timeout=None):
        assert argv == ["probe"]
        return parse_response(json.dumps({"proto": 3, "result": "ok", "data": {"installed": True, "running": False, "euid": 0, "arch": "aarch64"}}))

    monkeypatch.setattr(client, "call", fake_call)
    import asyncio

    result = asyncio.run(client.probe(SshSettings()))
    assert isinstance(result, ProbeResult)
    assert result.installed is True
    assert result.running is False
    assert result.arch == "aarch64"


def test_clients_parse_share(monkeypatch, tmp_path) -> None:
    client = ControlClient(cfg(tmp_path))

    async def fake_call(cfg_obj, argv, timeout=None):
        return parse_response(
            json.dumps(
                {
                    "proto": 3,
                    "result": "ok",
                    "data": {
                        "clients": [{"name": "owner", "client_id": "cid", "self": True, "ip": "10.13.13.2", "hs": 5}],
                        "share": {"backend": "new", "host": "h", "port": 56000, "mode": "udp", "obf_profile": "rtpopus3", "obf_key": "k"},
                    },
                }
            )
        )

    monkeypatch.setattr(client, "call", fake_call)
    import asyncio

    clients, share = asyncio.run(client.clients(SshSettings()))
    assert clients[0].name == "owner"
    assert clients[0].is_self is True
    assert clients[0].handshake == 5
    assert share.host == "h"
    assert share.port == 56000


def test_apply_raises_on_error(monkeypatch, tmp_path) -> None:
    client = ControlClient(cfg(tmp_path))

    async def fake_call(cfg_obj, argv, timeout=None):
        return parse_response(json.dumps({"proto": 3, "result": "err", "code": "needs_root", "msg": "нужен root"}))

    monkeypatch.setattr(client, "call", fake_call)
    import asyncio

    with pytest.raises(ControlError) as exc:
        asyncio.run(client.apply(SshSettings(), ServerOptions()))
    assert exc.value.code == "needs_root"


def test_logs_tail_argv(monkeypatch, tmp_path) -> None:
    client = ControlClient(cfg(tmp_path))
    seen: list[list[str]] = []

    async def fake_call(cfg_obj, argv, timeout=None):
        seen.append(argv)
        return parse_response(json.dumps({"proto": 3, "result": "ok", "data": {"lines": ["a", "b"]}}))

    monkeypatch.setattr(client, "call", fake_call)
    import asyncio

    lines = asyncio.run(client.logs(SshSettings(), 50))
    assert lines == ["a", "b"]
    assert seen[0] == ["logs", "--tail=50"]


def test_client_commands_argv(monkeypatch, tmp_path) -> None:
    client = ControlClient(cfg(tmp_path))
    seen: list[list[str]] = []

    async def fake_call(cfg_obj, argv, timeout=None):
        seen.append(argv)
        payload = {"client": {"name": "dev", "client_id": "cid-dev"}, "conf_b64": ""}
        return parse_response(json.dumps({"proto": 3, "result": "ok", "data": payload}))

    monkeypatch.setattr(client, "call", fake_call)
    import asyncio

    info, conf = asyncio.run(client.client_add(SshSettings(), "dev"))
    assert info.name == "dev"
    assert conf == ""
    asyncio.run(client.client_conf(SshSettings(), "dev"))
    asyncio.run(client.client_remove(SshSettings(), "dev"))
    assert seen == [["client-add", "--name=dev"], ["client-conf", "--name=dev"], ["client-remove", "--name=dev"]]


def test_uninstall_argv(monkeypatch, tmp_path) -> None:
    client = ControlClient(cfg(tmp_path))
    seen: list[list[str]] = []

    async def fake_call(cfg_obj, argv, timeout=None):
        seen.append(argv)
        return parse_response(json.dumps({"proto": 3, "result": "ok", "data": {}}))

    monkeypatch.setattr(client, "call", fake_call)
    import asyncio

    asyncio.run(client.uninstall(SshSettings(), "all", True))
    assert seen == [["uninstall", "--target=all", "--purge"]]
