from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from BOT.models import ClientInfo
from BOT.store import State, Store


def test_state_roundtrip() -> None:
    state = State()
    state.ssh.host = "203.0.113.10"
    state.ssh.mode = "SUDO_NOPASS"
    state.opts.listen_port = 56001
    state.opts.host = "vpn.example.org"
    state.link.threads = 20
    state.admin_id = 999
    state.owner_client_id = "cid"
    state.owner_conf = "[Interface]\nAddress = 10.13.13.2/24\n"
    state.log_tail = 500
    state.clients = [ClientInfo(name="owner", client_id="cid", ip="10.13.13.2").__dict__]
    clone = State.from_dict(state.to_dict())
    assert clone.ssh.host == "203.0.113.10"
    assert clone.ssh.mode == "SUDO_NOPASS"
    assert clone.opts.listen_port == 56001
    assert clone.opts.host == "vpn.example.org"
    assert clone.link.threads == 20
    assert clone.admin_id == 999
    assert "Address" in clone.owner_conf
    assert clone.log_tail == 500
    assert clone.clients[0]["name"] == "owner"


def test_state_from_empty_dict() -> None:
    state = State.from_dict(None)
    assert state.ssh.host == ""
    assert state.opts.listen_port == 56000
    assert state.link.threads == 12
    assert state.log_tail == 200


def test_save_and_load_permissions(tmp_path: Path) -> None:
    store = Store(tmp_path / "nested" / "state.json")
    state = State()
    state.ssh.host = "h"
    store.save(state)
    assert store.path.is_file()
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(store.path.parent).st_mode) == 0o700
    again = store.load()
    assert again.ssh.host == "h"
    raw = json.loads(store.path.read_text())
    assert raw["ssh"]["host"] == "h"
    assert raw["opts"]["listen_port"] == 56000


def test_load_missing_and_broken(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    assert store.load().ssh.host == ""
    store.path.write_text("{broken")
    assert store.load().ssh.host == ""
    store.path.write_text(json.dumps({"ssh": {"host": "x.y"}}))
    assert store.load().ssh.host == "x.y"
    store.path.write_text(json.dumps(["not", "a", "dict"]))
    assert store.load().ssh.host == ""


def test_save_is_atomic_and_leaves_no_temp_files(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    state = State()
    for index in range(5):
        state.log_tail = 100 + index
        store.save(state)
    leftovers = [item.name for item in tmp_path.iterdir() if item.name != "state.json"]
    assert leftovers == []
    assert store.load().log_tail == 104


def test_save_overwrites_previous_content(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    first = State()
    first.ssh.host = "one"
    store.save(first)
    second = State()
    second.ssh.host = "two"
    store.save(second)
    body = store.path.read_text()
    assert "one" not in body
    assert "two" in body
