from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from BOT.config import Config
from BOT.control import ControlResponse
from BOT.models import ClientInfo, ProbeResult, RemoteConfig, ShareInfo
from BOT.store import State

ROOT = Path(__file__).resolve().parent.parent
WG = (
    "[Interface]\n"
    "PrivateKey = a2V5\n"
    "Address = 10.13.13.2/24\n"
    "DNS = 1.1.1.1\n"
    "MTU = 1280\n"
    "\n"
    "[Peer]\n"
    "PublicKey = cHVi\n"
    "PresharedKey = cHNr\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\n"
    "Endpoint = 203.0.113.10:51820\n"
    "PersistentKeepalive = 25\n"
)


def make_config(state_dir: Path, admin_id: int = 777, **overrides: Any) -> Config:
    base: dict[str, Any] = dict(
        bot_token="123456:ABCDEF",
        api_id=12345,
        api_hash="0" * 32,
        admin_id=admin_id,
        state_dir=state_dir,
        install_script=ROOT / "Storage" / "install.sh",
    )
    base.update(overrides)
    return Config(**base)


class FakeMt:
    def __init__(self) -> None:
        self.drafts: list[dict[str, Any]] = []

    async def resolve_peer(self, value: Any) -> bytes:
        return b"peer"


class FakeApp:
    def __init__(self) -> None:
        self.sent: list[tuple[int, Any]] = []
        self.edited: list[tuple[int, int, Any]] = []
        self.deleted: list[tuple[int, int]] = []
        self.answers: list[tuple[str, bool]] = []
        self.log: list[Any] = []
        self.mt = FakeMt()
        self.closed = False

    async def send_rich(self, chat_id: Any, rich: Any, **kw: Any) -> int:
        self.sent.append((chat_id, rich))
        self.log.append(rich)
        return len(self.sent)

    async def edit_rich(self, chat_id: Any, msg_id: int, rich: Any, **kw: Any) -> int:
        self.edited.append((chat_id, msg_id, rich))
        self.log.append(rich)
        return msg_id

    async def delete_msg(self, chat_id: Any, msg_id: int, **kw: Any) -> bool:
        self.deleted.append((chat_id, msg_id))
        return True

    async def mt_req(self, act: str, **kw: Any) -> dict[str, Any]:
        self.mt.drafts.append({"act": act, **kw})
        return {}

    async def close(self) -> None:
        self.closed = True

    def last_rich(self) -> Any:
        return self.log[-1]

    def last_html(self) -> str:
        return self.last_rich().build()

    def all_html(self) -> str:
        return "".join(item[1].build() for item in self.sent) + "".join(item[2].build() for item in self.edited)


@dataclass
class FakeEvt:
    chat_id: int = 777
    msg_id: int = 42
    from_id: int = 777
    data: str = ""
    text: str = ""
    cmd: str = ""
    answers: list[tuple[str | None, bool]] = field(default_factory=list)

    async def answer(self, text: str | None = None, alert: bool = False, **kw: Any) -> None:
        self.answers.append((text, alert))


class FakeControl:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.fingerprint = "SHA256:abc"
        self.mode = "ROOT"
        self.probe_result = ProbeResult(
            installed=True,
            running=True,
            version="4.1.0",
            euid=0,
            arch="x86_64",
            method="docker",
            config=RemoteConfig(method="docker", backend="new", listen_port=56000, wg_port=51820, wg_net="10.13.13.0/24", mode="udp", obf_profile="rtpopus3", obf_key="a" * 64, version="4.1.0"),
        )
        self.client_list = [
            ClientInfo(name="owner", client_id="cid-owner", is_self=True, ip="10.13.13.2", pub="cHVi", handshake=1700000000),
            ClientInfo(name="phone", client_id="cid-phone", ip="10.13.13.3", pub="cGhvbmU=", handshake=0),
        ]
        self.share = ShareInfo(backend="new", host="203.0.113.10", port=56000, mode="udp", obf_profile="rtpopus3", obf_key="a" * 64)
        self.conf = WG
        self.log_lines = [f"log line {index}" for index in range(30)]
        self.fail: tuple[str, str] | None = None

    def _maybe_fail(self, name: str) -> None:
        if self.fail and self.fail[0] == name:
            from BOT.control import ControlError

            raise ControlError(self.fail[1], "start_failed")

    async def connect_check(self, cfg: Any) -> str:
        self.calls.append(("connect_check", None))
        self._maybe_fail("connect_check")
        return self.fingerprint

    async def detect_mode(self, cfg: Any) -> str:
        self.calls.append(("detect_mode", None))
        return self.mode

    async def probe(self, cfg: Any) -> ProbeResult:
        self.calls.append(("probe", None))
        self._maybe_fail("probe")
        return self.probe_result

    async def apply(self, cfg: Any, opts: Any, update: bool = False) -> ControlResponse:
        self.calls.append(("apply", update))
        self._maybe_fail("apply")
        opts.obf_key = opts.obf_key or "b" * 64
        response = ControlResponse(result="ok")
        response.data = {
            "owner": {
                "client_id": "cid-owner",
                "pub": "cHVi",
                "conf_b64": base64.b64encode(self.conf.encode()).decode(),
                "link": "",
            },
            "obf_key": opts.obf_key,
            "needs_restart": False,
        }
        return response

    async def stop(self, cfg: Any) -> ControlResponse:
        self.calls.append(("stop", None))
        self.probe_result.running = False
        return ControlResponse(result="ok")

    async def restart(self, cfg: Any) -> ControlResponse:
        self.calls.append(("restart", None))
        self.probe_result.running = True
        return ControlResponse(result="ok")

    async def logs(self, cfg: Any, tail: int = 200) -> list[str]:
        self.calls.append(("logs", tail))
        self._maybe_fail("logs")
        return self.log_lines[-tail:]

    async def clients(self, cfg: Any) -> tuple[list[ClientInfo], ShareInfo]:
        self.calls.append(("clients", None))
        self._maybe_fail("clients")
        return list(self.client_list), self.share

    async def client_add(self, cfg: Any, name: str) -> tuple[ClientInfo, str]:
        self.calls.append(("client_add", name))
        self._maybe_fail("client_add")
        info = ClientInfo(name=name, client_id=f"cid-{name}", ip="10.13.13.9", pub="bmV3")
        self.client_list.append(info)
        return info, self.conf

    async def client_conf(self, cfg: Any, name: str) -> tuple[ClientInfo, str]:
        self.calls.append(("client_conf", name))
        self._maybe_fail("client_conf")
        info = next((item for item in self.client_list if item.name == name), ClientInfo(name=name, client_id=f"cid-{name}"))
        return info, self.conf

    async def client_remove(self, cfg: Any, name: str) -> ControlResponse:
        self.calls.append(("client_remove", name))
        self._maybe_fail("client_remove")
        self.client_list = [item for item in self.client_list if item.name != name]
        return ControlResponse(result="ok")

    async def uninstall(self, cfg: Any, target: str = "all", purge: bool = True) -> ControlResponse:
        self.calls.append(("uninstall", target))
        self._maybe_fail("uninstall")
        return ControlResponse(result="ok", data={"target": target})


def make_state() -> State:
    state = State()
    state.ssh.host = "203.0.113.10"
    state.ssh.user = "root"
    state.ssh.password = "hunter2"
    state.opts.obf_key = "a" * 64
    state.link.call_link = "https://vk.ru/call/join/AbCdEf"
    state.owner_client_id = "cid-owner"
    state.owner_conf = WG
    return state
