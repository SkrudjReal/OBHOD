from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import LinkSettings, ServerOptions, SshSettings

DEFAULT_TAIL = 200


@dataclass
class State:
    ssh: SshSettings = field(default_factory=SshSettings)
    opts: ServerOptions = field(default_factory=ServerOptions)
    link: LinkSettings = field(default_factory=LinkSettings)
    admin_id: int = 0
    owner_client_id: str = ""
    owner_conf: str = ""
    log_tail: int = DEFAULT_TAIL
    clients: list[dict[str, Any]] = field(default_factory=list)
    last_probe: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ssh": self.ssh.to_dict(),
            "opts": self.opts.to_dict(),
            "link": self.link.to_dict(),
            "admin_id": self.admin_id,
            "owner_client_id": self.owner_client_id,
            "owner_conf": self.owner_conf,
            "log_tail": self.log_tail,
            "clients": self.clients,
            "last_probe": self.last_probe,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "State":
        data = raw or {}
        return State(
            ssh=SshSettings.from_dict(data.get("ssh")),
            opts=ServerOptions.from_dict(data.get("opts")),
            link=LinkSettings.from_dict(data.get("link")),
            admin_id=int(data.get("admin_id", 0) or 0),
            owner_client_id=str(data.get("owner_client_id", "")),
            owner_conf=str(data.get("owner_conf", "")),
            log_tail=int(data.get("log_tail", DEFAULT_TAIL) or DEFAULT_TAIL),
            clients=list(data.get("clients") or []),
            last_probe=dict(data.get("last_probe") or {}),
        )


class Store:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self) -> State:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return State()
        if not isinstance(raw, dict):
            return State()
        return State.from_dict(raw)

    def save(self, state: State) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        payload = json.dumps(state.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        handle, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".state-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except OSError:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
