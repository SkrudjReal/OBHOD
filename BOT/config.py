from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(Exception):
    pass


def _env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        data[key.strip()] = value
    return data


def _int(name: str, raw: str) -> int:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None


@dataclass(frozen=True)
class Config:
    bot_token: str
    api_id: int
    api_hash: str
    admin_id: int
    state_dir: Path
    install_script: Path
    session_name: str = "obhod"
    connect_timeout: float = 12.0
    command_timeout: float = 300.0
    apply_timeout: float = 900.0
    default_dc_host: str | None = None
    default_dc_port: int | None = None
    env_path: Path | None = None
    log_level: str = "INFO"
    extra: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def load(env_path: str | os.PathLike[str] | None = None) -> "Config":
        path = Path(env_path or os.environ.get("OBHOD_ENV", "/etc/obhod/obhod.env"))
        values = _env_file(path)
        for key, value in os.environ.items():
            if key.startswith("OBHOD_") or key in {
                "BOT_TOKEN",
                "API_ID",
                "API_HASH",
                "ADMIN_ID",
            }:
                values[key] = value

        token = values.get("BOT_TOKEN", "").strip()
        api_hash = values.get("API_HASH", "").strip()
        api_id_raw = values.get("API_ID", "").strip()
        admin_raw = values.get("ADMIN_ID", "").strip()

        missing = [
            name
            for name, value in (
                ("BOT_TOKEN", token),
                ("API_ID", api_id_raw),
                ("API_HASH", api_hash),
            )
            if not value
        ]
        if missing:
            raise ConfigError("missing required keys: " + ", ".join(missing))
        if ":" not in token:
            raise ConfigError("BOT_TOKEN must look like 123456:ABC-DEF")

        state_dir = Path(values.get("OBHOD_STATE_DIR", "/var/lib/obhod"))
        script = Path(
            values.get(
                "OBHOD_INSTALL_SCRIPT",
                str(Path(__file__).resolve().parent.parent / "Storage" / "install.sh"),
            )
        )

        return Config(
            bot_token=token,
            api_id=_int("API_ID", api_id_raw),
            api_hash=api_hash,
            admin_id=_int("ADMIN_ID", admin_raw) if admin_raw else 0,
            state_dir=state_dir,
            install_script=script,
            session_name=values.get("OBHOD_SESSION", "obhod"),
            connect_timeout=float(values.get("OBHOD_CONNECT_TIMEOUT", 12.0)),
            command_timeout=float(values.get("OBHOD_COMMAND_TIMEOUT", 300.0)),
            apply_timeout=float(values.get("OBHOD_APPLY_TIMEOUT", 900.0)),
            default_dc_host=values.get("OBHOD_DC_HOST") or None,
            default_dc_port=_int("OBHOD_DC_PORT", values["OBHOD_DC_PORT"]) if values.get("OBHOD_DC_PORT") else None,
            env_path=path,
            log_level=values.get("OBHOD_LOG_LEVEL", "INFO").upper(),
            extra=values,
        )

    @property
    def dc_host(self) -> str | None:
        return self.default_dc_host

    @property
    def dc_port(self) -> int | None:
        return self.default_dc_port

    def require_install_script(self) -> str:
        if not self.install_script.is_file():
            raise ConfigError(f"install script not found at {self.install_script}")
        raw = self.install_script.read_text(encoding="utf-8", errors="replace")
        return raw.replace("\r\n", "\n").replace("\r", "\n")
