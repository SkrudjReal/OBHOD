from __future__ import annotations

from pathlib import Path

import pytest

from BOT.config import Config, ConfigError

ENV_BODY = """BOT_TOKEN=123456:ABCDEF
API_ID=12345678
API_HASH=%s
ADMIN_ID=777
OBHOD_STATE_DIR=%s
OBHOD_LOG_LEVEL=debug
"""

HASH = "a" * 32


def write_env(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "obhod.env"
    path.write_text(body, encoding="utf-8")
    return path


def test_load_minimal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OBHOD_STATE_DIR", raising=False)
    path = write_env(tmp_path, ENV_BODY % (HASH, tmp_path / "state"))
    cfg = Config.load(path)
    assert cfg.bot_token == "123456:ABCDEF"
    assert cfg.api_id == 12345678
    assert cfg.api_hash == HASH
    assert cfg.admin_id == 777
    assert cfg.state_dir == tmp_path / "state"
    assert cfg.session_name == str(tmp_path / "state" / "obhod")
    assert cfg.log_level == "DEBUG"
    assert cfg.env_path == path


def test_admin_id_is_optional(tmp_path: Path) -> None:
    body = "BOT_TOKEN=1:A\nAPI_ID=5\nAPI_HASH=%s\n" % HASH
    cfg = Config.load(write_env(tmp_path, body))
    assert cfg.admin_id == 0


@pytest.mark.parametrize("missing", ["BOT_TOKEN", "API_ID", "API_HASH"])
def test_missing_required_keys(tmp_path: Path, missing: str) -> None:
    lines = [line for line in (ENV_BODY % (HASH, tmp_path / "state")).splitlines() if not line.startswith(missing + "=")]
    with pytest.raises(ConfigError) as exc:
        Config.load(write_env(tmp_path, "\n".join(lines) + "\n"))
    assert missing in str(exc.value)


def test_bad_token_shape(tmp_path: Path) -> None:
    body = "BOT_TOKEN=withoutcolon\nAPI_ID=5\nAPI_HASH=%s\n" % HASH
    with pytest.raises(ConfigError):
        Config.load(write_env(tmp_path, body))


def test_bad_api_id(tmp_path: Path) -> None:
    body = "BOT_TOKEN=1:A\nAPI_ID=abc\nAPI_HASH=%s\n" % HASH
    with pytest.raises(ConfigError):
        Config.load(write_env(tmp_path, body))


def test_quotes_and_export_prefix(tmp_path: Path) -> None:
    body = 'export BOT_TOKEN="1:A"\nAPI_ID=5\nAPI_HASH=%s\n# comment\n\n' % HASH
    cfg = Config.load(write_env(tmp_path, body))
    assert cfg.bot_token == "1:A"


def test_env_overrides_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_env(tmp_path, ENV_BODY % (HASH, tmp_path / "state"))
    monkeypatch.setenv("ADMIN_ID", "999")
    cfg = Config.load(path)
    assert cfg.admin_id == 999


def test_missing_file_is_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Config.load(tmp_path / "absent.env")
