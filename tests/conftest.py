from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("OBHOD_STATE_DIR", str(ROOT / ".pytest-state"))


@pytest.fixture(autouse=True)
def loopback_address(monkeypatch: pytest.MonkeyPatch) -> None:
    try:
        import BOT.app
    except ImportError:
        return
    monkeypatch.setattr(BOT.app, "public_address", lambda: "")
