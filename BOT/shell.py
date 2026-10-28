from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass


class ShellError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class ShellOutput:
    text: str
    code: int = 0


def agent_argv(argv: list[str], source: str) -> list[str]:
    return [sys.executable or "python3", "-c", source] + [str(item) for item in argv]


class LocalShell:
    def __init__(self, command_timeout: float = 300.0) -> None:
        self.command_timeout = float(command_timeout)

    def require_root(self) -> None:
        if os.geteuid() != 0:
            raise ShellError("the bot must run as root on its own machine, start it as root or from systemd")

    async def run_argv(self, argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> ShellOutput:
        self.require_root()
        limit = float(timeout or self.command_timeout)
        try:
            child = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=dict(os.environ),
            )
        except OSError as exc:
            raise ShellError(f"the command could not start: {exc}") from None
        try:
            out, _ = await asyncio.wait_for(child.communicate(stdin if stdin is not None else b""), limit)
        except asyncio.TimeoutError:
            child.kill()
            await child.wait()
            raise ShellError(f"the command did not finish within {int(limit)} seconds") from None
        text = (out or b"").decode("utf-8", "replace")
        return ShellOutput(text=text.strip(), code=int(child.returncode or 0))

    async def run(self, command: str, stdin: bytes | None = None, timeout: float | None = None, cfg: object = None) -> ShellOutput:
        return await self.run_argv(["/bin/sh", "-c", command], stdin=stdin, timeout=timeout)
