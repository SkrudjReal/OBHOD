from __future__ import annotations

import asyncio

from .ui import heading, muted, pre


class Draft:
    def __init__(self, app: object, chat_id: int, draft_id: int = 1) -> None:
        self.app = app
        self.chat_id = chat_id
        self.draft_id = draft_id
        self.lines: list[str] = []
        self.step = ""
        self._task: asyncio.Task[None] | None = None
        self._closed = False
        self._lock = asyncio.Lock()

    def html(self) -> str:
        body = [heading("Выполняется", 3)]
        if self.step:
            body.append(f"<p>{self.step}</p>")
        if self.lines:
            body.append(pre("\n".join(self.lines[-6:])))
        else:
            body.append(f"<p>{muted('подготовка')}</p>")
        return "".join(body)

    async def _push(self) -> None:
        if self._closed:
            return
        try:
            peer = await self.app.mt.resolve_peer(self.chat_id)
            action = {
                "_": "sendMessageRichMessageDraftAction",
                "random_id": self.draft_id,
                "can_stop": True,
                "keep_on_stop": False,
                "rich_message": {"_": "inputRichMessageHTML", "html": self.html()},
            }
            await self.app.mt_req("messages.setTyping", peer=peer, action=action)
        except asyncio.CancelledError:
            raise
        except Exception:
            return

    async def say(self, step: str, line: str = "") -> None:
        async with self._lock:
            self.step = step
            if line:
                self.lines.append(line)
            await self._push()

    async def _ticker(self) -> None:
        while not self._closed:
            await asyncio.sleep(3)
            async with self._lock:
                await self._push()

    async def close(self) -> None:
        self._closed = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        try:
            peer = await self.app.mt.resolve_peer(self.chat_id)
            await self.app.mt_req(
                "messages.setTyping",
                peer=peer,
                action={"_": "sendMessageStopDraftAction", "random_id": self.draft_id},
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return

    async def __aenter__(self) -> "Draft":
        self._task = asyncio.create_task(self._ticker())
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()
