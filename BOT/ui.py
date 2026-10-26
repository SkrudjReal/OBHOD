from __future__ import annotations

from dataclasses import dataclass
from html import escape
from typing import Iterable

from goygram.rich import Rich

MAX_BUTTONS = 18
MAX_CALLBACK = 64
SEP = " · "


def esc(value: object) -> str:
    return escape(str(value), quote=True)


def code(value: object) -> str:
    return f"<code>{esc(value)}</code>"


def bold(value: object) -> str:
    return f"<b>{esc(value)}</b>"


def italic(value: object) -> str:
    return f"<i>{esc(value)}</i>"


def muted(value: object) -> str:
    return f'<span style="color: #8a8a8a">{esc(value)}</span>'


def chip(value: object) -> str:
    return f"<mark>{esc(value)}</mark>"


@dataclass
class Button:
    label: str
    data: str
    style: str = ""

    def html(self) -> str:
        if len(self.data.encode("utf-8")) > MAX_CALLBACK:
            raise ValueError(f"callback data is too long: {self.data}")
        style = f' style="{esc(self.style)}"' if self.style else ""
        return f'<tg-button type="callback_data"{style} data="{esc(self.data)}">{esc(self.label)}</tg-button>'


def button(label: str, data: str, style: str = "") -> Button:
    return Button(label=label, data=data, style=style)


def copy_button(label: str, text: str) -> str:
    return f'<tg-button type="copy_text" text="{esc(text)}">{esc(label)}</tg-button>'


def link_button(label: str, url: str) -> str:
    return f'<tg-button type="url" url="{esc(url)}">{esc(label)}</tg-button>'


def row(*buttons: Button | str, align: str = "left") -> str:
    inner = "".join(item.html() if isinstance(item, Button) else item for item in buttons)
    return f'<tg-button-row align="{esc(align)}">{inner}</tg-button-row>'


def big(label: str, data: str, style: str = "") -> str:
    return row(button(label, data, style), align="left")


def rows(items: Iterable[str]) -> str:
    return "".join(items)


def table(pairs: Iterable[tuple[str, str]], headers: tuple[str, str] | None = None) -> str:
    head = ""
    if headers:
        head = f"<tr><th>{esc(headers[0])}</th><th>{esc(headers[1])}</th></tr>"
    body = "".join(f"<tr><td>{esc(key)}</td><td>{value}</td></tr>" for key, value in pairs)
    return f'<table bordered="false" striped="false">{head}{body}</table>'


def bullet_list(items: Iterable[str]) -> str:
    return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


def numbered(items: Iterable[str]) -> str:
    return "<ol>" + "".join(f"<li>{item}</li>" for item in items) + "</ol>"


def details(title: str, body: str, open_: bool = False) -> str:
    flag = " open" if open_ else ""
    return f"<details{flag}><summary>{esc(title)}</summary>{body}</details>"


def quote(body: str, cite: str = "") -> str:
    if cite:
        return f"<blockquote>{body}<cite>{esc(cite)}</cite></blockquote>"
    return f"<blockquote>{body}</blockquote>"


def heading(text: str, level: int = 3) -> str:
    return f"<h{level}>{esc(text)}</h{level}>"


def divider() -> str:
    return "<hr/>"


def pre(text: str, lang: str = "") -> str:
    if lang:
        return f'<pre><code class="language-{esc(lang)}">{esc(text)}</code></pre>'
    return f"<pre>{esc(text)}</pre>"


def screen(
    title: str,
    subtitle: str = "",
    blocks: Iterable[str] = (),
    buttons: Iterable[str] = (),
    footer: str = "",
) -> Rich:
    root = Rich()
    root.add(f"<h2>{esc(title)}</h2>")
    if subtitle:
        root.add(f"<p>{subtitle}</p>")
    for block in blocks:
        if block:
            root.add(block)
    button_html = [item for item in buttons if item]
    if button_html:
        root.add(divider())
        for item in button_html:
            root.add(item)
    if footer:
        root.add(f"<footer>{footer}</footer>")
    return root


def status_line(connected: bool, running: bool, installed: bool) -> str:
    if not connected:
        return chip("not connected")
    if not installed:
        return chip("not installed")
    if running:
        return chip("running")
    return chip("stopped")


def count_buttons(html: str) -> int:
    return html.count("<tg-button ")


def validate_buttons(html: str) -> None:
    total = count_buttons(html)
    if total > MAX_BUTTONS:
        raise ValueError(f"too many buttons: {total}")
