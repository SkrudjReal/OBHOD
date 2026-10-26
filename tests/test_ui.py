from __future__ import annotations

import re

import pytest
from goygram.rich import Rich

from BOT.ui import (
    MAX_BUTTONS,
    big,
    bold,
    button,
    bullet_list,
    chip,
    code,
    copy_button,
    count_buttons,
    details,
    divider,
    esc,
    heading,
    muted,
    numbered,
    pre,
    quote,
    row,
    screen,
    status_line,
    table,
    validate_buttons,
)

BUTTON_RE = re.compile(r"<tg-button [^>]*>")
ROW_RE = re.compile(r"<tg-button-row[^>]*>(.*?)</tg-button-row>", re.S)


def test_esc_and_helpers() -> None:
    assert esc("<b>&\"") == "&lt;b&gt;&amp;&quot;"
    assert code("x") == "<code>x</code>"
    assert bold("x") == "<b>x</b>"
    assert muted("x").startswith("<span")
    assert chip("x") == "<mark>x</mark>"


def test_button_html_shape() -> None:
    html = button("Меню", "nav:home").html()
    assert html.startswith('<tg-button type="callback_data"')
    assert 'data="nav:home"' in html
    assert html.endswith(">Меню</tg-button>")


def test_button_rejects_long_callback() -> None:
    with pytest.raises(ValueError):
        button("x", "a" * 65).html()


def test_copy_button_is_text_type() -> None:
    html = copy_button("Копировать", "freeturn://abc")
    assert 'type="copy_text"' in html
    assert 'text="freeturn://abc"' in html


def test_row_wraps_buttons() -> None:
    html = row(button("a", "x"), button("b", "y"))
    assert html.startswith("<tg-button-row align=\"left\">")
    assert html.endswith("</tg-button-row>")
    assert count_buttons(html) == 2


def test_big_is_single_button_row() -> None:
    html = big("Применить", "srv:apply", "success")
    assert count_buttons(html) == 1
    assert 'style="success"' in html
    assert html.count("<tg-button-row") == 1


def test_table_escapes_keys_not_values() -> None:
    html = table([("<k>", code("v"))])
    assert "<td>&lt;k&gt;</td>" in html
    assert "<td><code>v</code></td>" in html


def test_lists_details_quote_pre() -> None:
    assert bullet_list(["a", "b"]) == "<ul><li>a</li><li>b</li></ul>"
    assert numbered(["a"]).startswith("<ol>")
    assert details("t", "b").startswith("<details><summary>t</summary>")
    assert quote("x") == "<blockquote>x</blockquote>"
    assert heading("t", 2) == "<h2>t</h2>"
    assert divider() == "<hr/>"
    assert pre("a<b") == "<pre>a&lt;b</pre>"
    assert pre("{}", "json").startswith('<pre><code class="language-json">')


def test_screen_returns_rich_with_buttons() -> None:
    rich = screen("Заголовок", "подзаголовок", ["<p>x</p>"], [big("a", "nav:home")], footer=muted("f"))
    assert isinstance(rich, Rich)
    html = rich.build()
    assert html.startswith("<h2>Заголовок</h2>")
    assert "подзаголовок" in html
    assert "<hr/>" in html
    assert count_buttons(html) == 1
    assert html.rstrip().endswith("</footer>")


def test_screen_without_buttons_has_no_divider() -> None:
    html = screen("t", "", [], []).build()
    assert "<hr/>" not in html


def test_screen_every_button_is_inside_a_row() -> None:
    html = screen("t", "", [], [big("a", "x"), row(button("b", "y"), button("c", "z"))]).build()
    inside = sum(count_buttons(body) for body in ROW_RE.findall(html))
    assert inside == count_buttons(html)


def test_validate_buttons_limit() -> None:
    html = "".join(row(button(str(i), f"d{i}")) for i in range(MAX_BUTTONS))
    validate_buttons(html)
    html = "".join(row(button(str(i), f"d{i}")) for i in range(MAX_BUTTONS + 1))
    with pytest.raises(ValueError):
        validate_buttons(html)


def test_status_line_states() -> None:
    assert "not connected" in status_line(False, False, False)
    assert "not installed" in status_line(True, False, False)
    assert "running" in status_line(True, True, True)
    assert "stopped" in status_line(True, False, True)
