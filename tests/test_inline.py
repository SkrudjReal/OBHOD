from __future__ import annotations

from BOT import inline
from BOT.inline import CANCEL, FIELDS, MARKER, field, clean_value, marker, parse_marker, parse_query, prefill, results_for

import pytest

from BOT.inline import InlineError


def test_field_lookup() -> None:
    assert field("ssh_host").label == "адрес сервера"
    with pytest.raises(InlineError):
        field("nope")


def test_prefill_shape() -> None:
    assert prefill("ssh_host") == "ob ssh_host - "
    assert prefill("xr_sni", "3") == "ob xr_sni 3 "
    with pytest.raises(InlineError):
        prefill("nope")


def test_marker_roundtrip() -> None:
    text = marker("xr_sni", "3", "www.microsoft.com")
    assert text == "#ob xr_sni 3 www.microsoft.com"
    assert parse_marker(text) == ("xr_sni", "3", "www.microsoft.com")


def test_marker_with_big_value_keeps_spaces() -> None:
    text = marker("ssh_key", "", "line one two")
    assert parse_marker(text) == ("ssh_key", "", "line one two")


def test_marker_unknown_field_is_ignored() -> None:
    assert parse_marker("#ob nope - value") is None
    assert parse_marker("обычный текст") is None
    assert parse_marker("#ob") is None


def test_cancel_marker() -> None:
    text = inline.cancel_marker()
    assert text == "#ob cancel - -"
    assert parse_marker(text) == (CANCEL, "", "")


def test_marker_compresses_whitespace() -> None:
    assert marker("xr_remark", "1", "  my   name ") == "#ob xr_remark 1 my name"


def test_parse_query_forms() -> None:
    assert parse_query("ob ssh_host - 1.2.3.4") == ("ssh_host", "", "1.2.3.4")
    assert parse_query("ob ssh_host 1.2.3.4") == ("ssh_host", "", "1.2.3.4")
    assert parse_query("ob xr_sni 3 www.microsoft.com") == ("xr_sni", "3", "www.microsoft.com")
    assert parse_query("ob") == ("", "", "")
    assert parse_query("other text") is None
    assert parse_query("ob unknown - x") is None
    assert parse_query("") is None


def test_results_for_empty_query_are_empty() -> None:
    assert results_for("") == []
    assert results_for("nonsense") == []


def test_results_for_picker_lists_fields() -> None:
    results = results_for("ob")
    assert len(results) == len(FIELDS)
    assert results[0]["type"] == "article"
    assert results[0]["id"].startswith("pick-")


def test_results_for_picker_shows_current_values() -> None:
    results = results_for("ob", current={"ssh_host": "203.0.113.10"})
    host = next(item for item in results if item["id"] == "pick-ssh_host")
    assert "203.0.113.10" in host["description"]


def test_results_for_hint_when_empty_value() -> None:
    results = results_for("ob xr_port 2 ")
    ids = [item["id"] for item in results]
    assert "hint-xr_port" in ids
    assert "cancel-xr_port" in ids


def test_results_for_value_produces_marker() -> None:
    results = results_for("ob xr_remark 7 my-node")
    assert results[0]["id"] == "set-xr_remark"
    body = results[0]["input_message_content"]["message_text"]
    assert body == "#ob xr_remark 7 my-node"
    assert parse_marker(body) == ("xr_remark", "7", "my-node")


def test_secret_value_is_masked_in_description() -> None:
    results = results_for("ob ssh_password - hunter2")
    assert results[0]["description"] == "скрыто"
    ids = [item["id"] for item in results]
    assert "wipe-ssh_password" in ids


def test_plain_value_is_not_masked() -> None:
    results = results_for("ob ssh_host - 10.1.1.1")
    assert results[0]["description"] == "10.1.1.1"


def test_mt_results_use_tl_shape() -> None:
    results = results_for("ob ssh_host - 10.1.1.1", src="mt")
    body = results[0]
    assert body["_"] == "inputBotInlineResult"
    assert body["send_message"]["_"] == "inputBotInlineMessageText"
    assert body["send_message"]["message"] == "#ob ssh_host - 10.1.1.1"
    assert body["send_message"]["no_webpage"] is True
    assert "input_message_content" not in body


def test_bot_results_use_api_shape() -> None:
    results = results_for("ob ssh_host - 10.1.1.1", src="bot")
    body = results[0]
    assert body["type"] == "article"
    assert body["input_message_content"]["message_text"] == "#ob ssh_host - 10.1.1.1"
    assert body["input_message_content"]["disable_web_page_preview"] is True


def test_result_id_is_bounded() -> None:
    results = results_for("ob " + "x" * 1, src="mt")
    for item in results:
        assert len(item["id"]) <= 64


def test_clean_value_for_targets() -> None:
    assert clean_value("xr_scan_targets", "a:443; b:8443 , ,c:443") == "a:443, b:8443, c:443"
    assert clean_value("xr_scan_manual", " 1.1.1.1:443 ") == "1.1.1.1:443"


def test_clean_value_length_limit() -> None:
    with pytest.raises(InlineError):
        clean_value("xr_remark", "x" * (inline.MAX_VALUE + 1))


def test_clean_value_keeps_key_newlines() -> None:
    key = "-----BEGIN-----\nabc\n-----END-----"
    assert clean_value("ssh_key", key) == key


def test_every_field_has_hint() -> None:
    for item in FIELDS.values():
        assert item.hint
        assert item.label
        assert item.prefill.startswith("ob ")


def test_secret_fields_are_marked() -> None:
    secrets = {"ssh_password", "ssh_key", "ssh_sudo", "xr_private_key"}
    for ident in secrets:
        assert FIELDS[ident].secret is True


def test_marker_prefix_constant() -> None:
    assert MARKER == "#ob"
    assert inline.PREFIX == "ob"
    assert inline.CANCEL == "cancel"
