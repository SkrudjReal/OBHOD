from __future__ import annotations

import pytest

from BOT.flows import CYCLE_FIELDS, FIELD_TARGETS, FIELDS, Flows
from BOT.models import (
    AUTH_KEY,
    AUTH_PASSWORD,
    BACKEND_EXTERNAL,
    BACKEND_NEW,
    CORE_VERSION,
    CORE_VERSION_LATEST,
)
from BOT.store import State
from BOT.validate import ValidationError
from tests.fakes import make_state


def flows() -> Flows:
    return Flows()


def state() -> State:
    return State()


def test_every_field_is_complete() -> None:
    for key, spec in FIELDS.items():
        assert spec.key == key
        assert spec.label and spec.prompt and spec.hint
        assert key in FIELD_TARGETS
    for key in FIELD_TARGETS:
        assert key in FIELDS


def test_unknown_field() -> None:
    with pytest.raises(Exception):
        flows().field("nope")


def test_targets() -> None:
    assert flows().target("ssh_password") == "ssh"
    assert flows().target("setup_wgnet") == "setup"
    assert flows().target("link_threads") == "client"
    assert flows().target("client_name") == "client_new"


def test_ssh_fields() -> None:
    fl = flows()
    st = state()
    assert "203.0.113.10" in fl.apply_field(st, "ssh_host", " 203.0.113.10 ")
    assert st.ssh.host == "203.0.113.10"
    fl.apply_field(st, "ssh_port", "2222")
    assert st.ssh.port == 2222
    fl.apply_field(st, "ssh_user", "deploy")
    assert st.ssh.user == "deploy"
    fl.apply_field(st, "ssh_password", "pw")
    assert st.ssh.auth == AUTH_PASSWORD
    assert st.ssh.is_ready()
    fl.apply_field(st, "ssh_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
    assert st.ssh.auth == AUTH_KEY
    assert st.ssh.key.endswith("\n")
    fl.apply_field(st, "ssh_passphrase", "-")
    assert st.ssh.passphrase == ""
    fl.apply_field(st, "ssh_sudo", "s3cret")
    assert st.ssh.sudo_password == "s3cret"


@pytest.mark.parametrize("bad", ["", "he sto", "host/../x", "-lead"])
def test_ssh_host_rejects(bad: str) -> None:
    with pytest.raises(ValidationError):
        flows().apply_field(state(), "ssh_host", bad)


def test_ssh_key_rejects_short() -> None:
    with pytest.raises(ValidationError):
        flows().apply_field(state(), "ssh_key", "short")


def test_server_fields() -> None:
    fl = flows()
    st = state()
    fl.apply_field(st, "setup_listen", "56100")
    assert st.opts.listen_port == 56100
    fl.apply_field(st, "setup_wgport", "52000")
    assert st.opts.wg_port == 52000
    fl.apply_field(st, "setup_wgnet", "10.44.0.0/24")
    assert st.opts.wg_net == "10.44.0.0/24"
    fl.apply_field(st, "setup_connect", "127.0.0.1:51820")
    assert st.opts.backend == BACKEND_EXTERNAL
    assert st.opts.connect == "127.0.0.1:51820"
    fl.apply_field(st, "setup_host", "vpn.example.org")
    assert st.opts.host == "vpn.example.org"
    fl.apply_field(st, "setup_host", "-")
    assert st.opts.host == ""
    fl.apply_field(st, "setup_version", "v4.1.0")
    assert st.opts.version == "v4.1.0"


def test_port_collision() -> None:
    fl = flows()
    st = state()
    with pytest.raises(ValidationError):
        fl.apply_field(st, "setup_listen", str(st.opts.wg_port))
    with pytest.raises(ValidationError):
        fl.apply_field(st, "setup_wgport", str(st.opts.listen_port))


def test_obf_key_field() -> None:
    fl = flows()
    st = state()
    fl.apply_field(st, "setup_obfkey", "c" * 64)
    assert st.opts.obf_key == "c" * 64
    fl.apply_field(st, "setup_obfkey", "")
    assert len(st.opts.obf_key) == 64
    with pytest.raises(ValidationError):
        fl.apply_field(st, "setup_obfkey", "zz")


def test_link_fields() -> None:
    fl = flows()
    st = state()
    fl.apply_field(st, "link_threads", "24")
    assert st.link.threads == 24
    fl.apply_field(st, "link_spc", "6")
    assert st.link.streams_per_cred == 6
    fl.apply_field(st, "link_timing", "15")
    assert st.link.timing_ms == 15
    fl.apply_field(st, "link_listen", "127.0.0.1:1080")
    assert st.link.local_listen == "127.0.0.1:1080"
    fl.apply_field(st, "link_dnss", "1.1.1.1,8.8.8.8")
    assert st.link.dns_servers == "1.1.1.1,8.8.8.8"
    fl.apply_field(st, "link_call", "https://vk.ru/call/join/AbCdEf")
    assert st.link.call_link.endswith("AbCdEf")


def test_client_name_field() -> None:
    fl = flows()
    st = state()
    assert "dev-1" in fl.apply_field(st, "client_name", "dev-1")
    with pytest.raises(ValidationError):
        fl.apply_field(st, "client_name", "bad name")


def test_toggle_ssh_mode() -> None:
    fl = flows()
    st = state()
    fl.toggle_ssh_mode(st)
    assert st.ssh.auth == AUTH_KEY
    fl.toggle_ssh_mode(st)
    assert st.ssh.auth == AUTH_PASSWORD


def test_backend_switch_resets_mode() -> None:
    fl = flows()
    st = state()
    fl.set_backend(st, "external")
    fl.set_mode(st, "tcp")
    assert st.opts.mode == "tcp"
    fl.set_backend(st, "new")
    assert st.opts.mode == "udp"
    with pytest.raises(ValidationError):
        fl.set_backend(st, "other")


def test_set_mode_guard() -> None:
    fl = flows()
    st = state()
    with pytest.raises(ValidationError):
        fl.set_mode(st, "tcp")
    assert st.opts.mode == "udp"


def test_set_method() -> None:
    fl = flows()
    st = state()
    fl.set_method(st, "systemd")
    assert st.opts.method == "systemd"
    with pytest.raises(ValidationError):
        fl.set_method(st, "podman")


def test_set_obf_generates_and_clears_key() -> None:
    fl = flows()
    st = state()
    fl.set_obf(st, "rtpopus2")
    assert st.opts.obf_profile == "rtpopus2"
    assert len(st.opts.obf_key) == 64
    fl.set_obf(st, "none")
    assert st.opts.obf_key == ""
    with pytest.raises(ValidationError):
        fl.set_obf(st, "rot13")


def test_generate_key() -> None:
    fl = flows()
    st = state()
    fl.generate_obf_key(st)
    assert len(st.opts.obf_key) == 64


def test_cycle_wraps_every_field() -> None:
    fl = flows()
    st = state()
    for name in CYCLE_FIELDS:
        fl.cycle(st, name)
        fl.cycle(st, name)
    assert st.link.transport in ("tcp", "udp")
    assert st.link.mode in ("udp", "tcp")
    assert st.link.dns_mode in ("auto", "plain", "doh")
    with pytest.raises(ValidationError):
        fl.cycle(st, "nope")


def test_toggle_link() -> None:
    fl = flows()
    st = state()
    fl.toggle_link(st, "bond")
    assert st.link.bond is True
    fl.toggle_link(st, "mcap")
    assert st.link.manual_captcha is True
    with pytest.raises(ValidationError):
        fl.toggle_link(st, "nope")


def test_validate_server_happy_path() -> None:
    st = make_state()
    flows().validate_server(st)


def test_validate_server_generates_key() -> None:
    st = state()
    st.opts.obf_key = ""
    flows().validate_server(st)
    assert len(st.opts.obf_key) == 64


def test_validate_server_rejects_bad_combo() -> None:
    fl = flows()
    st = state()
    st.opts.mode = "tcp"
    with pytest.raises(ValidationError):
        fl.validate_server(st)
    st = state()
    st.opts.backend = BACKEND_EXTERNAL
    st.opts.connect = ""
    with pytest.raises(ValidationError):
        fl.validate_server(st)
    st = state()
    st.opts.listen_port = st.opts.wg_port
    with pytest.raises(ValidationError):
        fl.validate_server(st)
    st = state()
    st.opts.obf_key = "short"
    with pytest.raises(ValidationError):
        fl.validate_server(st)


def test_validate_server_none_profile_clears_key() -> None:
    st = state()
    st.opts.obf_profile = "none"
    flows().validate_server(st)
    assert st.opts.obf_key == ""


def test_backend_constant_usage() -> None:
    st = state()
    assert st.opts.backend == BACKEND_NEW


def test_pin_version_defaults_and_pins() -> None:
    fl = flows()
    assert fl.pin_version("latest") == "latest"
    assert fl.pin_version("v4.0.3") == "v4.0.3"
    assert fl.pin_version("4.0.3") == "v4.0.3"
    assert fl.pin_version(CORE_VERSION) == CORE_VERSION


def test_pin_version_rejects_junk() -> None:
    fl = flows()
    for bad in ("", "local", "4.1", "v4", "latest2", "4;rm -rf /"):
        with pytest.raises(ValidationError):
            fl.pin_version(bad)


def test_set_version_from_button() -> None:
    fl = flows()
    st = state()
    fl.set_version(st, CORE_VERSION_LATEST)
    assert st.opts.version == CORE_VERSION_LATEST
    fl.set_version(st, CORE_VERSION)
    assert st.opts.version == CORE_VERSION


def test_default_version_is_pinned() -> None:
    assert state().opts.version == CORE_VERSION


def test_version_field_prompt_matches_policy() -> None:
    spec = flows().field("setup_version")
    assert CORE_VERSION in spec.hint
    assert "latest" in spec.hint
