from __future__ import annotations

import base64
import hashlib
import json
import shlex
from dataclasses import dataclass, field
from typing import Any

from .models import SshSettings
from .sshx import MODE_SUDO_PASS, SshClient, SshError, SshOutput, wrap_sudo

PROTO = 3
DEFAULT_VERSION = "v26.10.21"
UNIT_NAME = "xray.service"
CORE_NAME = "xray"

PINNED_SHA256 = {
    "64": "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978",
}

ASSET_BY_ARCH = {
    "x86_64": "64",
    "amd64": "64",
    "aarch64": "arm64-v8a",
    "arm64": "arm64-v8a",
    "armv7l": "arm32-v7a",
    "armv7": "arm32-v7a",
    "armv6l": "arm32-v6",
    "i686": "32",
    "i386": "32",
    "s390x": "s390x",
    "riscv64": "riscv64",
}

RELEASE_URL = "https://github.com/XTLS/Xray-core/releases/download/{version}/Xray-linux-{asset}.zip"
DGST_URL = RELEASE_URL + ".dgst"

XRAY_ERROR_CODES = {
    "bad_arg": "неверные аргументы",
    "needs_root": "нужны права root на сервере",
    "no_python": "на сервере нет python3",
    "unsupported_arch": "архитектура сервера не поддерживается",
    "download_failed": "не удалось скачать релиз ядра",
    "digest_mismatch": "хеш скачанного архива не совпал",
    "unpack_failed": "не удалось распаковать архив ядра",
    "config_invalid": "конфигурация ядра отклонена",
    "config_missing": "конфигурация не задана",
    "no_systemd": "на сервере нет systemd",
    "start_failed": "ядро не запустилось",
    "not_installed": "ядро не установлено",
    "port_busy": "порт занят на сервере",
    "not_found": "не найдено",
    "internal": "внутренняя ошибка скрипта ядра",
    "transport": "сбой транспорта до сервера",
    "proto_mismatch": "версия протокола скрипта ядра не совпадает",
}

REMOTE_SCRIPT = r'''
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

PROTO = 3
PINNED = "v26.10.21"
ASSETS = {
    "x86_64": "64",
    "amd64": "64",
    "aarch64": "arm64-v8a",
    "arm64": "arm64-v8a",
    "armv7l": "arm32-v7a",
    "armv7": "arm32-v7a",
    "armv6l": "arm32-v6",
    "i686": "32",
    "i386": "32",
    "s390x": "s390x",
    "riscv64": "riscv64",
}
DIGESTS = {"64": "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978"}
ROOT = os.environ.get("XRAY_ROOT", "")
LOGS = []


def path_of(base):
    return os.path.join(ROOT, base.lstrip("/")) if ROOT else base


CORE = path_of("/usr/local/bin/xray")
CONF_DIR = path_of("/usr/local/etc/xray")
CONF = os.path.join(CONF_DIR, "config.json")
SHARE = path_of("/usr/local/share/xray")
UNIT_DIR = path_of("/etc/systemd/system")
UNIT = os.path.join(UNIT_DIR, "xray.service")
STATE = path_of("/var/lib/xray-manager")


def note(text):
    LOGS.append(str(text))


def machine():
    return os.uname().machine


def asset_for(arch):
    return ASSETS.get(arch, "")


def sha256_file(target):
    digest = hashlib.sha256()
    with open(target, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def run(argv, timeout=180, check=False):
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    text = proc.stdout.decode("utf-8", "replace").strip()
    if check and proc.returncode != 0:
        raise ScriptError("internal", "команда завершилась с кодом %s: %s" % (proc.returncode, text[:400]))
    return proc.returncode, text


def has_systemd():
    if os.environ.get("XRAY_NO_SYSTEMD"):
        return False
    return os.path.isdir("/run/systemd/system") and shutil.which("systemctl") is not None


class ScriptError(Exception):
    def __init__(self, code, message, stage=""):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.stage = stage


def core_version():
    if not os.path.isfile(CORE):
        return ""
    try:
        code, text = run([CORE, "version"], timeout=20)
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in text.splitlines():
        token = line.strip()
        if token.startswith("Xray"):
            parts = token.split()
            if len(parts) >= 2:
                return parts[1]
    return ""


def config_digest():
    if not os.path.isfile(CONF):
        return ""
    return sha256_file(CONF)


def read_config():
    if not os.path.isfile(CONF):
        return {}
    try:
        with open(CONF, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def listen_ports(config):
    ports = []
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        port = inbound.get("port")
        if isinstance(port, int) and port not in ports:
            ports.append(port)
    return ports


def port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.5)
        return sock.connect_ex(("127.0.0.1", int(port))) == 0


def unit_state():
    if not os.path.isfile(UNIT):
        if has_systemd():
            return "absent"
        return pid_state()
    if not has_systemd():
        return pid_state()
    code, text = run(["systemctl", "is-active", "xray.service"], timeout=20)
    token = text.strip().splitlines()[0] if text.strip() else ""
    return token or "unknown"


def pid_file():
    return os.path.join(STATE, "xray.pid")


def pid_state():
    target = pid_file()
    if not os.path.isfile(target):
        return "inactive"
    try:
        with open(target, "r", encoding="utf-8") as handle:
            pid = int(handle.read().strip() or 0)
    except (OSError, ValueError):
        return "inactive"
    if pid <= 0:
        return "inactive"
    try:
        os.kill(pid, 0)
    except OSError:
        return "inactive"
    return "active"


def write_state(pid):
    if not os.path.isdir(STATE):
        os.makedirs(STATE, exist_ok=True)
    with open(pid_file(), "w", encoding="utf-8") as handle:
        handle.write(str(pid))


def stop_core():
    if has_systemd() and os.path.isfile(UNIT):
        run(["systemctl", "stop", "xray.service"], timeout=90)
        return
    target = pid_file()
    if not os.path.isfile(target):
        return
    try:
        with open(target, "r", encoding="utf-8") as handle:
            pid = int(handle.read().strip() or 0)
    except (OSError, ValueError):
        pid = 0
    if pid > 0:
        try:
            os.kill(pid, 15)
            for _ in range(40):
                try:
                    os.kill(pid, 0)
                except OSError:
                    break
                time.sleep(0.25)
        except OSError:
            pass
    try:
        os.unlink(target)
    except OSError:
        pass


def start_core():
    if has_systemd():
        write_unit()
        run(["systemctl", "daemon-reload"], timeout=60)
        code, text = run(["systemctl", "enable", "xray.service"], timeout=90)
        if code != 0:
            note("enable: " + text[:200])
        code, text = run(["systemctl", "restart", "xray.service"], timeout=120)
        if code != 0:
            raise ScriptError("start_failed", "systemctl restart: " + text[:400], "start")
        return
    if not os.path.isdir(STATE):
        os.makedirs(STATE, exist_ok=True)
    log_path = os.path.join(STATE, "xray.log")
    env = dict(os.environ)
    env["XRAY_LOCATION_ASSET"] = SHARE
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(
            [CORE, "run", "-c", CONF],
            stdout=log,
            stderr=log,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    write_state(proc.pid)
    time.sleep(0.8)
    if proc.poll() is not None:
        raise ScriptError("start_failed", "ядро завершилось сразу после старта", "start")


def write_unit():
    if not os.path.isdir(UNIT_DIR):
        os.makedirs(UNIT_DIR, exist_ok=True)
    body = "\n".join(
        [
            "[Unit]",
            "Description=Xray Service",
            "Documentation=https://github.com/XTLS/Xray-core",
            "After=network.target nss-lookup.target",
            "",
            "[Service]",
            "User=root",
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
            "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
            "NoNewPrivileges=true",
            "Environment=XRAY_LOCATION_ASSET=" + SHARE,
            "ExecStart=" + CORE + " run -c " + CONF,
            "Restart=on-failure",
            "RestartPreventExitStatus=23",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    with open(UNIT, "w", encoding="utf-8") as handle:
        handle.write(body)
    note("unit written")


def download(url, target):
    if url.startswith("file://"):
        source = url[len("file://") :]
        shutil.copyfile(source, target)
        return
    request = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
    with urllib.request.urlopen(request, timeout=120) as response:
        with open(target, "wb") as handle:
            shutil.copyfileobj(response, handle, 1 << 20)


def latest_tag(timeout=15):
    try:
        request = urllib.request.Request(
            "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
            headers={"User-Agent": "curl/8.5.0", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError):
        return ""
    tag = str(body.get("tag_name", "") or "").strip()
    return tag if tag.startswith("v") else ""


def fetch_digest(version, asset, url):
    if url:
        base = url
    else:
        base = "https://github.com/XTLS/Xray-core/releases/download/%s/Xray-linux-%s.zip" % (version, asset)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "core.dgst")
            download(base + ".dgst", target)
            with open(target, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    token = line.strip()
                    if token.upper().startswith("SHA2-256="):
                        return token.split("=", 1)[1].strip().lower()
    except (OSError, ValueError):
        return ""
    return ""


def install_core(version, url, sha256, force):
    asset = asset_for(machine())
    if not asset:
        raise ScriptError("unsupported_arch", "архитектура %s не поддерживается" % machine(), "download")
    current = core_version()
    if current and current.lstrip("v") == version.lstrip("v") and os.path.isfile(CORE) and not force:
        note("ядро уже установлено: " + version)
        return {"version": current, "core_path": CORE, "downloaded": False, "sha256": sha256_file(CORE)}
    if not url:
        url = "https://github.com/XTLS/Xray-core/releases/download/%s/Xray-linux-%s.zip" % (version, asset)
    expected = (sha256 or "").strip().lower()
    if not expected:
        expected = fetch_digest(version, asset, url if not url.startswith("file://") else "")
    if not expected and version == PINNED:
        expected = DIGESTS.get(asset, "")
    note("скачивание " + url)
    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, "core.zip")
        try:
            download(url, archive)
        except (OSError, ValueError) as exc:
            raise ScriptError("download_failed", "загрузка не удалась: %s" % exc, "download")
        if expected:
            actual = sha256_file(archive)
            if actual != expected:
                raise ScriptError(
                    "digest_mismatch",
                    "ожидался %s, получен %s" % (expected, actual),
                    "download",
                )
            note("хеш совпал")
        else:
            note("хеш не проверен, источник без подписи")
        try:
            with zipfile.ZipFile(archive) as bundle:
                member = None
                for name in bundle.namelist():
                    if name.rstrip("/").split("/")[-1] == "xray":
                        member = name
                        break
                if member is None:
                    raise ScriptError("unpack_failed", "в архиве нет файла xray", "unpack")
                target_dir = os.path.dirname(CORE)
                if not os.path.isdir(target_dir):
                    os.makedirs(target_dir, exist_ok=True)
                with bundle.open(member) as source, open(CORE, "wb") as handle:
                    shutil.copyfileobj(source, handle, 1 << 20)
                for extra in ("geoip.dat", "geosite.dat"):
                    for name in bundle.namelist():
                        if name.rstrip("/").split("/")[-1] == extra:
                            payload = bundle.read(name)
                            for folder in (SHARE, os.path.dirname(CORE)):
                                if not os.path.isdir(folder):
                                    os.makedirs(folder, exist_ok=True)
                                with open(os.path.join(folder, extra), "wb") as handle:
                                    handle.write(payload)
        except zipfile.BadZipFile as exc:
            raise ScriptError("unpack_failed", "архив поврежден: %s" % exc, "unpack")
        except OSError as exc:
            raise ScriptError("unpack_failed", "распаковка не удалась: %s" % exc, "unpack")
    os.chmod(CORE, 0o755)
    installed = core_version()
    if not installed:
        raise ScriptError("start_failed", "ядро не отвечает на version", "verify")
    note("ядро установлено: " + installed)
    return {"version": installed, "core_path": CORE, "downloaded": True, "sha256": sha256_file(CORE)}


def test_config(payload):
    if not payload:
        raise ScriptError("config_missing", "конфигурация не передана", "config")
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "ядро не установлено", "config")
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "config.json")
        with open(target, "wb") as handle:
            handle.write(payload)
        code, text = run([CORE, "run", "-test", "-c", target], timeout=60)
    return code == 0, text


def write_config(payload):
    if not payload:
        raise ScriptError("config_missing", "конфигурация не передана", "config")
    config = json.loads(payload.decode("utf-8"))
    if not isinstance(config, dict) or not config.get("inbounds"):
        raise ScriptError("config_invalid", "в конфигурации нет ни одного inbound", "config")
    ok, text = test_config(payload)
    if not ok:
        raise ScriptError("config_invalid", text[:600] or "ядро отклонило конфигурацию", "config")
    if not os.path.isdir(CONF_DIR):
        os.makedirs(CONF_DIR, exist_ok=True)
    with open(CONF, "wb") as handle:
        handle.write(payload)
    note("конфигурация записана")
    return config


def state_report():
    config = read_config()
    ports = listen_ports(config)
    service = unit_state()
    listening = [port for port in ports if port_open(port)]
    return {
        "installed": os.path.isfile(CORE),
        "version": core_version(),
        "pinned": PINNED,
        "core_path": CORE,
        "config_path": CONF,
        "config_exists": os.path.isfile(CONF),
        "config_digest": config_digest(),
        "inbounds": len(config.get("inbounds") or []),
        "port": ports[0] if ports else 0,
        "ports": ports,
        "listening": listening,
        "service": service,
        "unit": os.path.isfile(UNIT),
        "systemd": has_systemd(),
        "arch": machine(),
        "asset": asset_for(machine()),
    }


def parse_flags(tokens):
    flags = {}
    rest = []
    for token in tokens:
        if token.startswith("--"):
            body = token[2:]
            if "=" in body:
                key, value = body.split("=", 1)
                flags[key.replace("-", "_")] = value
            else:
                flags[body.replace("-", "_")] = True
        else:
            rest.append(token)
    return flags, rest


def payload_of(flags, name):
    value = flags.get(name, "")
    if not value:
        return b""
    try:
        return base64.b64decode(value)
    except (ValueError, TypeError):
        raise ScriptError("bad_arg", "поле %s не декодируется" % name, "args")


def version_of(flags):
    version = str(flags.get("version", PINNED)).strip()
    if version.lower() in {"latest", "auto", ""}:
        return "latest"
    if not version.startswith("v"):
        version = "v" + version
    return version


def cmd_probe(flags, rest):
    return state_report(), None


def wants_latest(version):
    return version.strip().lower() in {"latest", "auto", ""}


def pinned_with_fallback(version, url, sha256, force, tag="", fallback_url="", fallback_sha256=""):
    resolved = version
    requested_latest = wants_latest(version)
    if requested_latest:
        resolved = str(tag or "").strip() or latest_tag()
        if resolved:
            note("последний релиз: " + resolved)
        else:
            resolved = PINNED
            note("github api недоступен, берем закрепленный " + PINNED)
    try:
        data = install_core(resolved, url, sha256, force)
        data["fallback"] = False
        return data
    except ScriptError as exc:
        if exc.code != "download_failed" or not requested_latest:
            raise
        note("скачивание " + resolved + " не удалось, фолбек на " + PINNED)
        data = install_core(PINNED, str(fallback_url or ""), str(fallback_sha256 or ""), True)
        data["fallback"] = True
        data["fallback_version"] = PINNED
        return data


def cmd_install(flags, rest):
    version = version_of(flags)
    url = str(flags.get("url", ""))
    sha256 = str(flags.get("sha256", ""))
    force = bool(flags.get("force", False))
    tag = str(flags.get("tag", ""))
    fallback_url = str(flags.get("fallback_url", ""))
    fallback_sha256 = str(flags.get("fallback_sha256", ""))
    data = pinned_with_fallback(version, url, sha256, force, tag, fallback_url, fallback_sha256)
    data.update(state_report())
    return data, None


def cmd_apply(flags, rest):
    payload = payload_of(flags, "config_b64")
    version = version_of(flags)
    install = {}
    if not os.path.isfile(CORE):
        install = pinned_with_fallback(
            version,
            str(flags.get("url", "")),
            str(flags.get("sha256", "")),
            False,
            str(flags.get("tag", "")),
            str(flags.get("fallback_url", "")),
            str(flags.get("fallback_sha256", "")),
        )
    config = write_config(payload)
    if not flags.get("no_restart", False):
        stop_core()
        start_core()
        ports = listen_ports(config)
        deadline = time.time() + 12
        while time.time() < deadline:
            if all(port_open(port) for port in ports):
                break
            time.sleep(0.4)
        data = state_report()
        if data["service"] not in ("active", "unknown") and has_systemd():
            raise ScriptError("start_failed", "служба не активна: " + str(data["service"]), "start")
        if ports and not data["listening"]:
            raise ScriptError("start_failed", "порты не открылись: " + str(ports), "start")
    else:
        data = state_report()
    data["applied"] = True
    data["config_digest"] = sha256_bytes(payload)
    if install:
        data["fallback"] = bool(install.get("fallback", False))
        if data["fallback"]:
            data["fallback_version"] = str(install.get("fallback_version", PINNED))
    return data, None


def cmd_test(flags, rest):
    payload = payload_of(flags, "config_b64")
    ok, text = test_config(payload)
    return {"valid": ok, "output": text[:4000]}, None


def cmd_restart(flags, rest):
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "ядро не установлено", "restart")
    if not os.path.isfile(CONF):
        raise ScriptError("config_missing", "конфигурация не задана", "restart")
    stop_core()
    start_core()
    time.sleep(0.6)
    return state_report(), None


def cmd_stop(flags, rest):
    stop_core()
    return state_report(), None


def cmd_start(flags, rest):
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "ядро не установлено", "start")
    start_core()
    time.sleep(0.6)
    return state_report(), None


def cmd_logs(flags, rest):
    tail = int(str(flags.get("tail", "120")))
    lines = []
    if has_systemd():
        code, text = run(["journalctl", "-u", "xray.service", "-n", str(tail), "--no-pager"], timeout=60)
        lines = [line for line in text.splitlines()]
    log_path = os.path.join(STATE, "xray.log")
    if not lines and os.path.isfile(log_path):
        with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()[-tail:]
    return {"lines": lines[-tail:]}, None


def cmd_x25519(flags, rest):
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "ядро не установлено", "keys")
    code, text = run([CORE, "x25519"], timeout=30)
    if code != 0:
        raise ScriptError("internal", "ядро не выдало ключи: " + text[:200], "keys")
    private = ""
    public = ""
    for line in text.splitlines():
        token = line.strip()
        lower = token.lower()
        if lower.startswith("private") or lower.startswith("privatekey"):
            private = token.split(":", 1)[1].strip() if ":" in token else token.split()[-1]
        elif lower.startswith("public") or lower.startswith("password"):
            public = token.split(":", 1)[1].strip() if ":" in token else token.split()[-1]
    if not private or not public:
        raise ScriptError("internal", "ответ ядра не разобран: " + text[:200], "keys")
    return {"private": private, "public": public}, None


def cmd_uninstall(flags, rest):
    stop_core()
    removed = []
    if os.path.isfile(UNIT):
        if has_systemd():
            run(["systemctl", "disable", "xray.service"], timeout=60)
        os.unlink(UNIT)
        if has_systemd():
            run(["systemctl", "daemon-reload"], timeout=60)
        removed.append("unit")
    if flags.get("purge", False):
        for target in (CONF_DIR, SHARE, STATE):
            if os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
                removed.append(target)
        if os.path.isfile(CORE):
            os.unlink(CORE)
            removed.append(CORE)
    return {"removed": removed, "purge": bool(flags.get("purge", False))}, None


COMMANDS = {
    "probe": cmd_probe,
    "install-core": cmd_install,
    "apply": cmd_apply,
    "test-config": cmd_test,
    "restart": cmd_restart,
    "stop": cmd_stop,
    "start": cmd_start,
    "logs": cmd_logs,
    "x25519": cmd_x25519,
    "uninstall": cmd_uninstall,
}


def emit(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stdout.flush()


def main(argv):
    if not argv:
        emit({"proto": PROTO, "result": "err", "code": "bad_arg", "msg": "не передана команда", "stage": "args"})
        return 2
    name = argv[0]
    handler = COMMANDS.get(name)
    if handler is None:
        emit({"proto": PROTO, "result": "err", "code": "bad_arg", "msg": "неизвестная команда %s" % name, "stage": "args"})
        return 2
    flags, rest = parse_flags(argv[1:])
    try:
        data, _ = handler(flags, rest)
    except ScriptError as exc:
        emit(
            {
                "proto": PROTO,
                "result": "err",
                "code": exc.code,
                "msg": exc.message,
                "stage": exc.stage,
                "logs": LOGS,
            }
        )
        return 1
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        emit({"proto": PROTO, "result": "err", "code": "internal", "msg": str(exc)[:600], "stage": name, "logs": LOGS})
        return 1
    emit({"proto": PROTO, "result": "ok", "data": data, "logs": LOGS})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''

def _bootstrap_code() -> str:
    encoded = base64.b64encode(REMOTE_SCRIPT.encode("utf-8")).decode("ascii")
    return "import base64,sys;exec(base64.b64decode(%r).decode('utf-8'))" % encoded


def remote_command(argv: list[str]) -> str:
    code = _bootstrap_code()
    parts = [
        "PY=$(command -v python3 || command -v python);",
        '[ -n "$PY" ] || { printf \'%s\\n\' \'{"proto":3,"result":"err","code":"no_python",'
        '"msg":"no python","stage":"args"}\'; exit 1; };',
        'exec "$PY" -c ' + shlex.quote(code),
    ]
    for item in argv:
        parts.append(shlex.quote(str(item)))
    return " ".join(parts)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@dataclass
class XrayResponse:
    result: str = "err"
    code: str = ""
    msg: str = ""
    stage: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)
    proto: int = PROTO

    @property
    def ok(self) -> bool:
        return self.result == "ok"

    def raise_for_status(self) -> None:
        if self.ok:
            return
        text = self.msg or XRAY_ERROR_CODES.get(self.code, self.code) or "неизвестная ошибка"
        if self.stage and self.code != "bad_arg":
            text = f"{text} (этап {self.stage})"
        raise XrayError(text, self.code or "internal")


class XrayError(Exception):
    def __init__(self, message: str, code: str = "internal") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass
class CoreState:
    installed: bool = False
    version: str = ""
    pinned: str = DEFAULT_VERSION
    core_path: str = ""
    config_path: str = ""
    config_exists: bool = False
    config_digest: str = ""
    inbounds: int = 0
    port: int = 0
    ports: list[int] = field(default_factory=list)
    listening: list[int] = field(default_factory=list)
    service: str = "absent"
    unit: bool = False
    systemd: bool = False
    arch: str = ""
    asset: str = ""
    fallback: bool = False
    fallback_version: str = ""

    @property
    def running(self) -> bool:
        return self.service == "active"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CoreState:
        raw = raw or {}
        return cls(
            installed=bool(raw.get("installed", False)),
            version=str(raw.get("version", "") or ""),
            pinned=str(raw.get("pinned", DEFAULT_VERSION) or DEFAULT_VERSION),
            core_path=str(raw.get("core_path", "") or ""),
            config_path=str(raw.get("config_path", "") or ""),
            config_exists=bool(raw.get("config_exists", False)),
            config_digest=str(raw.get("config_digest", "") or ""),
            inbounds=int(raw.get("inbounds", 0) or 0),
            port=int(raw.get("port", 0) or 0),
            ports=[int(item) for item in raw.get("ports") or []],
            listening=[int(item) for item in raw.get("listening") or []],
            service=str(raw.get("service", "absent") or "absent"),
            unit=bool(raw.get("unit", False)),
            systemd=bool(raw.get("systemd", False)),
            arch=str(raw.get("arch", "") or ""),
            asset=str(raw.get("asset", "") or ""),
            fallback=bool(raw.get("fallback", False)),
            fallback_version=str(raw.get("fallback_version", "") or ""),
        )


def parse_response(text: str) -> XrayResponse:
    payload = ""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            payload = stripped
    if not payload:
        raise XrayError((text or "").strip()[:400] or "скрипт ядра не вернул ответ", "transport")
    try:
        raw = json.loads(payload)
    except ValueError:
        raise XrayError(f"ответ не разобран: {payload[:200]}", "transport") from None
    if not isinstance(raw, dict):
        raise XrayError("ответ не является объектом", "transport")
    response = XrayResponse(
        result=str(raw.get("result", "err")),
        code=str(raw.get("code", "") or ""),
        msg=str(raw.get("msg", "") or ""),
        stage=str(raw.get("stage", "") or ""),
        data=raw.get("data") if isinstance(raw.get("data"), dict) else {},
        logs=[str(item) for item in raw.get("logs") or []],
        proto=int(raw.get("proto", 0) or 0),
    )
    if response.proto != PROTO:
        raise XrayError(f"скрипт ядра отвечает протоколом {response.proto}, бот ждет {PROTO}", "proto_mismatch")
    return response


class XrayControl:
    def __init__(self, ssh: SshClient | None = None, timeout: float = 300.0) -> None:
        self.ssh = ssh or SshClient()
        self.timeout = float(timeout)

    def stdin_for(self, cfg: SshSettings) -> bytes:
        if cfg.mode == MODE_SUDO_PASS:
            password = (cfg.sudo_password or cfg.password or "").encode("utf-8")
            return password + b"\n"
        return b""

    async def call(self, cfg: SshSettings, argv: list[str], timeout: float | None = None) -> XrayResponse:
        command = wrap_sudo(remote_command(argv), cfg.mode)
        stdin = self.stdin_for(cfg)
        try:
            out: SshOutput = await self.ssh.run(cfg, command, stdin=stdin or None, timeout=timeout or self.timeout)
        except SshError as exc:
            raise XrayError(exc.message, "transport") from None
        return parse_response(out.text)

    async def probe(self, cfg: SshSettings) -> CoreState:
        response = await self.call(cfg, ["probe"], timeout=90)
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def install_core(
        self,
        cfg: SshSettings,
        version: str = DEFAULT_VERSION,
        url: str = "",
        sha256: str = "",
        force: bool = False,
    ) -> XrayResponse:
        argv = ["install-core", f"--version={version}"]
        if url:
            argv.append(f"--url={url}")
        if sha256:
            argv.append(f"--sha256={sha256}")
        if force:
            argv.append("--force")
        response = await self.call(cfg, argv, timeout=max(self.timeout, 600.0))
        response.raise_for_status()
        return response

    async def apply(self, cfg: SshSettings, config: str, version: str = DEFAULT_VERSION, restart: bool = True) -> CoreState:
        payload = config.encode("utf-8") if isinstance(config, str) else bytes(config)
        argv = ["apply", f"--config-b64={b64(payload)}", f"--version={version}"]
        if not restart:
            argv.append("--no-restart")
        response = await self.call(cfg, argv, timeout=max(self.timeout, 600.0))
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def test_config(self, cfg: SshSettings, config: str) -> tuple[bool, str]:
        payload = config.encode("utf-8") if isinstance(config, str) else bytes(config)
        response = await self.call(cfg, ["test-config", f"--config-b64={b64(payload)}"], timeout=120)
        response.raise_for_status()
        return bool(response.data.get("valid", False)), str(response.data.get("output", "") or "")

    async def restart(self, cfg: SshSettings) -> CoreState:
        response = await self.call(cfg, ["restart"], timeout=180)
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def stop(self, cfg: SshSettings) -> CoreState:
        response = await self.call(cfg, ["stop"], timeout=120)
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def start(self, cfg: SshSettings) -> CoreState:
        response = await self.call(cfg, ["start"], timeout=120)
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def logs(self, cfg: SshSettings, tail: int = 120) -> list[str]:
        response = await self.call(cfg, ["logs", f"--tail={int(tail)}"], timeout=120)
        response.raise_for_status()
        return [str(item) for item in response.data.get("lines") or []]

    async def x25519(self, cfg: SshSettings) -> tuple[str, str]:
        response = await self.call(cfg, ["x25519"], timeout=60)
        response.raise_for_status()
        return str(response.data.get("private", "") or ""), str(response.data.get("public", "") or "")

    async def uninstall(self, cfg: SshSettings, purge: bool = True) -> XrayResponse:
        argv = ["uninstall"]
        if purge:
            argv.append("--purge")
        response = await self.call(cfg, argv, timeout=180)
        response.raise_for_status()
        return response


def release_asset(version: str, asset: str) -> str:
    return RELEASE_URL.format(version=version, asset=asset)


def asset_of_arch(arch: str) -> str:
    return ASSET_BY_ARCH.get(arch, "")


def pinned_digest(arch: str) -> str:
    return PINNED_SHA256.get(ASSET_BY_ARCH.get(arch, ""), "")


def digest_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_dgst(body: str, key: str = "SHA2-256") -> str:
    for line in (body or "").splitlines():
        token = line.strip()
        if "=" not in token:
            continue
        name, value = token.split("=", 1)
        if name.strip().upper().replace("_", "-") == key.upper():
            return value.strip().lower()
    return ""


def parse_xray_version(text: str) -> str:
    for line in (text or "").splitlines():
        token = line.strip()
        if token.startswith("Xray"):
            parts = token.split()
            if len(parts) >= 2:
                return parts[1]
    return ""
