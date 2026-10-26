from __future__ import annotations

import asyncio
import io
import os
import shlex
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .models import AUTH_KEY, SshSettings
from .sshx import SshClient, SshError, SshOutput, wrap_sudo

INSTALL_DIR = "/opt/obhod"
STATE_DIR = "/var/lib/obhod"
ENV_FILE = "/etc/obhod/obhod.env"
UNIT_PATH = "/etc/systemd/system/obhod.service"
PAYLOAD_ITEMS = ("BOT", "Storage", "requirements.txt", "run.sh", "pytest.ini")
REFUSAL = "установка возможна только от root, запустите sudo bash run.sh bootstrap"


class BootstrapError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def check_root(euid: int | None = None) -> None:
    value = os.geteuid() if euid is None else int(euid)
    if value != 0:
        raise BootstrapError(REFUSAL)


def verify_admin(user_id: int, expected: int) -> tuple[bool, int, str]:
    who = int(user_id or 0)
    want = int(expected or 0)
    if who <= 0:
        return False, want, "идентификатор не получен"
    if want <= 0:
        return True, who, "администратор закреплен"
    if who != want:
        return False, want, f"идентификатор {who} не совпадает с ожидаемым {want}"
    return True, want, "идентификатор совпал"


@dataclass
class BootstrapPlan:
    host: str = ""
    port: int = 22
    user: str = "root"
    password: str = ""
    key: str = ""
    passphrase: str = ""
    token: str = ""
    api_id: int = 0
    api_hash: str = ""
    admin_id: int = 0
    install_dir: str = INSTALL_DIR
    state_dir: str = STATE_DIR
    python: str = "python3"
    dev: bool = False
    check: bool = False
    steps: list[str] = field(default_factory=list)

    def settings(self) -> SshSettings:
        auth = AUTH_KEY if self.key.strip() else "PASSWORD"
        return SshSettings(
            host=self.host or "127.0.0.1",
            port=int(self.port),
            user=self.user or "root",
            auth=auth,
            password=self.password,
            key=self.key,
            passphrase=self.passphrase,
            mode="ROOT",
        )

    def env_text(self) -> str:
        pairs = [
            ("BOT_TOKEN", self.token),
            ("API_ID", str(self.api_id)),
            ("API_HASH", self.api_hash),
            ("ADMIN_ID", str(self.admin_id)),
            ("OBHOD_STATE_DIR", self.state_dir),
            ("OBHOD_INSTALL_SCRIPT", self.install_dir + "/Storage/install.sh"),
            ("OBHOD_LOG_LEVEL", "INFO"),
        ]
        return "\n".join(f"{name}={value}" for name, value in pairs) + "\n"


def parse_args(argv: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {"dev": False, "check": False}
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in {"--dev", "--check"}:
            out[token[2:]] = True
            index += 1
            continue
        if not token.startswith("--"):
            index += 1
            continue
        body = token[2:]
        if "=" in body:
            key, value = body.split("=", 1)
        else:
            key = body
            value = argv[index + 1] if index + 1 < len(argv) else ""
            index += 1
        out[key.replace("-", "_")] = value
        index += 1
    return out


def plan_from(args: dict[str, Any]) -> BootstrapPlan:
    return BootstrapPlan(
        host=str(args.get("ssh_host") or args.get("host") or ""),
        port=int(args.get("ssh_port") or args.get("port") or 22),
        user=str(args.get("ssh_user") or "root"),
        password=str(args.get("ssh_password") or ""),
        key=str(args.get("ssh_key") or ""),
        passphrase=str(args.get("ssh_passphrase") or ""),
        token=str(args.get("token") or args.get("bot_token") or ""),
        api_id=int(args.get("api_id") or 0),
        api_hash=str(args.get("api_hash") or ""),
        admin_id=int(args.get("admin_id") or 0),
        install_dir=str(args.get("install_dir") or INSTALL_DIR),
        state_dir=str(args.get("state_dir") or STATE_DIR),
        dev=bool(args.get("dev", False)),
        check=bool(args.get("check", False)),
    )


UNIT_TEMPLATE = """[Unit]
Description=OBHOD bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={root}
EnvironmentFile={env}
ExecStart={root}/.venv/bin/python -m BOT
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""


def install_script(plan: BootstrapPlan, phase: str = "deps") -> str:
    head = [
        "set -euo pipefail",
        f"ROOT={plan.install_dir}",
        f"STATE={plan.state_dir}",
        f"ENV_FILE={ENV_FILE}",
        f"UNIT={UNIT_PATH}",
        f'PY="${{PYTHON:-{plan.python}}}"',
        'if [ "$(id -u)" != "0" ]; then printf \'%s\\n\' "нужен root на сервере"; exit 1; fi',
        'if ! command -v "$PY" >/dev/null 2>&1; then printf \'%s\\n\' "нет python3 на сервере"; exit 1; fi',
        'mkdir -p "$ROOT" "$STATE" "$(dirname "$ENV_FILE")"',
        'chmod 700 "$STATE"',
    ]
    lines = list(head)
    if phase == "deps":
        lines.extend(
            [
                'rm -rf "$ROOT/.venv"',
                '"$PY" -m venv "$ROOT/.venv"',
                '"$ROOT/.venv/bin/pip" install --quiet --upgrade pip',
                '"$ROOT/.venv/bin/pip" install --quiet -r "$ROOT/requirements.txt"',
                'printf \'%s\\n\' "зависимости установлены"',
            ]
        )
    if phase == "finalize":
        lines.extend(
            [
                'cat > "$ENV_FILE" <<OBHODENV',
                plan.env_text().rstrip("\n"),
                "OBHODENV",
                'chmod 600 "$ENV_FILE"',
                'cat > "$UNIT" <<OBHODUNIT',
                UNIT_TEMPLATE.format(root=plan.install_dir, env=ENV_FILE).rstrip("\n"),
                "OBHODUNIT",
                'chmod 644 "$UNIT"',
                "if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then",
                "  systemctl daemon-reload",
                "  systemctl enable obhod.service >/dev/null 2>&1 || true",
                "  systemctl restart obhod.service",
                '  printf \'%s\\n\' "служба запущена через systemd"',
                "else",
                '  printf \'%s\\n\' "systemd недоступен, запустите вручную"',
                "fi",
            ]
        )
    lines.append('printf \'%s\\n\' "готово"')
    return "\n".join(lines) + "\n"


def payload_archive(root: Path | None = None) -> bytes:
    base = Path(root or Path(__file__).resolve().parent.parent)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name in PAYLOAD_ITEMS:
            target = base / name
            if not target.exists():
                continue
            bundle.add(target, arcname=name, filter=_skip_cache)
    return buffer.getvalue()


def _skip_cache(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    parts = Path(info.name).parts
    if any(part in {"__pycache__", ".pytest_cache", ".venv"} for part in parts):
        return None
    return info


CHECK_SCRIPT = """set -u
if [ "$(id -u)" != "0" ]; then printf 'root=no\\n'; else printf 'root=yes\\n'; fi
if command -v python3 >/dev/null 2>&1; then printf 'python=%s\\n' "$(python3 -c 'import sys;print(sys.version.split()[0])')"; else printf 'python=none\\n'; fi
if command -v systemctl >/dev/null 2>&1; then printf 'systemd=yes\\n'; else printf 'systemd=no\\n'; fi
if command -v tar >/dev/null 2>&1; then printf 'tar=yes\\n'; else printf 'tar=no\\n'; fi
printf 'disk=%s\\n' "$(df -Pk / | awk 'NR==2 {print $4}')"
python3 - <<'CHECKPY' 2>/dev/null || true
import socket
def probe(host, port):
    try:
        with socket.create_connection((host, port), timeout=5):
            return "yes"
    except OSError:
        return "no"
print("github=" + probe("github.com", 443))
print("telegram=" + probe("api.telegram.org", 443))
CHECKPY
printf 'check done\\n'
"""


async def check_plan(ssh: SshClient, cfg: SshSettings, plan: BootstrapPlan) -> list[tuple[str, bool, str]]:
    out = await ssh.run(cfg, wrap_sudo("bash -s", cfg.mode), stdin=CHECK_SCRIPT.encode("utf-8"), timeout=180)
    values: dict[str, str] = {}
    for line in out.text.splitlines():
        token = line.strip()
        if "=" in token and not token.startswith("check"):
            key, value = token.split("=", 1)
            values[key.strip()] = value.strip()
    checks: list[tuple[str, bool, str]] = []
    checks.append(("root на сервере", values.get("root") == "yes", values.get("root", "нет ответа")))
    python = values.get("python", "none")
    checks.append(("python3", python not in {"", "none"}, python))
    systemd = values.get("systemd") == "yes"
    checks.append(("systemd", systemd, "есть" if systemd else "нет, запуск через процесс"))
    tar = values.get("tar") == "yes"
    checks.append(("tar", tar, "есть" if tar else "нет"))
    disk = values.get("disk", "0")
    try:
        free_gb = int(disk) / 1024 / 1024
    except ValueError:
        free_gb = 0.0
    checks.append(("свободное место", free_gb >= 1.0, f"{free_gb:.1f} ГБ"))
    github = values.get("github") == "yes"
    checks.append(("github с сервера", github, "доступен" if github else "недоступен"))
    telegram = values.get("telegram") == "yes"
    checks.append(("telegram с сервера", telegram, "доступен" if telegram else "недоступен"))
    return checks


def format_checks(checks: list[tuple[str, bool, str]]) -> list[str]:
    lines = []
    for name, ok, detail in checks:
        mark = "ok" if ok else "нет"
        lines.append(f"{mark} {name}: {detail}")
    return lines


async def run_script(ssh: SshClient, cfg: SshSettings, script: str, timeout: float = 600.0) -> SshOutput:
    command = wrap_sudo("bash -s", cfg.mode)
    return await ssh.run(cfg, command, stdin=script.encode("utf-8"), timeout=timeout)


async def push_files(ssh: SshClient, cfg: SshSettings, blob: bytes, plan: BootstrapPlan) -> SshOutput:
    prepare = await ssh.run(
        cfg,
        wrap_sudo(f"mkdir -p {shlex.quote(plan.install_dir)} {shlex.quote(plan.state_dir)}", cfg.mode),
        timeout=120,
    )
    if prepare.code != 0:
        return prepare
    command = wrap_sudo("tar -xzf - -C " + shlex.quote(plan.install_dir), cfg.mode)
    return await ssh.run(cfg, command, stdin=blob, timeout=600)


async def install_files(ssh: SshClient, cfg: SshSettings, blob: bytes, plan: BootstrapPlan) -> list[SshOutput]:
    out: list[SshOutput] = []
    out.append(await push_files(ssh, cfg, blob, plan))
    if out[-1].code == 0:
        out.append(await run_script(ssh, cfg, install_script(plan, "deps")))
    return out


async def bootstrap(
    plan: BootstrapPlan,
    ssh: SshClient | None = None,
    payload: bytes | None = None,
    confirm: Callable[[], Any] | None = None,
    on_step: Callable[[str], Any] | None = None,
) -> list[str]:
    check_root(0 if not plan.dev else os.geteuid())
    client = ssh or SshClient()
    cfg = plan.settings()
    steps: list[str] = []

    async def note(text: str) -> None:
        steps.append(text)
        if on_step is not None:
            result = on_step(text)
            if hasattr(result, "__await__"):
                await result

    await note("проверка root пройдена")
    if not plan.host:
        raise BootstrapError("не задан адрес сервера для установки")
    if not plan.token:
        raise BootstrapError("не задан токен бота")
    await note(f"передача файлов бота на {plan.user}@{plan.host}")
    try:
        outs = await install_files(client, cfg, payload if payload is not None else payload_archive(), plan)
    except SshError as exc:
        raise BootstrapError(f"установка по ssh не выполнена: {exc.message}") from None
    for out in outs:
        if out.code != 0:
            raise BootstrapError("установка по ssh завершилась с ошибкой: " + out.text[-300:])
    await note("файлы и зависимости установлены")
    await note("ожидание идентификатора администратора")
    if confirm is not None:
        result = confirm()
        if hasattr(result, "__await__"):
            result = await result
        user_id = int(result or 0)
    else:
        user_id = int(plan.admin_id or 0)
    ok, admin_id, message = verify_admin(user_id, plan.admin_id)
    if not ok:
        raise BootstrapError(message)
    plan.admin_id = admin_id
    await note(message)
    try:
        out = await run_script(client, cfg, install_script(plan, "finalize"))
    except SshError as exc:
        raise BootstrapError(f"запуск службы не выполнен: {exc.message}") from None
    if out.code != 0:
        raise BootstrapError("запуск службы завершился с ошибкой: " + out.text[-300:])
    await note("служба установлена и запущена")
    await note("дальнейшие шаги выполняются в боте")
    return steps


def run(argv: list[str] | None = None) -> int:
    import sys

    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    plan = plan_from(args)
    try:
        check_root()
        if plan.check:
            return asyncio.run(check_only(plan))
        steps = asyncio.run(bootstrap(plan))
    except BootstrapError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    for line in steps:
        print(line)
    return 0


async def check_only(plan: BootstrapPlan, ssh: SshClient | None = None) -> int:
    if not plan.host:
        raise BootstrapError("не задан адрес сервера для проверки")
    client = ssh or SshClient()
    try:
        checks = await check_plan(client, plan.settings(), plan)
    except SshError as exc:
        raise BootstrapError(f"проверка по ssh не выполнена: {exc.message}") from None
    for line in format_checks(checks):
        print(line)
    return 0 if all(item[1] for item in checks) else 1


def main(argv: list[str] | None = None) -> int:
    return run(argv)


def unit_text(plan: BootstrapPlan) -> str:
    return UNIT_TEMPLATE.format(root=plan.install_dir, env=ENV_FILE)
