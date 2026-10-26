# OBHOD

Telegram bot over MTProto that installs and drives a [free-turn-proxy](https://github.com/hackdiaz-dev/free-turn-proxy) node on one server and hands out a single `freeturn://` link that works on Android and iOS alike.

Everything the user sees is a rich message: headings, tables, details blocks, code blocks, notice banners and big text buttons. Every button is a callback button built from `tg-button` markup with `callback_data`, never a link button. Nothing goes through the Bot API HTTP transport: the bot talks MTProto with `bot_token` + `api_id` + `api_hash`.

## What changed against the previous bot

| Area | Before | Now |
| --- | --- | --- |
| Transport | Bot API over HTTPS | MTProto, `default_transport="mtproto"`, `intake="mtproto"` |
| Interface | plain text with inline keyboards | rich messages, `tg-button` rows, streaming drafts |
| Links | separate iOS and Android builders | one `freeturn://` payload for both platforms |
| Servers | multi server with per server state | one server, one admin |
| Remote control | ad hoc shell snippets in `Storage/VKTurn` | RPC v3 of the upstream `install.sh` |
| Installer | user mode with sudo juggling | root only service, refuses non root, `--dev` for local tests |

## Layout

```
BOT/
  main.py       entry point, logging, signals
  app.py        router, admin gate, operations, draft orchestration
  screens.py    every screen as a rich message
  flows.py      text input fields, validation, state mutations
  drafts.py     streaming drafts over messages.setTyping
  control.py    install.sh RPC v3 client with typed responses
  sshx.py       asyncssh session, host key pinning, root mode detection
  links.py      freeturn codec, kcp profile, android core config
  models.py     dataclasses for settings, probe results, clients
  validate.py   input validators
  store.py      state.json with 0600 permissions
  ui.py         html and button helpers
Storage/
  install.sh          vendored upstream installer, byte identical
  obhod-install.sh    installer for this bot, root only
  obhod.service       systemd unit template
tests/          404 tests, mock control plus a real ssh integration suite
requirements.txt
run.sh          local foreground runner
pytest.ini
```

## Requirements

* Python 3.13 or newer with the `venv` module.
* Root on the machine that runs the bot, for the unit, the config and the state directory.
* SSH access to the target server, key or password. Root mode, passwordless sudo and sudo with password are detected automatically.
* Outbound network from the bot host to Telegram MTProto endpoints and to the target server.

## Install

```
sudo bash Storage/obhod-install.sh install
```

The installer asks for the bot token, `api_id`, `api_hash` and the admin id, copies the payload to `/opt/obhod`, builds the virtual environment, writes `/etc/obhod/obhod.env` with mode 600 and starts `obhod.service`.

Started as a normal user it stops immediately and prints the command to run with `sudo`. Nothing is written in that case.

```
bash Storage/obhod-install.sh install
bash Storage/obhod-install.sh update
bash Storage/obhod-install.sh status
bash Storage/obhod-install.sh restart
bash Storage/obhod-install.sh logs
bash Storage/obhod-install.sh uninstall
```

Options: `--yes` accepts values already present in the env file, `--prefix=PATH`, `--env-file=PATH`, `--python=PATH`, `--skip-deps` copies the payload without building a virtual environment, and `--dev` installs under `$HOME/.obhod` without root for local testing only.

## Configuration

`/etc/obhod/obhod.env`:

```
BOT_TOKEN=123456:ABCDEF
API_ID=12345678
API_HASH=0123456789abcdef0123456789abcdef
ADMIN_ID=123456789
OBHOD_STATE_DIR=/var/lib/obhod
OBHOD_INSTALL_SCRIPT=/opt/obhod/Storage/install.sh
OBHOD_LOG_LEVEL=INFO
```

Optional keys: `OBHOD_SESSION`, `OBHOD_CONNECT_TIMEOUT`, `OBHOD_COMMAND_TIMEOUT`, `OBHOD_APPLY_TIMEOUT`, `OBHOD_DC_HOST`, `OBHOD_DC_PORT`. The same keys are read from the environment, and `OBHOD_ENV` points the bot at a different env file.

`ADMIN_ID` may be left empty. In that case the first account that writes to the bot becomes the admin and the id is stored in `state.json`; every later account is refused. When `ADMIN_ID` is set it always wins.

Only the admin is served. Messages and callbacks from anyone else get a short refusal, no state is read and no remote command runs.

## Screens

* Home: connection state, server address, admin state, entry points to every section.
* Server: full probe result, apply, stop, restart, links to logs, SSH settings, install parameters, maintenance.
* SSH: host, port, user, auth mode, password, private key, key passphrase, sudo password, host key pinning reset.
* Install parameters: backend `new` or `external`, method `docker` or `systemd`, listen port, wireguard port and subnet, external vpn address, mode `udp` or `tcp`, obfuscation profile, obfuscation key, core version, public host for the link.
* Obfuscation: `rtpopus3`, `rtpopus2`, `rtpopus`, `none`, plus key generation.
* Clients: allowlist with peer addresses and handshake flags, per client screen with link building, WireGuard config, core config snapshot and two step removal.
* Connection parameters: threads, streams per credential, transport, tunnel mode, bond, timing, local listen address, DNS mode and servers, manual captcha, call link.
* Logs: tail selector 50, 200, 500.
* Maintenance: core update, restart, uninstall with a confirmation screen.
* Help and link import: offline `freeturn://` parsing with a field by field summary.

Long operations run inside a draft: the bot sends `messages.setTyping` with a rich draft action, keeps it updated while SSH work proceeds, then stops the draft and posts the final screen in place of the pressed message.

## Remote protocol

The bot never calls docker or systemd on the server directly. It pipes the vendored `install.sh` into `bash -s -- <command>` over SSH and reads the last JSON line of the output:

```
{"proto":3,"result":"ok","data":{...},"logs":[...]}
```

Commands used: `probe`, `apply`, `stop`, `restart`, `logs`, `client-list`, `client-add`, `client-conf`, `client-remove`, `uninstall`.

Root runs the command as is, passwordless sudo prefixes `sudo -n`, sudo with password prefixes `sudo -k -S -p ''` and sends the password as the first stdin line ahead of the script body. Any protocol version other than 3 is reported as `proto_mismatch` instead of being misinterpreted.

Defaults follow the upstream core: entry port 56000, wireguard subnet `10.13.13.0/24`, wireguard port 51820, mtu 1280, client side `127.0.0.1:9000`, kcp profile with nodelay 1, interval 20, resend 2, nc 1, windows 512, mtu 1200, acknodelay, obfuscation key of 64 hex characters.

## Links

`freeturn://` plus base64url of a compact JSON body:

```
{"v":1,"provider":"vk","peer":"host:56000","obf":"rtpopus3","key":"...","timing":0,
 "n":12,"spc":12,"cid":"client-id","name":"owner","listen":"127.0.0.1:9000",
 "dns":"plain","dnss":"1.1.1.1","mcap":false,"vk":"call link","wg":"[Interface]..."}
```

There is no platform field and no separate iOS variant. The same payload feeds the Android core configuration view on the client screen, which mirrors the shape the mobile client expects when it starts.

## Tests

```
python -m venv .venv
.venv/bin/pip install -r requirements.txt pytest pytest-asyncio pyflakes
.venv/bin/python -m pytest
```

404 tests covering validators, the link codec, kcp clamping, RPC parsing, argument quoting, store permissions, every screen, every callback route, the admin gate and admin claim, apply, stop, restart, logs, client add and remove flows, drafts, installer refusal and payload copy, plus a real SSH suite that starts a local asyncssh server, executes the vendored `install.sh` for real and checks the parsed result.

`tests/test_source.py` enforces the source rules: no comments, no docstrings, no emoji, no long dashes, no left over markers in the code written for this bot. `Storage/install.sh` is exempt because it is the vendored upstream installer and is kept byte identical on purpose.

## Security notes

* `state.json` lives in `OBHOD_STATE_DIR` with mode 600, the directory is 700, writes are atomic through a temporary file and `os.replace`.
* Passwords and keys only travel to the target server over SSH, they are never rendered in a message; the screens show a masked length instead.
* A password or key typed into the chat is confirmed by a notice that does not repeat the value; the bot deletes nothing on the Telegram side, so secrets typed into a chat stay in that chat history.
* Host keys are pinned on first successful connection, a change is refused with an explicit error and can be reset from the SSH screen.
* The unit runs with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome` and a single writable state directory.

## Removed in this rewrite

The old `BOT/Modules`, `BOT/protection.py`, `BOT/strings.py`, `Storage/VKTurn` and `Storage/Installation` trees are gone. Their behaviour is covered by the vendored upstream `install.sh`, which is the only supported way to prepare a server, and by `BOT/control.py`, which drives it over the RPC interface. The legacy bare map `clients.json` layout and the removed `-wrap` flags are not used anywhere.
