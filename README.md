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
| Installer | user mode with sudo juggling, user `OBHOD`, `/etc/sudoers.d/vkturn` | root only system service, no extra user, no sudoers entry |
| Reinstall | in place edits of an existing tree | destructive: everything is removed and installed again from scratch |
| Core version | whatever the update script downloaded last | pinned `v4.1.0` by default, `latest` only on request |

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
  xray.py       inbound model, config builder, share links, x25519 keys
  scan.py       reality scanner: tls 1.3, h2, x25519, certificate chain
  xrayrpc.py    proto 3 client plus the remote xray script it streams
  xscreens.py   rich screens for the xray section
  panel.py      xray operations behind the screens and callbacks
  inline.py     inline text input: fields, markers, inline results
  bootstrap.py  root only, ssh first installer for the bot itself
Storage/
  install.sh          vendored upstream installer, byte identical
  obhod-install.sh    installer for this bot, root only
  obhod.service       systemd unit template
get.sh          curl entry point: clone, sync, run the installer
tests/          838 tests, mock control, cross repo contract suite, real ssh suite
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

The shortest path is `get.sh`, which is fetched with `curl`, clones the repository and runs the installer:

```
curl -fsSL https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh | sudo bash
```

It refuses to run without root, needs `git` or `curl` plus `tar`, clones `i-execute/OBHOD` into a temporary directory, copies the tree into `/opt/obhod-src`, then runs `Storage/obhod-install.sh install` from there. Because the script itself arrives on stdin, the installer gets `/dev/tty` as its stdin, so the prompts still work.

Fully unattended, with the credentials in the environment:

```
curl -fsSL https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh | sudo BOT_TOKEN=123456:ABCDEF API_ID=12345678 API_HASH=<32 hex> ADMIN_ID=<telegram id> bash
```

That path writes a temporary env file with mode 600 and calls the installer with `--env-file` and `--yes`, so nothing is asked.

| Option | Meaning |
| --- | --- |
| `--ref=TAG` or `--ref=branch` | clone or download that revision instead of the default branch |
| `--repo=owner/name` | use another repository, also `OBHOD_REPO` |
| `--dir=PATH` | where the sources land, default `/opt/obhod-src`, also `OBHOD_DIR` |
| `--src=PATH` | skip the download and use a local tree, also `OBHOD_SRC_DIR` |
| `--env-file=PATH` | where the generated env file goes |
| `--no-install` | only refresh the sources, print the command to run afterwards |
| `--dry-run` | print what would happen, touch nothing, no network |
| `install`, `reinstall`, `update`, `--dev` and other installer flags | passed through to `Storage/obhod-install.sh` |

The repository is cloned into `/opt/obhod-src` and marked with `.obhod-src`, so a later run replaces exactly that directory and leaves anything else alone. Git files, `__pycache__` and virtual environments are never copied.

The manual path, without the helper script:

```
sudo bash Storage/obhod-install.sh install
```

The installer asks for the bot token, `api_id`, `api_hash` and the admin id, copies the payload to `/opt/obhod`, builds the virtual environment, writes `/etc/obhod/obhod.env` with mode 600 and starts `obhod.service`.

Started as a normal user it stops immediately and prints the command to run with `sudo`. Nothing is written in that case.

```
bash Storage/obhod-install.sh install
bash Storage/obhod-install.sh reinstall
bash Storage/obhod-install.sh update
bash Storage/obhod-install.sh status
bash Storage/obhod-install.sh restart
bash Storage/obhod-install.sh logs
bash Storage/obhod-install.sh uninstall
```

Options: `--yes` accepts values already present in the env file, `--prefix=PATH`, `--env-file=PATH`, `--python=PATH`, `--skip-deps` copies the payload without building a virtual environment, and `--dev` installs under `$HOME/.obhod` without root for local testing only.

`reinstall` is destructive by design: it stops and disables the unit, kills every process started from the install prefix, deletes `/opt/obhod` and then installs from zero. Credentials in the env file survive unless `--purge-all` is given, which also deletes `/etc/obhod/obhod.env` and the state directory and therefore requires the credentials to be entered again.

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

## Xray

The bot configures the Xray core on the same server it already reaches over SSH. There is no panel binary and no inbound database: the configuration is generated bot side from `BOT/xray.py` and streamed to the server, where the remote script validates it with `xray run -test` before it is written to `/usr/local/etc/xray/config.json`.

* Protocols: `vless`, `vmess`, `trojan`, `shadowsocks`. Networks: `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`. Security: `reality`, `tls`, `none`. Reality is offered only for `tcp`, `grpc` and `xhttp`, because the core rejects anything else.
* Inbound screen: summary table, reality keys with copy buttons, inline input buttons for `server name`, `dest`, `path`, `service name`, port and remark, client list, per client link, key regeneration through `xray x25519` on the server, enable toggle, two step removal.
* Share links follow the 3x-ui recipe exactly: `vless://uuid@host:port` with `flow` only for `tcp` and `reality` or `tls`, `trojan://password` with `flow` only for `tcp` plus `reality`, `ss://` base64url for classic methods and the SIP022 `method:inboundPassword:clientPassword` form for `2022-*`, query parameters `type`, `path`, `host`, `serviceName`, `security`, `sni`, `pbk`, `sid`, `fp`, `spx`, `flow`, `encryption`.
* Core screen: install or update, apply configuration, restart, stop, purge, log level, state table with version, service state, ports, listening ports and a config digest.

## Reality scanner

`BOT/scan.py` ports the 3x-ui scanner without the panel: ten second timeout, four second discovery timeout, concurrency 32, at most 256 addresses per subnet and 512 targets per run, private and loopback ranges blocked, results deduplicated by target preferring a feasible candidate and then lower latency.

A target is feasible when the handshake negotiates TLS 1.3, HTTP/2 through ALPN, the X25519 group and a certificate that verifies. The certificate is walked in DER without a third party library: subject, issuer, `notAfter` and subject alternative names. One command probes a target, scans a list, scans a subnet, and applies the best candidate to a reality inbound as `dest` plus `serverName`.

## Inline input

Text fields open an inline form instead of asking for the next chat message. The button is `switch_inline_query_current_chat` and carries a prefilled query such as `ob xr_sni 3 `. The bot answers the inline query with one article per action: save, clear, cancel, plus the field picker when the query is empty. Choosing a result posts a marker message `#ob <field> <context> <value>` that the bot consumes and deletes, then re-renders the screen it came from.

Fields with the same machinery: `ssh_host`, `ssh_port`, `ssh_user`, `ssh_password`, `ssh_key`, `ssh_sudo`, every xray field, the scan target list, the log level. Secrets are masked in the inline result description and the marker message is removed after it is read.

Inline mode has to be enabled for the bot by its owner with `@BotFather` and `/setinline`; the bot does not try to work around that, and the text input path from the previous round keeps working as a fallback. Inline answers are restricted to the configured admin id, so a stranger who finds the bot gets an empty result list instead of a list of this server's field names.

## Bootstrap

`python -m BOT bootstrap` mirrors the Feroku install shape and keeps it minimal:

1. Only check that the process runs as root, otherwise refuse with an instruction to run under `sudo`.
2. Copy the payload over SSH into `/opt/obhod` and build the virtual environment there.
3. Ask for the numeric Telegram id, compare it with the configured admin id, and only accept the same account.
4. Only after that identity check, write `/etc/obhod/obhod.env` with mode 600, install `obhod.service`, start it and hand the rest of the work to the bot in Telegram.

`python -m BOT bootstrap --check --ssh-host <host>` is the read only preflight: one ssh call, one line per condition (`root`, `python3`, `systemd`, `tar`, free space, `github.com` and `api.telegram.org` reachable from the server itself), exit code 0 only when every line is `ok`. It writes nothing, so it is safe to run before anything is installed.

`bootstrap.payload_archive` builds the tarball in memory, skipping caches and the test tree.

## Screens

* Home: connection state, server address, admin state, entry points to every section.
* Server: full probe result, apply, stop, restart, links to logs, SSH settings, install parameters, maintenance.
* SSH: host, port, user, auth mode, password, private key, key passphrase, sudo password, host key pinning reset.
* Install parameters: backend `new` or `external`, method `docker` or `systemd`, listen port, wireguard port and subnet, external vpn address, mode `udp` or `tcp`, obfuscation profile, obfuscation key, core version, public host for the link.
* Obfuscation: `rtpopus3`, `rtpopus2`, `rtpopus`, `none`, plus key generation.
* Clients: allowlist with peer addresses and handshake flags, per client screen with link building, WireGuard config, core config snapshot and two step removal.
* Connection parameters: threads, streams per credential, transport, tunnel mode, bond, timing, local listen address, DNS mode and servers, manual captcha, call link.
* Logs: tail selector 50, 200, 500.
* Maintenance: core update, destructive reinstall, restart, uninstall, each behind its own confirmation screen.
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

## Core version

The bot never installs an unpinned floating build. `BOT/models.py` carries `CORE_VERSION = "v4.1.0"` and that value is the default for `ServerOptions.version`, so every `apply` sends `--version=v4.1.0` and the server downloads

```
https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.0/server-linux-<arch>
```

The Xray core is pinned to `v26.10.21` in `BOT/xrayrpc.py` with its published digest `0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978` for `Xray-linux-64.zip`. The remote script reads the `.dgst` sidecar next to the release, falls back to that pinned digest when the sidecar cannot be fetched, and refuses the archive when neither matches. When GitHub is unreachable the pinned version and digest are still what the install command tries first, so a failed lookup never turns into an unpinned download.

`latest` is available from the install parameters screen as an explicit second button, and a `vX.Y.Z` value can be typed in by hand. `local`, which would need an uploaded binary, is refused. A version reported by `probe` is normalised to the `vX.Y.Z` form install.sh validates, a value that does not parse is dropped instead of being written back, so the pin cannot silently drift after a probe.

## Reinstall from scratch

`maint:reset2` and `srv:reset2` run `ControlClient.hard_reset` in five steps:

1. `install.sh uninstall --target=all --purge`, which stops the container or unit, closes the firewall port, removes the own wireguard interface and purges `/opt/free-turn-proxy`.
2. A cleanup script streamed over the same `bash -s` channel: `docker rm -f free-turn-proxy`, `systemctl disable --now free-turn-proxy.service`, removal of the unit file and daemon reload, `wg-quick down ft-wg0`, `ip link del ft-wg0`, `pkill -f /opt/free-turn-proxy`, removal of `/etc/wireguard/ft-wg0.conf`, `/etc/sysctl.d/99-free-turn-proxy.conf`, `/usr/local/bin/freeturn` and the prefix itself.
3. `probe` again. If the server still reports an installation, the operation is aborted with an explicit error and nothing is installed on top of leftovers.
4. `apply` with the full option set and `--update`, so the pinned release is downloaded again instead of reusing anything.
5. `probe` plus `client-list`, which must report a running core.

The cleanup script contains no comment lines, is validated with `bash -n` in the test suite, is executed for real against the ssh test server, and only ever touches the paths the upstream installer owns. The vendored `Storage/install.sh` is not modified by any of this: the same bytes the mobile client ships are streamed for every call.

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

803 tests covering validators, the link codec, kcp clamping, RPC parsing, argument quoting, store permissions, every screen, every callback route, the admin gate and admin claim, apply, stop, restart, logs, client add and remove flows, drafts, destructive reinstall, installer refusal, payload copy, reinstall and leftover process cleanup, plus a real SSH suite that starts a local asyncssh server, executes the vendored `install.sh` and the cleanup script for real and checks the parsed result.

`tests/test_contract.py` opens the Android client sources at `FREETURN_ANDROID_DIR` (default `/home/user/turn-proxy-android`) and compares this bot against them: the RPC command set, the `apply` flag set, the error code enum, the JSON field names of `probe`, `apply`, `client-list` and `logs`, the `freeturn://` key order, the kcp defaults, the `bash -s --` launch shape with `sudo -n` and `sudo -k -S -p ''`, the script asset name and the protocol version. The test skips with a clear reason when the Android tree is not present, and every expectation is also frozen in the test file so the suite still runs on its own.

New suites for this round: `tests/test_xray.py` for the inbound model, the config builder and every share link shape, `tests/test_scan.py` for the scanner including a real local TLS server and an openssl certificate walked by the DER reader, `tests/test_xrayrpc.py` for the remote script executed for real in a temporary root with a fake core plus an end to end run over an in process SSH server, `tests/test_panel.py` for every xray callback and every inline field, `tests/test_xscreens.py` for the new screens and their button budgets, `tests/test_inline.py` for markers and inline results, `tests/test_bootstrap.py` for the root check, the `--check` preflight, the identity gate and the payload.

`tests/test_source.py` enforces the source rules: no comments, no docstrings, no emoji, no long dashes, no left over markers in the code written for this bot. `Storage/install.sh` is exempt because it is the vendored upstream installer and is kept byte identical on purpose.

## Security notes

* `state.json` lives in `OBHOD_STATE_DIR` with mode 600, the directory is 700, writes are atomic through a temporary file and `os.replace`.
* Passwords and keys only travel to the target server over SSH, they are never rendered in a message; the screens show a masked length instead.
* A password or key typed into the chat is confirmed by a notice that does not repeat the value; the bot deletes nothing on the Telegram side, so secrets typed into a chat stay in that chat history.
* Host keys are pinned on first successful connection, a change is refused with an explicit error and can be reset from the SSH screen.
* The unit runs with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome` and a single writable state directory.

## Where the old scripts went

No script was silently dropped. The whole `/opt/vkturn` plus `sudoers` model is replaced by the upstream `install.sh` RPC, and `REPORT.md` carries the same table with a line per file.

| Old file | Was doing | Now |
| --- | --- | --- |
| `Storage/VKTurn/setup_root.sh` | created user `OBHOD`, `/opt/vkturn`, own `wg0` on `192.168.102.0/24`, nft/iptables rules | `install.sh apply`, own `ft-wg0` on `10.13.13.0/24`, no extra user |
| `Storage/VKTurn/add_client.sh` | inserted a client id into `/etc/wireguard/clients.json` | `install.sh client-add`, allowlist handled by the core |
| `Storage/VKTurn/add_peer_android.sh` | wireguard peer plus `freeturn://` link | `install.sh client-add` and `client-conf`, one link |
| `Storage/VKTurn/add_peer_ios.sh` | peer plus `vkturnproxy://import?data=` link with the wrap key | removed, iOS takes the same `freeturn://` link |
| `Storage/VKTurn/ensure_profile.sh` | `profiles.json` plus `/etc/wireguard/wrap.key` | `--obf-profile` and `--obf-key` of the core, no `-wrap` scheme |
| `Storage/VKTurn/revoke_peer.sh` | cut a peer, removed the client id, deleted the peer files | `install.sh client-remove` |
| `Storage/VKTurn/update_core.sh` | downloaded a binary and swapped it in place | `install.sh apply --update`, version pinned |
| `Storage/Installation/Setuper.sh` | cloned the repo into `/home/OBHOD`, `useradd -m`, `loginctl enable-linger`, systemd user unit, `/etc/sudoers.d/vkturn` | `Storage/obhod-install.sh`, root only, `/opt/obhod`, `obhod.service`, no user, no sudoers |
| `Storage/Installation/QuickStart.sh` | `curl` of `Setuper.sh` from `raw.githubusercontent.com` | not needed, the payload is local and offline |
| `Storage/Installation/APICerds.py` | printed a hardcoded list of third party `api_id` and `api_hash` pairs | removed, the operator supplies their own credentials |
| `BOT/Modules/VKTurn.py` | menu, VK call sourcing, peer and profile management, per platform links | `BOT/app.py`, `BOT/screens.py`, `BOT/flows.py`, `BOT/links.py` |
| `BOT/Modules/Updater.py` | GitHub release download with a stored token and a marker file | `install.sh apply --update`, `probe` reports the version |
| `BOT/protection.py` | flood counter for a multi user bot | single admin gate in `BOT/app.py` |
| `BOT/strings.py` and `BOT/Strings/*.yml` | three languages in yml | one language in code, screens are functions |
| `BOT/core.py`, `BOT/installer.py` | telethon bot loop and the in chat installer | `BOT/main.py`, `BOT/app.py`, `GoyGram` over MTProto |

The user `OBHOD` is not created any more. The old `Setuper.sh` did `useradd -m -s /bin/bash OBHOD`, installed to `/home/OBHOD/OBHOD`, enabled linger and granted `NOPASSWD` on seven `/opt/vkturn` scripts. The new installer creates no account at all: it installs system wide into `/opt/obhod`, writes `/etc/obhod/obhod.env` with mode 600, keeps state in `/var/lib/obhod` with mode 700 and runs `obhod.service` as a system unit.
