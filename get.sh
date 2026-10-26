#!/usr/bin/env bash
set -euo pipefail

REPO="${OBHOD_REPO:-i-execute/OBHOD}"
REF="${OBHOD_REF:-}"
DEST="${OBHOD_DIR:-/opt/obhod-src}"
SRC_DIR="${OBHOD_SRC_DIR:-}"
ENV_PATH="${OBHOD_ENV_FILE:-}"
DRY_RUN=0
NO_INSTALL=0
ARGS=()
WORK=""

say() { printf '%s\n' "$*" ; }
note() { printf '%s\n' "$*" >&2 ; }
die() { printf 'error: %s\n' "$*" >&2 ; exit 1 ; }

cleanup() {
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
  return 0
}
trap cleanup EXIT

for item in "$@"; do
  case "$item" in
    --ref=*) REF="${item#*=}" ;;
    --repo=*) REPO="${item#*=}" ;;
    --dir=*) DEST="${item#*=}" ;;
    --src=*) SRC_DIR="${item#*=}" ;;
    --env-file=*) ENV_PATH="${item#*=}" ;;
    --dry-run) DRY_RUN=1 ;;
    --no-install) NO_INSTALL=1 ;;
    *) ARGS+=("$item") ;;
  esac
done

if [ "${#ARGS[@]}" -eq 0 ]; then
  ARGS=("install")
fi

if [ "$(id -u)" != "0" ]; then
  die "установка возможна только от root, запустите curl ... | sudo bash"
fi

CREDS=0
if [ -n "${OBHOD_TOKEN:-}${BOT_TOKEN:-}" ] || [ -n "${OBHOD_API_ID:-}${API_ID:-}" ] || [ -n "${OBHOD_API_HASH:-}${API_HASH:-}" ] || [ -n "${OBHOD_ADMIN_ID:-}${ADMIN_ID:-}" ]; then
  CREDS=1
fi

TOKEN="${OBHOD_TOKEN:-${BOT_TOKEN:-}}"
API_ID="${OBHOD_API_ID:-${API_ID:-}}"
API_HASH="${OBHOD_API_HASH:-${API_HASH:-}}"
ADMIN_ID="${OBHOD_ADMIN_ID:-${ADMIN_ID:-}}"

tty_available() {
  if [ -t 0 ]; then
    return 0
  fi
  if [ -c /dev/tty ] && ( exec 3</dev/tty ) 2>/dev/null; then
    return 0
  fi
  return 1
}

need_tools() {
  if [ -n "$SRC_DIR" ]; then
    return 0
  fi
  if command -v git >/dev/null 2>&1; then
    return 0
  fi
  if command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
    return 0
  fi
  die "нужен git, либо curl и tar, поставьте их и повторите"
}

fetch_source() {
  if [ -n "$SRC_DIR" ]; then
    [ -f "$SRC_DIR/Storage/obhod-install.sh" ] || die "в $SRC_DIR нет Storage/obhod-install.sh"
    say "источник: $SRC_DIR"
    SRC="$SRC_DIR"
    return 0
  fi
  WORK="$(mktemp -d)"
  if command -v git >/dev/null 2>&1; then
    say "клонирование https://github.com/$REPO.git"
    if [ -n "$REF" ]; then
      git clone --depth 1 --branch "$REF" "https://github.com/$REPO.git" "$WORK/repo" >&2
    else
      git clone --depth 1 "https://github.com/$REPO.git" "$WORK/repo" >&2
    fi
    SRC="$WORK/repo"
    return 0
  fi
  say "git не найден, скачивание архива ветки ${REF:-по умолчанию}"
  mkdir -p "$WORK/repo"
  curl -fsSL "https://codeload.github.com/$REPO/tar.gz/${REF:-HEAD}" -o "$WORK/repo.tar.gz"
  tar -xzf "$WORK/repo.tar.gz" --strip-components=1 -C "$WORK/repo"
  SRC="$WORK/repo"
}

sync_source() {
  if [ -d "$DEST" ] && [ -e "$DEST/.obhod-src" ]; then
    rm -rf "$DEST"
  fi
  mkdir -p "$DEST"
  tar -cf - -C "$SRC" --exclude='.git*' --exclude='.venv' --exclude='__pycache__' --exclude='.pytest_cache' . | tar -xf - -C "$DEST"
  : > "$DEST/.obhod-src"
  chmod 600 "$DEST/.obhod-src"
}

write_env_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  umask 077
  {
    printf 'BOT_TOKEN=%s\n' "$TOKEN"
    printf 'API_ID=%s\n' "$API_ID"
    printf 'API_HASH=%s\n' "$API_HASH"
    printf 'ADMIN_ID=%s\n' "$ADMIN_ID"
  } > "$path"
  chmod 600 "$path"
}

need_tools
say "репозиторий: $REPO"
say "ветка: ${REF:-по умолчанию}"
say "каталог: $DEST"

if [ "$DRY_RUN" = "1" ]; then
  if [ -n "$SRC_DIR" ]; then
    say "источник: $SRC_DIR"
  elif command -v git >/dev/null 2>&1; then
    say "шаг: git clone --depth 1 https://github.com/$REPO.git"
  else
    say "шаг: curl https://codeload.github.com/$REPO/tar.gz/${REF:-HEAD} и tar -xzf"
  fi
  say "шаг: синхронизация файлов в $DEST"
  if [ "$CREDS" = "1" ]; then
    say "учетные данные: из переменных окружения"
  else
    say "учетные данные: спрашиваются в терминале"
  fi
  if [ -n "$ENV_PATH" ]; then
    if [ "$CREDS" = "1" ]; then
      write_env_file "$ENV_PATH"
      say "env-файл: $ENV_PATH"
    fi
  fi
  say "команда: bash $DEST/Storage/obhod-install.sh ${ARGS[*]}"
  exit 0
fi

if [ "$NO_INSTALL" = "0" ] && [ "$CREDS" = "0" ] && ! tty_available; then
  die "нет терминала для ввода, передайте BOT_TOKEN API_ID API_HASH ADMIN_ID переменными окружения"
fi

fetch_source
[ -f "$SRC/Storage/obhod-install.sh" ] || die "в источнике нет Storage/obhod-install.sh"
sync_source
say "файлы обновлены в $DEST"

if [ "$NO_INSTALL" = "1" ]; then
  say "установка пропущена, запуск вручную: bash $DEST/Storage/obhod-install.sh ${ARGS[*]}"
  exit 0
fi

INSTALL_ARGS=("${ARGS[@]}")
if [ "$CREDS" = "1" ]; then
  if [ -z "$ENV_PATH" ]; then
    WORK="${WORK:-$(mktemp -d)}"
    ENV_PATH="$WORK/obhod.env"
  fi
  write_env_file "$ENV_PATH"
  INSTALL_ARGS+=("--env-file=$ENV_PATH" "--yes")
  unset BOT_TOKEN API_ID API_HASH ADMIN_ID OBHOD_TOKEN OBHOD_API_ID OBHOD_API_HASH OBHOD_ADMIN_ID
  say "учетные данные: из переменных окружения"
else
  say "учетные данные: спрашиваются в терминале"
fi

say "запуск установщика"
if [ -t 0 ]; then
  bash "$DEST/Storage/obhod-install.sh" "${INSTALL_ARGS[@]}"
elif tty_available; then
  bash "$DEST/Storage/obhod-install.sh" "${INSTALL_ARGS[@]}" < /dev/tty
else
  bash "$DEST/Storage/obhod-install.sh" "${INSTALL_ARGS[@]}" < /dev/null
fi

say "готово, проверка службы: systemctl status obhod"
say "обновление потом: повторный запуск этого скрипта с теми же ключами"
say "исходники на сервере: $DEST"
