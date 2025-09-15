#!/usr/bin/env bash
set -eEuo pipefail
export LC_ALL=C
umask 027

# ── базовые пути (синхронно с settings.sh) ──────────────────────────────────
: "${BASE_DIR:=/opt/rzans_vpn_main}"
: "${AGH_DIR:=/opt/AdGuardHome}"
DOWNLOAD_DIR="${BASE_DIR}/download"

# Всегда работаем из BASE_DIR
cd "$BASE_DIR" 2>/dev/null || true

# ── curl опции (без "режимов") ──────────────────────────────────────────────
declare -a CURL_OPTS=( --retry 3 --retry-all-errors \
                       --connect-timeout 10 --max-time 180 \
                       --speed-time 20 --speed-limit 1024 \
                       --happy-eyeballs-timeout-ms 200 \
                       -fL --compressed --progress-bar )

# ── обработчик ошибок ───────────────────────────────────────────────────────
handle_error() {
  local os
  os="$(lsb_release -ds 2>/dev/null || sed -n 's/^PRETTY_NAME="\{0,1\}\(.*\)"\{0,1\}$/\1/p' /etc/os-release)"
  local now
  now="$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z)"
  echo "$os $(uname -r) $now"
  echo -e "\e[1;31mError at line $1: $2\e[0m"
  exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

echo "RzaNs update: start"

# ── подхватываем helpers из settings.sh ─────────────────────────────────────
. "${BASE_DIR}/settings/settings.sh"

# ── лёгкая страховка: вернуть маску на APT/unattended, если её сняли ────────
APT_UNITS=(apt-daily.service apt-daily-upgrade.service apt-news.service \
           apt-daily.timer apt-daily-upgrade.timer apt-news.timer \
           unattended-upgrades.service esm-cache.service)
for u in "${APT_UNITS[@]}"; do
  systemctl mask "$u" >/dev/null 2>&1 || true
done

# ── анти double-run lock для update (отдельно от settings-lock) ─────────────
UPDATE_LOCK="/run/lock/rzans_update.lock"
install -d "$(dirname "$UPDATE_LOCK")"
exec 8>"$UPDATE_LOCK" || { echo "Cannot open lock file $UPDATE_LOCK"; exit 1; }
flock -n 8 || { echo "Update already running (see $UPDATE_LOCK) — exit."; exit 0; }
trap 'exec 8>&-' EXIT

# ── ссылки/пути списков ─────────────────────────────────────────────────────
HOSTS_LINK_1="https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv.gz"
HOSTS_PATH_1="${DOWNLOAD_DIR}/dump.csv.gz"

HOSTS_LINK_2="https://antifilter.download/list/domains.lst"
HOSTS_PATH_2="${DOWNLOAD_DIR}/domains.lst"

NXDOMAIN_LINK="https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt"
NXDOMAIN_PATH="${DOWNLOAD_DIR}/nxdomain.txt"

INCLUDE_HOSTS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/include-hosts.txt"
INCLUDE_HOSTS_PATH="${DOWNLOAD_DIR}/include-hosts.txt"

EXCLUDE_HOSTS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/exclude-hosts.txt"
EXCLUDE_HOSTS_PATH="${DOWNLOAD_DIR}/exclude-hosts.txt"

DISCORD_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/discord-ips.txt"
DISCORD_IPS_PATH="${DOWNLOAD_DIR}/discord-ips.txt"

CLOUDFLARE_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/cloudflare-ips.txt"
CLOUDFLARE_IPS_PATH="${DOWNLOAD_DIR}/cloudflare-ips.txt"

AMAZON_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/amazon-ips.txt"
AMAZON_IPS_PATH="${DOWNLOAD_DIR}/amazon-ips.txt"

HETZNER_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/hetzner-ips.txt"
HETZNER_IPS_PATH="${DOWNLOAD_DIR}/hetzner-ips.txt"

DIGITALOCEAN_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/digitalocean-ips.txt"
DIGITALOCEAN_IPS_PATH="${DOWNLOAD_DIR}/digitalocean-ips.txt"

OVH_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/ovh-ips.txt"
OVH_IPS_PATH="${DOWNLOAD_DIR}/ovh-ips.txt"

TELEGRAM_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/telegram-ips.txt"
TELEGRAM_IPS_PATH="${DOWNLOAD_DIR}/telegram-ips.txt"

GOOGLE_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/google-ips.txt"
GOOGLE_IPS_PATH="${DOWNLOAD_DIR}/google-ips.txt"

AKAMAI_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/akamai-ips.txt"
AKAMAI_IPS_PATH="${DOWNLOAD_DIR}/akamai-ips.txt"

# ── скачивалка ──────────────────────────────────────────────────────────────
download() {
  # Раздельные присваивания, чтобы не словить set -u на ${path} до инициализации
  local path url tmp
  path="${1:?download(): missing <path>}"
  url="${2:-}"
  if [[ -z "$url" ]]; then
    echo "download(): missing <url> for path '$path'" >&2
    return 2
  fi
  tmp="${path}.tmp"
  install -d -m 755 "$(dirname "$path")"
  echo "[DL] $url"
  curl "${CURL_OPTS[@]}" -o "$tmp" "$url"
  [[ -s "$tmp" ]] || { echo "Failed to download $path (empty)"; rm -f "$tmp"; return 2; }
  mv -f "$tmp" "$path"
  case "$path" in
    *.sh) chmod +x "$path" ;;
    *.gz) gunzip -f "$path" || { : > "${path%.gz}"; rm -f -- "$path"; } ;;
  esac
}

# ── загрузка списков ────────────────────────────────────────────────────────
download_host_lists() {
  rm -f "${DOWNLOAD_DIR}/"* 2>/dev/null || true
  download "$HOSTS_PATH_1" "$HOSTS_LINK_1"
  ( download "$HOSTS_PATH_2" "$HOSTS_LINK_2" ) || : > "$HOSTS_PATH_2"
  download "$NXDOMAIN_PATH" "$NXDOMAIN_LINK"
  download "$INCLUDE_HOSTS_PATH" "$INCLUDE_HOSTS_LINK"

  if [[ "$(yaml_bool 'routing.route_all')" == y ]]; then
    download "$EXCLUDE_HOSTS_PATH" "$EXCLUDE_HOSTS_LINK"
  else
    printf '# НЕ РЕДАКТИРУЙТЕ ЭТОТ ФАЙЛ!\n' > "$EXCLUDE_HOSTS_PATH"
  fi
}

download_ip_lists() {
  [[ "$(yaml_bool 'routing.flags.discord')"      == y ]] && download "$DISCORD_IPS_PATH"      "$DISCORD_IPS_LINK"      || true
  [[ "$(yaml_bool 'routing.flags.cloudflare')"   == y ]] && download "$CLOUDFLARE_IPS_PATH"   "$CLOUDFLARE_IPS_LINK"   || true
  [[ "$(yaml_bool 'routing.flags.amazon')"       == y ]] && download "$AMAZON_IPS_PATH"       "$AMAZON_IPS_LINK"       || true
  [[ "$(yaml_bool 'routing.flags.hetzner')"      == y ]] && download "$HETZNER_IPS_PATH"      "$HETZNER_IPS_LINK"      || true
  [[ "$(yaml_bool 'routing.flags.digitalocean')" == y ]] && download "$DIGITALOCEAN_IPS_PATH" "$DIGITALOCEAN_IPS_LINK" || true
  [[ "$(yaml_bool 'routing.flags.ovh')"          == y ]] && download "$OVH_IPS_PATH"          "$OVH_IPS_LINK"          || true
  [[ "$(yaml_bool 'routing.flags.telegram')"     == y ]] && download "$TELEGRAM_IPS_PATH"     "$TELEGRAM_IPS_LINK"     || true
  [[ "$(yaml_bool 'routing.flags.google')"       == y ]] && download "$GOOGLE_IPS_PATH"       "$GOOGLE_IPS_LINK"       || true
  [[ "$(yaml_bool 'routing.flags.akamai')"       == y ]] && download "$AKAMAI_IPS_PATH"       "$AKAMAI_IPS_LINK"       || true
}

# ── AGH: обновление только бинарника (по мотивам setup.sh) ──────────────────
agh_update() {
  echo "[AGH] Checking…"
  local FILE BASE TAR SHA REF SHA_FILE BIN
  BIN="${AGH_DIR}/AdGuardHome"

  # если AGH не установлен — ничего не делаем (setup ставит его всегда)
  [[ -d "$AGH_DIR" ]] || { echo "[AGH] Not installed — skip."; return 0; }

  case "$(uname -m)" in
    x86_64|amd64)  FILE="AdGuardHome_linux_amd64.tar.gz" ;;
    aarch64|arm64) FILE="AdGuardHome_linux_arm64.tar.gz" ;;
    armv7l)        FILE="AdGuardHome_linux_armv7.tar.gz" ;;
    armv6l)        FILE="AdGuardHome_linux_armv6.tar.gz" ;;
    i386|i686)     FILE="AdGuardHome_linux_386.tar.gz" ;;
    *)             FILE="AdGuardHome_linux_amd64.tar.gz" ;;
  esac
  BASE="https://static.adtidy.org/adguardhome/release"
  TAR="${DOWNLOAD_DIR}/${FILE}"
  SHA_FILE="${AGH_DIR}/.tar.sha256"

  install -d -m 755 "$DOWNLOAD_DIR"
  REF="$(curl "${CURL_OPTS[@]}" "${BASE}/checksums.txt" \
          | awk -v f="$FILE" '($NF==f || $NF=="./"f){print $1; exit}')"
  if [[ -z "$REF" ]]; then
    echo "[AGH] Cannot get reference checksum — skip."
    return 0
  fi

  # уже актуально?
  if [[ -f "$SHA_FILE" ]] && grep -qx "$REF" "$SHA_FILE" && [[ -x "$BIN" ]]; then
    echo "[AGH] Up to date."
    return 0
  fi

  echo "[AGH] Downloading…"
  curl "${CURL_OPTS[@]}" -o "$TAR" "${BASE}/${FILE}"
  echo "${REF}  ${TAR}" | sha256sum -c - --status

  # распаковываем во временный каталог и копируем ТОЛЬКО бинарь
  local UNP; UNP="$(mktemp -d)"
  tar -xzf "$TAR" -C "$UNP"
  if [[ -x "$UNP/AdGuardHome/AdGuardHome" ]]; then
    install -m 0755 "$UNP/AdGuardHome/AdGuardHome" "$BIN"
  elif [[ -x "$UNP/AdGuardHome" ]]; then
    install -m 0755 "$UNP/AdGuardHome" "$BIN"
  else
    echo "[AGH] Binary not found after extract — skip."
    rm -rf "$UNP"
    return 0
  fi
  rm -rf "$UNP"
  echo "$REF" > "$SHA_FILE"
  chown adguardhome:adguardhome "$BIN" 2>/dev/null || true

  # НИКАКИХ setcap — юнит даёт CAP_NET_BIND_SERVICE через AmbientCapabilities
  # Сервис не включаем/не выключаем; если активен — мягко перезапустим
  if systemctl is-active --quiet AdGuardHome; then
    systemctl try-reload-or-restart AdGuardHome || true
  fi
  echo "[AGH] Binary updated."
}

# ── системное обслуживание ──────────────────────────────────────────────────
apt_upgrade() {
  echo "[SYS] apt update && dist-upgrade…"
  if apt-get update && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y --autoremove; then
    echo "[SYS] System packages are up to date."
  else
    echo "[SYS] apt dist-upgrade failed — continuing."
  fi
}

# ── ipset: сохранить состояние как в down.sh (но без удаления наборов) ──────
persist_ipset_state() {
  command -v ipset >/dev/null || return 0
  install -d -m 755 /var/lib/ipset
  local BAN_FILE=/var/lib/ipset/ipset-bans.rules
  local ALLOW_FILE=/var/lib/ipset/ipset-allow.rules

  # 1) Сохранить ТОЛЬКО динамические allow (без comment "src=settings")
  local _tmp_allow; _tmp_allow="$(mktemp)"
  ipset save 2>/dev/null \
    | awk '/^add (ipset-allow|ipset-allow6) / && $0 !~ /comment "src=settings"($| )/' \
    > "$_tmp_allow" || true
  mv -f "$_tmp_allow" "$ALLOW_FILE"

  # 2) Сохранить ТОЛЬКО баны (строки create/add для ipset-block{,6})
  local _tmp_ban; _tmp_ban="$(mktemp)"
  : > "$_tmp_ban"
  ipset save 2>/dev/null \
    | awk '/^(create|add) (ipset-block|ipset-block6) /' \
    >> "$_tmp_ban" || true
  mv -f "$_tmp_ban" "$BAN_FILE"

  # информативное сообщение (мягкое; не ломает выполнение)
  echo "[SYS] ipset saved: bans=$(wc -l < "$BAN_FILE" 2>/dev/null || echo 0), allow=$(wc -l < "$ALLOW_FILE" 2>/dev/null || echo 0)."
}

maybe_reboot() {
  if [[ -f /var/run/reboot-required ]]; then
    trap 'echo "[SYS] Reboot cancelled."; shutdown -c; trap - INT; exit 130' INT
    echo "[SYS] Reboot required — system will reboot in 60 seconds. (Ctrl-C to cancel)"
    shutdown -r +1 'System reboot (updates applied)' || reboot --no-wall
    trap - INT
  fi
}

# ── два режима ──────────────────────────────────────────────────────────────
run_lists_only() {
  _require_root
  echo "[MODE] lists"
  _with_lock settings_heal || true
  install -d -m 755 "$DOWNLOAD_DIR"
  download_host_lists
  download_ip_lists
  echo "[DONE] lists"
}

run_full() {
  _require_root
  echo "[MODE] full"

  # списки
  install -d -m 755 "$DOWNLOAD_DIR"
  download_host_lists
  download_ip_lists

  # обслуживание системы и сервисов
  agh_update
  apt_upgrade
  _with_lock prepare_main || true
  persist_ipset_state
  maybe_reboot
  echo "[DONE] full"
}

# ── CLI ─────────────────────────────────────────────────────────────────────
MODE="${1:-full}"
case "$MODE" in
  lists) run_lists_only ;;
  full)  run_full ;;
  *)     echo "Usage: $0 {lists|full}"; exit 2 ;;
esac