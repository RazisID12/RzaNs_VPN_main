#!/bin/bash
set -eEuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 027

# Всегда работаем из /opt/rzans_vpn_main
cd /opt/rzans_vpn_main 2>/dev/null || true

# единые опции curl (тайм-ауты, ретраи, IPv4)
# Формируем окончательный набор динамически:  QUIET=1 → -sS, иначе progress-bar
declare -a CURL_COMMON_OPTS=( --retry 3 --retry-all-errors \
                              --connect-timeout 10 --max-time 180 \
                              --speed-time 20 --speed-limit 1024 \
                              --happy-eyeballs-timeout-ms 200 \
                              -fL --compressed )
declare -a CURL_OPTS=()   # будет заполнен ниже

# если скрипт запущен внутри setup.sh → устанавливаем режим «install»
#   INSTALL_STAGE=1 update.sh                   # ← ничего «тяжёлого» не выполняем
INSTALL_STAGE="${INSTALL_STAGE:-0}"
# install-этап: ничего “тяжёлого” не делаем и не тянем списки
if [[ "$INSTALL_STAGE" == "1" ]]; then
  SKIP_AGH=1  SKIP_APT=1  SKIP_FAIL2BAN=1  SKIP_IPSET=1  SKIP_SETTINGS_HEAL=1
  SKIP_LISTS=1
  SKIP_SELF_UPD=1
  QUIET=1
# собираем итоговый массив curl-опций
else
  QUIET=0
fi

if [[ $QUIET -eq 1 ]]; then
  # тихий режим: без прогресс-бара, но ошибки печатаем
  CURL_OPTS=( "${CURL_COMMON_OPTS[@]}" -sS )
else
  # обычный режим: показываем прогресс-бар
  CURL_OPTS=( "${CURL_COMMON_OPTS[@]}" --progress-bar )
fi

# Обработка ошибок
handle_error() {
    os="$(lsb_release -ds 2>/dev/null \
         || grep -oP '(?<=^PRETTY_NAME=).*' /etc/os-release | tr -d '\"')"
    echo "$os $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

[[ $QUIET == 0 ]] && echo "Update RzaNs_VPN_main files:"

# ── YAML-helpers ────────────────────────────────────────────────────────────
. /opt/rzans_vpn_main/settings/settings.sh

# 1) гарантируем, что settings.yaml существует
_ensure_settings_yaml

# 2) «Лечение» settings.yaml (defaults * settings) —
#    пропускаем, если задан SKIP_SETTINGS_HEAL.
if [[ -z "${SKIP_SETTINGS_HEAL:-}" ]]; then
  [[ $QUIET == 0 ]] && echo "[SET] Healing settings.yaml…"
  tmp_heal="$(mktemp)"
  yq ea --prettyPrint \
        'select(fi==0) * select(fi==1)' \
        "$DEFAULTS_YAML" "$SETTINGS_YAML" >"$tmp_heal" \
    && mv -f "$tmp_heal" "$SETTINGS_YAML"
else
  [[ $QUIET == 0 ]] && echo "[SET] Healing skipped (install stage)"
fi

# 3) Дополняем авто-поля (dns.ip*, версии и т.п.)
autofill_settings

mkdir -p /opt/rzans_vpn_main/download

# ── anti-double-run lock (ОТДЕЛЬНЫЙ от settings-lock) ───────────────────
# используем другой файл и другой FD, чтобы не пересекаться с FD=9 из settings.sh
LOCK_FILE="/run/lock/rzans_update.lock"
mkdir -p "$(dirname "$LOCK_FILE")"
exec 8>"$LOCK_FILE" || { echo "Cannot open lock file $LOCK_FILE"; exit 1; }
flock -n 8 || { echo "Update already running (see $LOCK_FILE) — exit."; exit 0; }
# lock снимется автоматически при закрытии FD 8

# закроем FD 8 *перед* выходом, чтобы дочерний update.sh (если будет)
# не наследовал уже захваченный lock
trap 'exec 8>&-' EXIT

# ── AdGuard Home: ручное обновление с проверкой sha256 ───────────────
agh_upgrade() {
  # флаг нужен только, чтобы ПОСЛЕ апгрейда решать стартовать ли сервис
  local WANT; WANT="$(yaml_bool 'adguard_home.enable')"
  [[ $QUIET == 0 ]] && echo "[AGH] Checking for updates…"

  # текущий бинарник
  local AGH_BIN="/opt/AdGuardHome/AdGuardHome"
  [[ -x "$AGH_BIN" ]] || { [[ $QUIET == 0 ]] && echo "[AGH] Not installed — skip."; return 0; }

  # запомним текущую версию (если получится прочитать, с таймаутом и fallback)
  local OLDV NEWV out
  if out=$(timeout 3 "$AGH_BIN" -v 2>&1 | sed -n 's/.*version[[:space:]]\+//p'); then
    OLDV="$out"
  elif command -v strings >/dev/null 2>&1; then
    OLDV="$(strings -n3 "$AGH_BIN" | grep -Eom1 '^v?[0-9]+([.-][0-9A-Za-z]+)*' || true)"
  else
    OLDV=""
  fi

  # подберём архив под архитектуру
  local ARCH FILE BASE TAR SHA SHA_FILE
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64)  FILE="AdGuardHome_linux_amd64.tar.gz" ;;
    aarch64|arm64) FILE="AdGuardHome_linux_arm64.tar.gz" ;;
    armv7l)        FILE="AdGuardHome_linux_armv7.tar.gz" ;;
    armv6l)        FILE="AdGuardHome_linux_armv6.tar.gz" ;;
    i386|i686)     FILE="AdGuardHome_linux_386.tar.gz" ;;
    *)             FILE="AdGuardHome_linux_amd64.tar.gz" ;;
  esac

  BASE="https://static.adtidy.org/adguardhome/release"
  TAR="/opt/rzans_vpn_main/download/${FILE}"
  SHA_FILE="/opt/AdGuardHome/.last_sha256"

  # получим контрольную сумму нужного файла
  if ! curl "${CURL_OPTS[@]}" "${BASE}/checksums.txt" \
        | awk -v f="$FILE" '($NF==f || $NF=="./"f){print $1; exit}' > "${TAR}.sha"; then
    echo "[AGH] ✗ Cannot fetch checksum"; return 1
  fi
  read -r SHA < "${TAR}.sha" || { echo "[AGH] ✗ Cannot parse checksum"; return 1; }

  # ── бинарь уже свежий ────────────────────────────────────────────────
  if [[ -f "$SHA_FILE" ]] && grep -qx "$SHA" "$SHA_FILE"; then
    [[ $QUIET == 0 ]] && echo "[AGH] Already up to date."
    return 0
  fi

  [[ $QUIET == 0 ]] && echo "[AGH] Downloading…"
  if ! curl "${CURL_OPTS[@]}" -o "$TAR" "${BASE}/${FILE}"; then
    echo "[AGH] ✗ Download failed"; return 1
  fi
  if ! echo "${SHA}  ${TAR}" | sha256sum -c - --status; then
    echo "[AGH] ✗ Checksum mismatch"; return 1
  fi

  systemctl stop AdGuardHome 2>/dev/null || true
  rm -rf /opt/AdGuardHome/* 2>/dev/null || true
  tar -xzf "$TAR" --strip-components=1 -C /opt/AdGuardHome
  chown -R adguardhome:adguardhome /opt/AdGuardHome 2>/dev/null || true
  # привести чувствительные права на конфиг
  [[ -f /opt/AdGuardHome/AdGuardHome.yaml ]] && chmod 640 /opt/AdGuardHome/AdGuardHome.yaml || true
  # если доступны утилиты — вернуть cap_net_bind_service на бинарь
  if command -v setcap >/dev/null 2>&1; then
    if ! command -v getcap >/dev/null 2>&1 || \
       ! getcap /opt/AdGuardHome/AdGuardHome 2>/dev/null | grep -q cap_net_bind_service; then
      setcap 'cap_net_bind_service=+eip' /opt/AdGuardHome/AdGuardHome 2>/dev/null || true
    fi
  fi

  # подлечим конфиг
  agh_heal || true

  systemctl daemon-reload
  if [[ ${WANT,,} == y ]]; then
    systemctl enable --now AdGuardHome 2>/dev/null || true
  else
    # сервис выключен пользователем – оставляем остановленным и disabled
    systemctl disable --now AdGuardHome 2>/dev/null || true
  fi

  if out=$(timeout 3 /opt/AdGuardHome/AdGuardHome -v 2>&1 | sed -n 's/.*version[[:space:]]\+//p'); then
    NEWV="$out"
  elif command -v strings >/dev/null 2>&1; then
    NEWV="$(strings -n3 /opt/AdGuardHome/AdGuardHome | grep -Eom1 '^v?[0-9]+([.-][0-9A-Za-z]+)*' || true)"
  else
    NEWV=""
  fi

# ── фиксируем версию & дату ТОЛЬКО при замене бинаря ───────────────────
if [[ -n "$OLDV" && "$NEWV" != "$OLDV" ]]; then
  bump_service_ver adguard_home "$NEWV"
fi

  echo "$SHA" > "$SHA_FILE"
  [[ $QUIET == 0 ]] && echo "[AGH] Upgrade done: ${OLDV:-unknown} → ${NEWV:-unknown}"
}

# ── AGH‑upgrade: пропускаем, если INSTALL_STAGE=1 или вызван skip‑флаг ──
if [[ "${1:-}" == "agh" ]]; then     # однократный режим «только AGH»
  [[ -n "${SKIP_AGH:-}" ]] && exit 0
  agh_upgrade; exit 0
fi

# Чистим кеш только если действительно тянем списки
if [[ -z "${SKIP_LISTS:-}" ]]; then
  rm -f /opt/rzans_vpn_main/download/*
fi

UPDATE_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/update.sh"
UPDATE_PATH="update.sh"

PARSE_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/parse.sh"
PARSE_PATH="parse.sh"

DOALL_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/doall.sh"
DOALL_PATH="doall.sh"

HOSTS_LINK_1="https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv.gz"
HOSTS_PATH_1="download/dump.csv.gz"
#HOSTS_LINK_1="https://svn.code.sf.net/p/zapret-info/code/dump.csv"
#HOSTS_PATH_1="download/dump.csv"

HOSTS_LINK_2="https://antifilter.download/list/domains.lst"
HOSTS_PATH_2="download/domains.lst"

NXDOMAIN_LINK="https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt"
#NXDOMAIN_LINK="https://svn.code.sf.net/p/zapret-info/code/nxdomain.txt"
NXDOMAIN_PATH="download/nxdomain.txt"

INCLUDE_HOSTS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/include-hosts.txt"
INCLUDE_HOSTS_PATH="download/include-hosts.txt"

EXCLUDE_HOSTS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/exclude-hosts.txt"
EXCLUDE_HOSTS_PATH="download/exclude-hosts.txt"

DISCORD_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/discord-ips.txt"
DISCORD_IPS_PATH="download/discord-ips.txt"

CLOUDFLARE_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/cloudflare-ips.txt"
CLOUDFLARE_IPS_PATH="download/cloudflare-ips.txt"

AMAZON_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/amazon-ips.txt"
AMAZON_IPS_PATH="download/amazon-ips.txt"

HETZNER_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/hetzner-ips.txt"
HETZNER_IPS_PATH="download/hetzner-ips.txt"

DIGITALOCEAN_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/digitalocean-ips.txt"
DIGITALOCEAN_IPS_PATH="download/digitalocean-ips.txt"

OVH_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/ovh-ips.txt"
OVH_IPS_PATH="download/ovh-ips.txt"

TELEGRAM_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/telegram-ips.txt"
TELEGRAM_IPS_PATH="download/telegram-ips.txt"

GOOGLE_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/google-ips.txt"
GOOGLE_IPS_PATH="download/google-ips.txt"

AKAMAI_IPS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/akamai-ips.txt"
AKAMAI_IPS_PATH="download/akamai-ips.txt"

# ── smart_download: перезаписывает файл ТОЛЬКО если содержимое изменилось ──
smart_download() {
    local dst="$1" url="$2" tmp
    tmp="$(mktemp)"
    curl "${CURL_OPTS[@]}" -o "$tmp" "$url" || { rm -f "$tmp"; return 1; }
    if [[ ! -f "$dst" ]] || ! cmp -s "$tmp" "$dst"; then
        mv -f "$tmp" "$dst"
    else
        rm -f "$tmp"
    fi
}

# ── обычный download ‒ без сравнения (остаётся для списков) ────────────────
download() {
    local path tmp_path link
    # — сохраним прежний RETURN-trap, затем восстановим —
    local __old_trap; __old_trap="$(trap -p RETURN || true)"

    path="/opt/rzans_vpn_main/$1"
    tmp_path="${path}.tmp"
    link=$2

    [[ $QUIET == 0 ]] && echo "$path"
    # локальный trap: удалить tmp и вернуть старую ловушку
    trap 'rm -f "$tmp_path"; trap - RETURN; eval "${__old_trap}"' RETURN

    install -d "$(dirname "$path")"
    # скачиваем с тайм-аутами и ретраями; покажем одну строку статуса при QUIET=0
    [[ $QUIET == 0 ]] && echo "[DL] $link"
    curl "${CURL_OPTS[@]}" -o "$tmp_path" "$link"
    # если файл не скачался или пустой — считаем ошибкой
    if [[ ! -s "$tmp_path" ]]; then
        echo "Failed to download $path (empty file)"
        return 2
    fi

    mv -f "$tmp_path" "$path"

    case "$path" in
        *.sh) chmod +x "$path" ;;
        *.gz)
            # если распаковка не удалась — создаём пустой целевой файл
            if ! gunzip -f "$path"; then
                : > "${path%.gz}"
            fi
            ;;
    esac
}

# --- само-обновляющиеся скрипты ---
# при INSTALL_STAGE=1 (или если явно задан SKIP_SELF_UPD) — пропускаем
if [[ -z "${SKIP_SELF_UPD:-}" ]]; then
  smart_download "$UPDATE_PATH" "$UPDATE_LINK" && chmod +x "$UPDATE_PATH"
  smart_download "$PARSE_PATH"  "$PARSE_LINK"  && chmod +x "$PARSE_PATH"
  smart_download "$DOALL_PATH"  "$DOALL_LINK"  && chmod +x "$DOALL_PATH"
fi

# ── читаем флаги из settings.yaml ───────────────────────────────────────────
ROUTE_ALL="$(yaml_bool 'routing.route_all')"
DISCORD_INCLUDE="$(yaml_bool 'routing.flags.discord')"
CLOUDFLARE_INCLUDE="$(yaml_bool 'routing.flags.cloudflare')"
AMAZON_INCLUDE="$(yaml_bool 'routing.flags.amazon')"
HETZNER_INCLUDE="$(yaml_bool 'routing.flags.hetzner')"
DIGITALOCEAN_INCLUDE="$(yaml_bool 'routing.flags.digitalocean')"
OVH_INCLUDE="$(yaml_bool 'routing.flags.ovh')"
TELEGRAM_INCLUDE="$(yaml_bool 'routing.flags.telegram')"
GOOGLE_INCLUDE="$(yaml_bool 'routing.flags.google')"
AKAMAI_INCLUDE="$(yaml_bool 'routing.flags.akamai')"

if [[ -z "${1:-}" || "${1:-}" == "host" || "${1:-}" == "hosts" ]]; then
  if [[ -n "${SKIP_LISTS:-}" ]]; then
      [[ $QUIET == 0 ]] && echo "[DL] hosts lists skipped (SKIP_LISTS=1)"
  else
      download "$HOSTS_PATH_1" "$HOSTS_LINK_1"
    ( download "$HOSTS_PATH_2" "$HOSTS_LINK_2" ) || \
      > "/opt/rzans_vpn_main/$HOSTS_PATH_2"
    download "$NXDOMAIN_PATH" "$NXDOMAIN_LINK"
    download "$INCLUDE_HOSTS_PATH" "$INCLUDE_HOSTS_LINK"

	if [[ "$ROUTE_ALL" = "y" ]]; then
        download "$EXCLUDE_HOSTS_PATH" "$EXCLUDE_HOSTS_LINK"
	else
       printf '# НЕ РЕДАКТИРУЙТЕ ЭТОТ ФАЙЛ!' > "/opt/rzans_vpn_main/$EXCLUDE_HOSTS_PATH"
	fi
  fi
fi

if [[ -z "${1:-}" || "${1:-}" == "ip" || "${1:-}" == "ips" ]]; then
  if [[ -n "${SKIP_LISTS:-}" ]]; then
      [[ $QUIET == 0 ]] && echo "[DL] ip lists skipped (SKIP_LISTS=1)"
  else
	if [[ "$DISCORD_INCLUDE" = "y" ]]; then
        download "$DISCORD_IPS_PATH" "$DISCORD_IPS_LINK"
	fi

	if [[ "$CLOUDFLARE_INCLUDE" = "y" ]]; then
        download "$CLOUDFLARE_IPS_PATH" "$CLOUDFLARE_IPS_LINK"
	fi

	if [[ "$AMAZON_INCLUDE" = "y" ]]; then
        download "$AMAZON_IPS_PATH" "$AMAZON_IPS_LINK"
	fi

	if [[ "$HETZNER_INCLUDE" = "y" ]]; then
        download "$HETZNER_IPS_PATH" "$HETZNER_IPS_LINK"
	fi

	if [[ "$DIGITALOCEAN_INCLUDE" = "y" ]]; then
        download "$DIGITALOCEAN_IPS_PATH" "$DIGITALOCEAN_IPS_LINK"
	fi

	if [[ "$OVH_INCLUDE" = "y" ]]; then
        download "$OVH_IPS_PATH" "$OVH_IPS_LINK"
	fi

	if [[ "$TELEGRAM_INCLUDE" = "y" ]]; then
        download "$TELEGRAM_IPS_PATH" "$TELEGRAM_IPS_LINK"
	fi

	if [[ "$GOOGLE_INCLUDE" = "y" ]]; then
        download "$GOOGLE_IPS_PATH" "$GOOGLE_IPS_LINK"
	fi

	if [[ "$AKAMAI_INCLUDE" = "y" ]]; then
        download "$AKAMAI_IPS_PATH" "$AKAMAI_IPS_LINK"
	fi
  fi
fi

# ── Проверка/обновление AdGuard Home (если включён) ────────────────────
if [[ -n "${SKIP_AGH:-}" ]]; then
  [[ $QUIET == 0 ]] && echo "[AGH] skipped (install stage)"
else
  agh_upgrade
fi

# ── system packages upgrade (runs nightly via timer) ───────────────────
if [[ -n "${SKIP_APT:-}" ]]; then
  :
else
  [[ $QUIET == 0 ]] && echo "[SYS] Running apt update && dist-upgrade…"
  if apt-get update && \
     DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y --autoremove; then
      [[ $QUIET == 0 ]] && echo "[SYS] System packages are up to date."
  else
      [[ $QUIET == 0 ]] && echo "[SYS] apt dist-upgrade failed — continuing."
  fi                     # ← закрывает inner if apt‑get
fi

# ── Fail2Ban: фиксируем версию в YAML ───────────────────────────────────────
if [[ -z "${SKIP_FAIL2BAN:-}" && -x /usr/bin/fail2ban-server ]]; then
  NEW_F2B_VER=$(dpkg -s fail2ban 2>/dev/null | awk '/^Version:/{print $2}')
  bump_service_ver fail2ban "$NEW_F2B_VER"
fi

# ── persist ipset bans ──────────────────────────────────────────
if [[ -z "${SKIP_IPSET:-}" ]]; then
  if command -v ipset >/dev/null; then
    mkdir -p /var/lib/ipset
    { ipset save ipset-block   2>/dev/null || true; \
      ipset save ipset-block6  2>/dev/null || true; } \
      > /var/lib/ipset/ipset-bans.rules
    [[ $QUIET == 0 ]] && echo "[SYS] ipset bans saved."
  fi
fi

# ── автоматический reboot, если ядро/glibc потребуют перезагрузки ───────────
# ── автоматический reboot (отключаем, если NO_REBOOT=1) ─────────────────────
if [[ -f /var/run/reboot-required && "${NO_REBOOT:-0}" != "1" && $QUIET == 0 ]]; then
    # Разрешаем отмену ребута по Ctrl-C: снимаем таймер и выходим кодом 130
    trap 'echo "[SYS] Reboot cancelled."; shutdown -c; trap - INT; exit 130' INT
    echo "[SYS] Reboot required — system will reboot in 60 seconds. (Ctrl-C to cancel)"
    shutdown -r +1 'System reboot (updates applied)' || reboot --no-wall
    trap - INT
fi
