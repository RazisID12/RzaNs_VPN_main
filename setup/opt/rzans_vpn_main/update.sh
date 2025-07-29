#!/bin/bash
set -eEuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

# Обработка ошибок
handle_error() {
    os="$(lsb_release -ds 2>/dev/null \
         || grep -oP '(?<=^PRETTY_NAME=).*' /etc/os-release | tr -d '\"')"
    echo "$os $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

echo "Update RzaNs_VPN_main files:"

# ── подключаем общий модуль настроек и «лечим» settings.map ────────────────
. /opt/rzans_vpn_main/settings.sh
settings_heal

mkdir -p /opt/rzans_vpn_main/download

# ── anti‑double‑run lock ────────────────────────────────────────────────
#  • создаём /run/lock/rzans_update.lock (каталог /run/lock есть в systemd‑дистрибуциях);
#  • получаем эксклюзивный non‑blocking flock на дескриптор 9;
#  • если другой экземпляр уже держит lock → тихо выходим.
LOCK_FILE="/run/lock/rzans_update.lock"
mkdir -p "$(dirname "$LOCK_FILE")"
# открываем файл на запись в FD 9
exec 9>"$LOCK_FILE" || { echo "Cannot open lock file $LOCK_FILE"; exit 1; }
# пытаемся взять эксклюзивную, неблокирующую блокировку
flock -n 9 || { echo "Update already running (see $LOCK_FILE) — exit."; exit 0; }
# при штатном завершении lock снимется автоматически, когда shell закроет FD 9


# ── AdGuard Home: ручное обновление с проверкой sha256 ───────────────
agh_upgrade() {
  # флаг нужен только, чтобы ПОСЛЕ апгрейда решать стартовать ли сервис
  local WANT; WANT="$(settings_get_tag ADGUARD_HOME n)"

  echo -e '\e[1;36m[AGH] Checking for updates…\e[0m'

  # текущий бинарник
  local AGH_BIN="/opt/AdGuardHome/AdGuardHome"
  [[ -x "$AGH_BIN" ]] || { echo "[AGH] Not installed — skip."; return 0; }

  # запомним текущую версию (если получится прочитать)
  local OLDV NEWV
  OLDV="$("$AGH_BIN" -v 2>&1 | sed -n 's/.*version[[:space:]]\+//p' || true)"

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
  if ! curl --retry 3 -fsSL "${BASE}/checksums.txt" | grep "  ./${FILE}$" > "${TAR}.sha"; then
    echo "[AGH] ✗ Cannot fetch checksum"; return 1
  fi
  read -r SHA _ < "${TAR}.sha" || { echo "[AGH] ✗ Cannot parse checksum"; return 1; }

  # ── бинарь уже свежий ────────────────────────────────────────────────
  if [[ -f "$SHA_FILE" ]] && grep -qx "$SHA" "$SHA_FILE"; then
    echo -e '\e[1;36m[AGH] Already up to date.\e[0m'
    return 0        # комментарий НЕ трогаем
  fi

  echo -e '\e[1;36m[AGH] Downloading…\e[0m'
  if ! curl --retry 3 -fsSL "${BASE}/${FILE}" -o "$TAR"; then
    echo "[AGH] ✗ Download failed"; return 1
  fi
  if ! echo "${SHA}  $TAR" | sha256sum -c - --status; then
    echo "[AGH] ✗ Checksum mismatch"; return 1
  fi

  systemctl stop AdGuardHome 2>/dev/null || true
  rm -rf /opt/AdGuardHome/* 2>/dev/null || true
  tar -xzf "$TAR" --strip-components=1 -C /opt/AdGuardHome
  chown -R adguardhome:adguardhome /opt/AdGuardHome 2>/dev/null || true

  # подлечим конфиг
  agh_heal || true

  systemctl daemon-reload
  if [[ ${WANT,,} == y ]]; then
    systemctl enable --now AdGuardHome 2>/dev/null || true
  else
    # сервис выключен пользователем – оставляем остановленным и disabled
    systemctl disable --now AdGuardHome 2>/dev/null || true
  fi

  NEWV="$(/opt/AdGuardHome/AdGuardHome -v 2>&1 | sed -n 's/.*version[[:space:]]\+//p' || true)"

# ── фиксируем версию & дату ТОЛЬКО при замене бинаря ───────────────────
if [[ -n "$OLDV" && "$NEWV" != "$OLDV" ]]; then
  settings_set_agh_comment "$NEWV" "$(date +%d.%m.%Y)"
fi

  echo "$SHA" > "$SHA_FILE"
  echo -e "\e[1;36m[AGH] Upgrade done: ${OLDV:-unknown} → ${NEWV:-unknown}\e[0m"
}

# Режим «только обновить AGH»: ./update.sh agh
if [[ "${1:-}" == "agh" ]]; then
  agh_upgrade
  exit 0
fi

rm -f /opt/rzans_vpn_main/download/*

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

download() {
    local path tmp_path link
    local local_size remote_size

    path="/opt/rzans_vpn_main/$1"
    tmp_path="${path}.tmp"
    link=$2

    echo "$path"

    # удаляем tmp-файл при выходе из download()  (RETURN-trap не затрагивает EXIT-trap родительского скрипта)
    trap 'rm -f "$tmp_path"' RETURN

    curl -fL "$link" -o "$tmp_path"
    local_size=$(stat -c '%s' "$tmp_path")
    remote_size=$(curl -fsSLI "$link" \
                     | awk -F': *' 'tolower($1)=="content-length"{print $2;exit}' \
                     | tr -d '\r')

    if [[ -n "$remote_size" && $remote_size -gt 0 && "$local_size" != "$remote_size" ]]; then
        echo "Failed to download $path! Size mismatch ($local_size != $remote_size)"
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

download "$UPDATE_PATH" "$UPDATE_LINK"
download "$PARSE_PATH"  "$PARSE_LINK"
download "$DOALL_PATH"  "$DOALL_LINK"

# ── читаем флаги из settings.map через settings_get_tag ────────────
FLAGS=(ROUTE_ALL DISCORD_INCLUDE CLOUDFLARE_INCLUDE AMAZON_INCLUDE \
       HETZNER_INCLUDE DIGITALOCEAN_INCLUDE OVH_INCLUDE TELEGRAM_INCLUDE       \
       GOOGLE_INCLUDE AKAMAI_INCLUDE)

for f in "${FLAGS[@]}"; do
  val="$(settings_get_tag "$f" n)"
  if [[ ${val,,} == y ]]; then
    declare "$f=y"
  else
    declare "$f=n"
  fi
done

if [[ -z "${1:-}" || "${1:-}" == "host" || "${1:-}" == "hosts" ]]; then
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

if [[ -z "${1:-}" || "${1:-}" == "ip" || "${1:-}" == "ips" ]]; then
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

# ── Проверка/обновление AdGuard Home (если включён)
agh_upgrade

# ── system packages upgrade (runs nightly via timer) ──────────────────
echo -e '\e[1;36m[SYS] Running apt update && dist-upgrade…\e[0m'
if apt-get update && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y --autoremove; then
    echo -e '\e[1;36m[SYS] System packages are up to date.\e[0m'
else
    echo -e '\e[1;31m[SYS] apt dist-upgrade failed — continuing.\e[0m'
fi

# ── Fail2Ban: проверка версии и комментарий в settings.map ──────────────
if dpkg -s fail2ban &>/dev/null; then
  NEW_F2B_VER=$(dpkg -s fail2ban | awk '/^Version:/{print $2}')
  OLD_F2B_VER=$(grep -Po '(?<=^SSH_PROTECTION[^\n#]*# v)[^ ]+' "$SETTINGS" 2>/dev/null || true)
  # пишем только если найдено РАЗНОЕ значение
  if [[ -n "$OLD_F2B_VER" && "$NEW_F2B_VER" == "$OLD_F2B_VER" ]]; then
    :   # всё актуально
  else
    settings_set_ssh_comment "$NEW_F2B_VER" "$(date +%d.%m.%Y)"
  fi
fi

# ── persist ipset bans ──────────────────────────────────────────
if command -v ipset >/dev/null; then
    mkdir -p /var/lib/ipset
    { ipset save ipset-block   2>/dev/null || true; \
      ipset save ipset-block6  2>/dev/null || true; } \
      > /var/lib/ipset/ipset-bans.rules
    echo -e '\e[1;36m[SYS] ipset bans saved.\e[0m'
fi

# ── автоматический reboot, если ядро/glibc потребуют перезагрузки ───────────
if [[ -f /var/run/reboot-required ]]; then
    echo -e '\e[1;33m[SYS] Reboot required — system will reboot in 60 seconds.\e[0m'
    # даём минуту на graceful завершение активных подключений
    shutdown -r +1 'System reboot (updates applied)' || reboot --no-wall
fi
