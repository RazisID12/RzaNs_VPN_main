#!/bin/bash
# ==============================================================================
# Скрипт для установки на своём сервере RzaNs_VPN_main
# ==============================================================================
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027
export LC_ALL=C
set -euo pipefail
set -E -o errtrace
# разумный дефолт как раньше (~5 минут)
: "${APT_LOCK_TIMEOUT:=300}"

# ── runtime mode & TTY helpers ────────────────────────────────────────────────
# Non-interactive режим, если нет TTY (pipe/cron/systemd) или передан -y флаг
NONINTERACTIVE=0
# если нет ни stdin/stdout/stderr TTY, ни доступного /dev/tty — считаем неинтерактивным
if [[ ! -t 0 && ! -t 1 && ! -t 2 && ! -r /dev/tty ]]; then NONINTERACTIVE=1; fi
# интерактивен, если не форс-noninteractive и доступен хотя бы какой-то TTY или /dev/tty
is_interactive() { [[ $NONINTERACTIVE -eq 0 && ( -t 0 || -t 1 || -t 2 || -r /dev/tty ) ]]; }

normalize_yn() {
  # also accepts true/false/enabled/disabled for CLI overrides
  local v="${1,,}"
  case "$v" in
    y|yes|true|1|on|enable|enabled)     echo y ;;
    n|no|false|0|off|disable|disabled)  echo n ;;
    *) echo "" ;;
  esac
}

# prompt_line "Текст" "дефолт" → безопасно читает строку (или возвращает дефолт в non-interactive)
prompt_line() {
  local prompt="$1" def="$2" out=""
  if is_interactive; then
    # Всегда читаем из /dev/tty, если он есть
    if [[ -r /dev/tty ]]; then
      read -rp "${prompt} " -e -i "$def" out < /dev/tty 2>/dev/tty
    else
      read -rp "${prompt} " -e -i "$def" out 2>/dev/tty
    fi
  else
    out="$def"
  fi
  out="${out//$'\r'/}"
  out="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$out")"
  printf '%s' "$out"
}

# ask_yn "Вопрос" [y|n] → 'y'/'n' (TTY-safe, уважает non-interactive)
ask_yn() {
  local prompt="$1" def="${2:-y}" a
  [[ "$def" != "y" && "$def" != "n" ]] && def="y"
  if ! is_interactive; then printf '%s' "$def"; return 0; fi
  while true; do
    # Всегда читаем из /dev/tty, если он есть
    if [[ -r /dev/tty ]]; then
      read -rp "${prompt} [y/n] (default: $def): " a < /dev/tty 2>/dev/tty
    else
      read -rp "${prompt} [y/n] (default: $def): " a 2>/dev/tty
    fi
    a="${a,,}"; a="${a//$'\r'/}"
    a="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$a")"
    [[ -z "$a" ]] && a="$def"
    case "$a" in y|n) printf '%s' "$a"; return 0 ;; esac
  done
}

# pick_yn VAR "Вопрос" "дефолт(y|n)" "cli_override"
pick_yn() {
  local __var="$1" __prompt="$2" __def="$3" __cli="$4" __val
  if [[ -n "$__cli" ]]; then
    __val="$(normalize_yn "$__cli")"
    [[ -z "$__val" ]] && { echo "Bad value for flag ($__var): $__cli"; exit 2; }
    printf -v "$__var" '%s' "$__val"
  else
    printf -v "$__var" '%s' "$(ask_yn "$__prompt" "$__def")"
  fi
}

# ── локальный tmp и его авточистка ────────────────────────────────────────────
TMP_DIR="$(mktemp -d -t rzansvpn.XXXXXXXX)"
export TMP_DIR
cleanup_tmp() {
  local d="${TMP_DIR:-}"
  if [[ -n "$d" ]]; then
    rm -rf -- "$d" 2>/dev/null || true
  fi
}
trap cleanup_tmp EXIT

# ── локальный overlay для раннего бэкапа ─────────────────────────────────────
# В этот каталог будем складывать пользовательские артефакты как будто это «/»
STAGE="$TMP_DIR/overlay"
install -d "$STAGE"

# файл с ответами мастера создадим позже в $TMP_DIR (блок «РАННИЕ ВОПРОСЫ»)
# (чтобы ловить сбой даже на ранних шагах, до остановки таймеров)
handle_error() {
    source /etc/os-release
    echo "${PRETTY_NAME} $(uname -r) $(date --iso-8601=seconds)"
    echo -e "\e[1;31mError at line $1: $2\e[0m"
    exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

# Проверка прав root
if [[ "$EUID" -ne 0 ]]; then
	echo 'Error: You need to run this as root!'
	exit 2
fi

mkdir -p /opt && cd /opt

# ── запрет на контейнеры OpenVZ/LXC (если systemd-detect-virt есть)
# Проверка на OpenVZ и LXC (если утилита есть)
if command -v systemd-detect-virt &>/dev/null; then
  virt_type="$(systemd-detect-virt 2>/dev/null || true)"
  if [[ "$virt_type" == "openvz" || "$virt_type" == "lxc" ]]; then
    echo 'Error: OpenVZ and LXC are not supported!'
    exit 3
  fi
fi

# Проверка версии системы
if command -v lsb_release &>/dev/null; then
  OS="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
  VERSION="$(lsb_release -rs | cut -d '.' -f1)"
  CODENAME="$(lsb_release -cs)"
else
  source /etc/os-release
  OS="${ID}"
  VERSION="${VERSION_ID%%.*}"
  CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
fi

if [[ "$OS" == "debian" ]]; then
	if [[ $VERSION -lt 11 ]]; then
		echo 'Error: Your Debian version is not supported!'
		exit 4
	fi
elif [[ "$OS" == "ubuntu" ]]; then
	if [[ $VERSION -lt 22 ]]; then
		echo 'Error: Your Ubuntu version is not supported!'
		exit 5
	fi
elif [[ "$OS" != "debian" ]] && [[ "$OS" != "ubuntu" ]]; then
	echo 'Error: Your Linux version is not supported!'
	exit 6
fi

# Проверка свободного места (минимум 2 ГБ)
if [[ $(df --output=avail -B1 / | tail -n1) -lt $((2 * 1024 * 1024 * 1024)) ]]; then
	echo 'Error: Low disk space! You need 2GB of free space!'
	exit 7
fi

# ── CLI flags ---------------------------------------------------------------
CLI_DNS=""; CLI_DOMAIN=""
CLI_ADGUARD=""; CLI_FAIL2BAN=""
CLI_ROUTE_ALL=""
CLI_DISCORD=""; CLI_CLOUDFLARE=""; CLI_AMAZON=""
CLI_HETZNER=""; CLI_DIGITALOCEAN=""; CLI_OVH=""
CLI_TELEGRAM=""; CLI_GOOGLE=""; CLI_AKAMAI=""

print_usage() {
cat <<'USAGE'
Usage: setup.sh [options]

General:
  -i, --interactive            Force prompts even without a TTY
  -y, --non-interactive        Run without prompts (use YAML/flags/defaults)
  -h, --help                   Show this help

Config overrides:
  --dns=cloudflare|quad9|google|1|2|3
  --domain=example.com
  --agh=y|n
  --fail2ban=y|n
  --route-all=y|n

Split routing flags (include in Split VPN):
  --discord=y|n  --cloudflare=y|n  --amazon=y|n  --hetzner=y|n
  --digitalocean=y|n  --ovh=y|n  --telegram=y|n  --google=y|n  --akamai=y|n
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--interactive) NONINTERACTIVE=0; shift ;;
    -y|--non-interactive) NONINTERACTIVE=1; shift ;;
    -h|--help) print_usage; exit 0 ;;
    --dns=*)           CLI_DNS="${1#*=}"; shift ;;
    --domain=*)        CLI_DOMAIN="${1#*=}"; shift ;;
    --agh=*)           CLI_ADGUARD="${1#*=}"; shift ;;
    --fail2ban=*)      CLI_FAIL2BAN="${1#*=}"; shift ;;
    --route-all=*)     CLI_ROUTE_ALL="${1#*=}"; shift ;;
    --discord=*)       CLI_DISCORD="${1#*=}"; shift ;;
    --cloudflare=*)    CLI_CLOUDFLARE="${1#*=}"; shift ;;
    --amazon=*)        CLI_AMAZON="${1#*=}"; shift ;;
    --hetzner=*)       CLI_HETZNER="${1#*=}"; shift ;;
    --digitalocean=*)  CLI_DIGITALOCEAN="${1#*=}"; shift ;;
    --ovh=*)           CLI_OVH="${1#*=}"; shift ;;
    --telegram=*)      CLI_TELEGRAM="${1#*=}"; shift ;;
    --google=*)        CLI_GOOGLE="${1#*=}"; shift ;;
    --akamai=*)        CLI_AKAMAI="${1#*=}"; shift ;;
    --) shift; break ;;
    *) echo "Unknown option: $1"; echo "Use --help"; exit 2 ;;
  esac
done

echo
echo -e '\e[1;32mInstalling RzaNs_VPN_main (split + full VPN)...\e[0m'
echo 'AmneziaWG'
echo 'More details: https://github.com/RazisID12/RzaNs_VPN_main'

##############################################################################
# ── РАННИЕ ВОПРОСЫ (до тяжёлых шагов): пишем ответы во временный файл ───────
##############################################################################
# В этом блоке НЕ трогаем YAML и не требуем yq — только сбор ответов.
# Дефолты берём из settings_defaults.yaml (жёстко закодированы).
ANS_FILE="${TMP_DIR}/installer_answers.env"
: >"$ANS_FILE"

# ── DNS ─────────────────────────────────────────────────────────────────────
echo
echo -e 'Choose upstream \e[1;32mDNS\e[0m (applies to Split&Full):'
echo '    1) Cloudflare'
echo '    2) Quad9'
echo '    3) Google'
DNS_DEF_CH=1   # дефолт из settings_defaults.yaml: cloudflare
if [[ -n "${CLI_DNS:-}" ]]; then
  case "${CLI_DNS,,}" in
    1|cloudflare) UPSTREAM_DNS=1 ;;
    2|quad9)      UPSTREAM_DNS=2 ;;
    3|google)     UPSTREAM_DNS=3 ;;
    *) echo "Bad --dns=$CLI_DNS (use cloudflare|quad9|google|1|2|3)"; exit 2 ;;
  esac
else
  if is_interactive; then
    until [[ "${UPSTREAM_DNS:-}" =~ ^[1-3]$ ]]; do
      # Всегда читаем из /dev/tty, если он есть
      if [[ -r /dev/tty ]]; then
        read -rp "DNS choice [1-3] (default: $DNS_DEF_CH): " UPSTREAM_DNS < /dev/tty 2>/dev/tty
      else
        read -rp "DNS choice [1-3] (default: $DNS_DEF_CH): " UPSTREAM_DNS 2>/dev/tty
      fi
      UPSTREAM_DNS="${UPSTREAM_DNS//$'\r'/}"
      UPSTREAM_DNS="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$UPSTREAM_DNS")"
      [[ -z "$UPSTREAM_DNS" ]] && UPSTREAM_DNS="$DNS_DEF_CH"
    done
  else
    UPSTREAM_DNS="$DNS_DEF_CH"
  fi
fi
case "$UPSTREAM_DNS" in
  1) DNS_UPSTREAM=cloudflare ;;
  2) DNS_UPSTREAM=quad9      ;;
  3) DNS_UPSTREAM=google     ;;
esac
echo "DNS_UPSTREAM=$DNS_UPSTREAM" >>"$ANS_FILE"

# ── AdGuard Home / Fail2ban ─────────────────────────────────────────────────
echo
pick_yn ADGUARD_HOME $'Install and use \001\e[1;36m\002AdGuard Home\001\e[0m\002 for DNS filtering?' n "${CLI_ADGUARD:-}"
echo "ADGUARD_HOME=$ADGUARD_HOME" >>"$ANS_FILE"

echo
pick_yn SSH_PROTECTION $'Enable \001\e[1;36m\002SSH protection\001\e[0m\002?' n "${CLI_FAIL2BAN:-}"
echo "SSH_PROTECTION=$SSH_PROTECTION" >>"$ANS_FILE"

# ── Домен ───────────────────────────────────────────────────────────────────
echo
if [[ -n "${CLI_DOMAIN:-}" ]]; then
  SERVER_HOST="$CLI_DOMAIN"
  if [[ -n "$SERVER_HOST" ]]; then
    readarray -t _ip_test < <(getent ahostsv4 "$SERVER_HOST") || true
    [[ ${#_ip_test[@]} -gt 0 ]] || { echo "Error: Domain not resolvable: $SERVER_HOST"; exit 2; }
  fi
else
  SERVER_HOST="$(prompt_line $'Enter valid \001\e[1;36m\002domain name\001\e[0m\002 for this server (Enter to skip):' "")"
  if [[ -n "$SERVER_HOST" ]]; then
    readarray -t _ip_test < <(getent ahostsv4 "$SERVER_HOST") || true
    while [[ ${#_ip_test[@]} -eq 0 ]]; do
      SERVER_HOST="$(prompt_line $'Domain is not resolvable. Try again (Enter to skip):' "")"
      [[ -z "$SERVER_HOST" ]] && break
      readarray -t _ip_test < <(getent ahostsv4 "$SERVER_HOST") || true
    done
  fi
fi
unset _ip_test
echo "SERVER_HOST=$SERVER_HOST" >>"$ANS_FILE"

# ── Маршрутизация и флаги (дефолты из settings_defaults.yaml) ───────────────
echo
pick_yn ROUTE_ALL $'Enable \001\e[1;36m\002route all\001\e[0m\002 traffic via Split VPN, excluding Russian domains and domains from exclude-hosts.txt?' n "${CLI_ROUTE_ALL:-}"
echo "ROUTE_ALL=$ROUTE_ALL" >>"$ANS_FILE"

declare -A _DEF=( [discord]=y [cloudflare]=y [amazon]=n [hetzner]=n [digitalocean]=n [ovh]=n [telegram]=n [google]=n [akamai]=n )
for k in discord cloudflare amazon hetzner digitalocean ovh telegram google akamai; do
  vname="$(tr '[:lower:]' '[:upper:]' <<<"$k")_INCLUDE"
  cli="CLI_$(tr '[:lower:]' '[:upper:]' <<<"$k")"
  echo
  pick_yn "$vname" $'Include \001\e[1;36m\002'"${k^}"$'\001\e[0m\002 IPs in Split VPN?' "${_DEF[$k]}" "${!cli:-}"
  echo "${vname}=${!vname}" >>"$ANS_FILE"
done

# Синхронизируем состояние systemd заранее
SYSTEMD_LOG_LEVEL=err systemctl --no-pager daemon-reload >/dev/null 2>&1 || true

##############################################################################
# РАННИЙ БЭКАП пользовательских артефактов в $STAGE (как «/»)                #
##############################################################################
# Сохраняем только пользовательские артефакты (никаких служебных файлов из репо)

# 1) settings.yaml
if [[ -s /opt/rzans_vpn_main/settings.yaml ]]; then
  install -D -m 0600 /opt/rzans_vpn_main/settings.yaml \
    "$STAGE/opt/rzans_vpn_main/settings.yaml"
fi

# 2) /opt/rzans_vpn_main/config (без ./templates)
if [[ -d /opt/rzans_vpn_main/config ]]; then
  install -d "$STAGE/opt/rzans_vpn_main/config"
  tar -C /opt/rzans_vpn_main/config --exclude='./templates' -cf - . \
    | tar -C "$STAGE/opt/rzans_vpn_main/config" -xf - 2>/dev/null || true
fi

# 3) Amnezia templates
if [[ -d /etc/wireguard/templates ]]; then
  install -d -m 0700 "$STAGE/etc/wireguard"
  tar -C /etc/wireguard -cf - templates \
    | tar -C "$STAGE/etc/wireguard" -xf - 2>/dev/null || true
fi

# 4) WG-артефакты сервера: конфиги + key/ips
for f in /etc/wireguard/rzans_*vpn_main.conf /etc/wireguard/key /etc/wireguard/ips; do
  [[ -e "$f" ]] && install -D -m 0600 "$f" "$STAGE$f"
done
# а также внешние пути из PrivateKeyFile|PresharedKeyFile
mapfile -t _refs < <(
  grep -Eh '^(PrivateKeyFile|PresharedKeyFile)[[:space:]]*=' \
    /etc/wireguard/rzans_*vpn_main.conf 2>/dev/null \
  | awk -F= '{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' | awk 'NF'
)
for p in "${_refs[@]}"; do
  [[ -s "$p" ]] || continue
  install -D -m 0600 "$p" "$STAGE$p"
done
unset _refs

# 5) AdGuard Home YAML
if [[ -s /opt/AdGuardHome/AdGuardHome.yaml ]]; then
  install -D -m 0640 /opt/AdGuardHome/AdGuardHome.yaml \
    "$STAGE/opt/AdGuardHome/AdGuardHome.yaml"
fi

# 6) Fail2ban jail.local
if [[ -s /etc/fail2ban/jail.local ]]; then
  install -D -m 0644 /etc/fail2ban/jail.local \
    "$STAGE/etc/fail2ban/jail.local"
fi

# ожидание apt перенесено ниже в универсальную функцию wait_for_apt

# Отключим фоновые обновления системы
stop_units() {
  # usage: stop_units unit1 unit2 ...
  ((${#@}>0)) && SYSTEMD_LOG_LEVEL=err systemctl --no-pager stop "$@" &>/dev/null || true
}
disable_units() {
  ((${#@}>0)) && SYSTEMD_LOG_LEVEL=err systemctl --no-pager disable "$@" &>/dev/null || true
}
mask_units() {
  # usage: mask_units unit1 unit2 ...
  ((${#@}>0)) && SYSTEMD_LOG_LEVEL=err systemctl --no-pager mask "$@" >/dev/null 2>&1 || true
}
stop_disable() { stop_units "$@"; disable_units "$@"; }
stop_disable_pattern() {
  # usage: stop_disable_pattern 'regex-for-unitname'
  local rx="$1"
  # Собираем реальные инстансы unit'ов и фильтруем по ERE через grep -E.
  # Приглушаем предупреждения systemd и глушим STDERR, чтобы не было "Run 'systemctl daemon-reload'".
  local -a _u=()
  mapfile -t _u < <(
    SYSTEMD_LOG_LEVEL=err \
    systemctl --no-pager list-units --type=service --all --no-legend 2>/dev/null \
      | awk '{print $1}' \
      | grep -E -- "$rx" || true
  )
  # Под set -e голый (( ... )) с нулём вызовет ERR, поэтому используем if.
  if (( ${#_u[@]} > 0 )); then
    stop_disable "${_u[@]}"
  fi
}

# ── 4. Отключение мешающих сервисов (без resolved/kresd) ─────────────────────
disable_conflicts() {
  # 1) Системные авто-обновления APT, чтобы не висеть на замках
  stop_disable unattended-upgrades.service esm-cache.service \
               apt-daily.service apt-daily-upgrade.service apt-news.service
  stop_disable apt-daily.timer apt-daily-upgrade.timer apt-news.timer
  mask_units   unattended-upgrades.service esm-cache.service \
               apt-daily.service apt-daily-upgrade.service apt-news.service \
               apt-daily.timer apt-daily-upgrade.timer apt-news.timer

  # 2) Резольверы/прокси, кто может занять :53 (чужие, если вдруг стоят)
  stop_disable \
    dnsmasq.service bind9.service named.service named-chroot.service \
    unbound.service dnscrypt-proxy.service \
    adguardhome.service AdGuardHome.service \
    pdns-recursor.service pdns.service \
    knot.service \
    coredns.service pihole-FTL.service \
    stubby.service smartdns.service mosdns.service \
    pdnsd.service maradns.service tinydns.service dnscache.service \
    dnsproxy.service cloudflared.service

  # 3) Менеджеры фаервола / персистентные загрузчики правил
  stop_disable \
    ufw.service firewalld.service ferm.service \
    netfilter-persistent.service iptables-persistent.service \
    shorewall.service shorewall6.service firehol.service \
    nftables.service \
    csf.service lfd.service
  command -v ufw &>/dev/null && ufw disable &>/dev/null || true

  # 4) Баны/IDS, способные конфликтовать с fail2ban
  stop_disable sshguard.service denyhosts.service \
               crowdsec.service crowdsec-firewall-bouncer.service

  # 5) Любые WireGuard-интерфейсы могут мешать нашим правилам — гасим всё
  stop_disable_pattern '^wg-quick@.*\.service$'

  # 6) Наши кастомные юниты
  # oneshot-юниты: останавливать бессмысленно — только отключаем
  disable_units apply.service first_init.service dwnld_update.service
  # path/timer/обычные — гасим и отключаем
  stop_disable apply.path dwnld_update.timer lo_ipv6@::2.service firewall.service proxy.service \
               firewall_fallback.service

  # ВАЖНО: здесь НЕ трогаем systemd-resolved и НЕ трогаем kresd@*
}

# вернуть true если unit реально в состоянии выполнения
_unit_busy() {
  local u="$1"
  local sub
  sub="$(SYSTEMD_LOG_LEVEL=err systemctl show -p SubState --value "$u" 2>/dev/null || true)"
  [[ "$sub" == "running" || "$sub" == "activating" ]]
}

# ── 5. Надёжное ожидание APT/Dpkg и обёртка для запусков apt-get ────────────
wait_for_apt() {
  # usage: wait_for_apt [timeout_sec]
  local t_max="${1:-${APT_LOCK_TIMEOUT:-300}}" t0=$(date +%s) i=0
  local err="/dev/stderr"
  [[ -w /dev/tty ]] && err="/dev/tty"
  local frames=('|' '/' '-' '\')
  local locks=(
    /var/lib/dpkg/lock-frontend
    /var/lib/dpkg/lock
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )
  local units=(apt-daily.service apt-daily-upgrade.service apt-news.service esm-cache.service unattended-upgrades.service)
  while :; do
    local busy=0
    # проверяем держателей файлов-замков
    for l in "${locks[@]}"; do
      if command -v fuser >/dev/null 2>&1 && fuser -s "$l" &>/dev/null; then busy=1; break; fi
    done
    # подстрахуемся: реально выполняющиеся systemd-юниты
    if (( !busy )); then
      for u in "${units[@]}"; do
        _unit_busy "$u" && { busy=1; break; }
      done
    fi
    # и процессы (если вдруг без systemd)
    if (( !busy )) && pgrep -fa 'apt\.systemd\.daily' >/dev/null; then busy=1; fi
    if (( !busy )) && pgrep -fa 'unattended-?upgrad(e|es)' >/dev/null; then busy=1; fi

    if (( !busy )); then
      printf '\r' >"$err"; return 0
    fi
    (( $(date +%s) - t0 > t_max )) && {
      echo -e "\n✗ APT still busy after ${t_max}s" >&2; return 1; }
    printf '\r⏳ Waiting for apt/dpkg locks %s' "${frames[i]}" >"$err"
    # не давать set -e «ронять» скрипт, когда выражение == 0
    i=$(( (i + 1) % ${#frames[@]} ))
    sleep 2
  done
}

apt_safe() {
  # перед любым apt-get ждём замки и даём самому APT таймаут на lock
  local t="${APT_LOCK_TIMEOUT:-300}"
  wait_for_apt "$t" || return 1
  apt-get -o Dpkg::Options::=--force-confdef \
          -o Dpkg::Options::=--force-confold \
          -o Acquire::Retries=3 \
          -o DPkg::Lock::Timeout="$t" \
          "$@"
}

# ── 6. Чистка наших старых хвостов + устранение yq<4 ────────────────────────
cleanup_legacy() {
  systemctl --no-pager daemon-reload >/dev/null 2>&1 || true

  # Наш исторический sysctl-конфиг, если оставался
  rm -f /etc/sysctl.d/99-rzans_vpn_main.conf

  # Knot Resolver: чистим только кеш/состояние, конфиги не трогаем
  rm -rf /var/cache/knot-resolver/* /var/lib/knot-resolver/* 2>/dev/null || true

  # Убираем конфликтные реализации yq из реп (python3-yq/yq<4)
  apt_safe -y remove --purge yq python3-yq >/dev/null 2>&1 || true
}

# --- 🔧 РАНО гасим авто-джобы APT, чтобы не ждать замков на чистой системе ---
SYSTEMD_LOG_LEVEL=err systemctl --no-pager daemon-reload >/dev/null 2>&1 || true
disable_conflicts
cleanup_legacy

# Обновляем систему
# перед первой apt-операцией еще раз перечитаем юниты, чтобы убрать возможные ворнинги
SYSTEMD_LOG_LEVEL=err systemctl --no-pager daemon-reload >/dev/null 2>&1 || true
apt_safe clean
apt_safe update
export DEBIAN_FRONTEND=noninteractive
apt_safe dist-upgrade -y
apt_safe install --reinstall -y curl gpg

# После dist-upgrade/unit-скриптов — ещё раз синхронизируем systemd
SYSTEMD_LOG_LEVEL=err systemctl --no-pager daemon-reload >/dev/null 2>&1 || true

# Папка для ключей
install -d /etc/apt/keyrings

# --- репозиторий Knot Resolver ---------------------------------------------
# 1. базовый ключ CZ.NIC (включает pub-/sub-ключ 0xAB6A303124019B64)
rm -f /etc/apt/keyrings/cznic-labs-pkg.gpg 2>/dev/null || true
curl --proto '=https' --tlsv1.2 --retry 3 -fsSL https://pkg.labs.nic.cz/gpg \
     | gpg --dearmor > /etc/apt/keyrings/cznic-labs-pkg.gpg

# 2. дополнительный signing-key 0xD959241751179EC7 из публичного keyserver’а
GPG_TMP_DIR="$(mktemp -d)"
if curl --retry 3 -fsSL \
     "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xD959241751179EC7" \
     | gpg --dearmor >"$GPG_TMP_DIR/D959241751179EC7.gpg"; then
  cat "$GPG_TMP_DIR/D959241751179EC7.gpg" >> /etc/apt/keyrings/cznic-labs-pkg.gpg
fi
rm -rf "$GPG_TMP_DIR"
chmod 644 /etc/apt/keyrings/cznic-labs-pkg.gpg

echo "deb [signed-by=/etc/apt/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-resolver ${CODENAME} main" \
  > /etc/apt/sources.list.d/cznic-labs-knot-resolver.list

# Добавим репозиторий Debian Backports
if [[ "$OS" == "debian" ]]; then
	echo "deb https://deb.debian.org/debian ${CODENAME}-backports main" > /etc/apt/sources.list.d/backports.list
fi

apt_safe update
# после обновления индексов юниты могли обновиться зависимостями предыдущих шагов
SYSTEMD_LOG_LEVEL=err systemctl --no-pager daemon-reload >/dev/null 2>&1 || true

# Ставим необходимые пакеты
apt_safe install --reinstall -y --no-install-recommends \
                              git iptables gawk jq knot-resolver sipcalc python3 python3-pip \
                              wireguard-tools diffutils socat lua-cqueues ipset file \
                              libcap2-bin logrotate gettext-base ca-certificates \
                              acl attr uuid-runtime binutils
#
# libidn (idn) vs libidn2 (idn2) отличаются по дистрибутивам — пробуем по очереди, не валим установку
apt_safe install -y idn || apt_safe install -y idn2 || true
modprobe -q xt_owner 2>/dev/null || true

##############################################################################
# yq v4: пакетного нет (в репо v3), поэтому скачиваем релиз и кладём в /usr/bin
##############################################################################
if ! command -v yq >/dev/null 2>&1 \
   || ! yq --version 2>/dev/null | grep -Eqi '(^|[[:space:]])v?4(\.|$)'; then
  echo 'Installing yq v4 …'
  case "$(uname -m)" in
    x86_64|amd64)   yq_arch=amd64 ;;
    aarch64|arm64)  yq_arch=arm64 ;;
    riscv64)        yq_arch=riscv64 ;;
    ppc64le)        yq_arch=ppc64le ;;
    s390x)          yq_arch=s390x ;;
    armv7l)         yq_arch=arm   ;;
    armv6l)         yq_arch=arm   ;;
    i386|i686)      yq_arch=386   ;;
    *)              yq_arch=amd64 ;;
  esac
  # допускаем пин версий: YQ_VERSION=v4.44.1; по умолчанию — latest
  YQ_VERSION="${YQ_VERSION:-latest}"
  if [[ "$YQ_VERSION" == "latest" ]]; then
    yq_url="https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${yq_arch}"
  else
    yq_url="https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${yq_arch}"
  fi
  if curl --retry 3 -fsSL -L "$yq_url" \
       -o /usr/bin/yq; then
    chmod 0755 /usr/bin/yq
    # гарантируем, что в PATH будет только новый v4
    install -d /usr/local/bin
    rm -f /usr/local/bin/yq
    ln -s /usr/bin/yq /usr/local/bin/yq

    # ── валидация загрузки ───────────────────────────────────────────
    if ! file -b /usr/bin/yq | grep -q 'ELF'; then
      echo '✗ yq download looks broken (not an ELF binary). See first lines below:' >&2
      head -n 10 /usr/bin/yq >&2
      rm -f /usr/bin/yq
      exit 13                         # ловушка ERR выведет контекст
    fi

  else
    echo '✗ GitHub download failed — yq v4 is mandatory. Aborting.' >&2
    exit 13
  fi
  # sanity-check: убеждаемся, что действительно стоит Go-yq v4 (покажем, что он отвечает)
  if ! /usr/bin/yq --version 2>&1 | tee /dev/stderr | \
        grep -Eqi '(^|[[:space:]])v?4(\.|$)'; then
    echo '✗ yq v4 installation failed or wrong binary. Aborting.' >&2
    exit 13
  fi
fi

# ==== единственное клонирование репозитория =====
readonly REPO_TMP="$TMP_DIR/rzans_vpn_main"
git clone --depth=1 --filter=blob:none https://github.com/RazisID12/RzaNs_VPN_main.git "$REPO_TMP"

# инициализируем накопитель ошибок СРАЗУ
ERRORS=""

# ── AdGuard Home: УСТАНАВЛИВАЕМ ВСЕГДА, старт откладываем ───────────────
{
  echo
  echo 'Installing AdGuard Home...'
  
  AGH_DST="/opt/AdGuardHome"   # целевой каталог, всегда /opt/AdGuardHome
  AGH_SHA_FILE="${AGH_DST}/.tar.sha256"

  # универсальная загрузка с SHA256
  agh_base="https://static.adtidy.org/adguardhome/release"
  # выбираем архив под текущую архитектуру
  case "$(uname -m)" in
    x86_64|amd64)  agh_file="AdGuardHome_linux_amd64.tar.gz" ;;
    aarch64|arm64) agh_file="AdGuardHome_linux_arm64.tar.gz" ;;
    armv7l)        agh_file="AdGuardHome_linux_armv7.tar.gz" ;;
    armv6l)        agh_file="AdGuardHome_linux_armv6.tar.gz" ;;
    i386|i686)     agh_file="AdGuardHome_linux_386.tar.gz" ;;
    *)             agh_file="AdGuardHome_linux_amd64.tar.gz" ;;  # fallback
  esac
  agh_url="${agh_base}/${agh_file}"
  agh_tar="$TMP_DIR/${agh_file}"

  # Получаем контрольную сумму из checksums.txt (поддерживаем и ./filename, и filename)
  agh_ref_sha="$(
    curl --retry 3 -fsSL "${agh_base}/checksums.txt" \
    | awk -v f="$agh_file" '($NF==f || $NF=="./"f){print $1; exit}'
  )"
  [[ -n "$agh_ref_sha" ]] || { echo "✗ Cannot parse checksum"; exit 11; }

  # Если уже стоит та же версия (по SHA tar.gz) — пропускаем переустановку
  if [[ -f "$AGH_SHA_FILE" ]] && [[ "$(cat "$AGH_SHA_FILE" 2>/dev/null || true)" == "$agh_ref_sha" ]] \
     && [[ -x "${AGH_DST}/AdGuardHome" ]]; then
    echo "AdGuard Home is up to date; skipping reinstall."
  else
    # Скачать и проверить архив
    if ! curl --retry 3 -fsSL "$agh_url" -o "$agh_tar"; then
      echo "✗ AdGuard Home download failed" >&2; exit 10
    fi
    if ! echo "${agh_ref_sha}  $agh_tar" | sha256sum -c - --status; then
      echo "✗ AdGuard Home checksum mismatch"; exit 9
    fi

    # Каталог назначения
    install -d "${AGH_DST}"

    # Распаковка и обновление ТОЛЬКО бинарника (YAML/данные не трогаем)
    AGH_UNPACK="$TMP_DIR/agh_unpack"
    install -d "$AGH_UNPACK"
    tar -xzf "$agh_tar" -C "$AGH_UNPACK"
    if [[ -x "$AGH_UNPACK/AdGuardHome/AdGuardHome" ]]; then
      install -m 0755 "$AGH_UNPACK/AdGuardHome/AdGuardHome" "${AGH_DST}/AdGuardHome"
    elif [[ -x "$AGH_UNPACK/AdGuardHome" ]]; then
      install -m 0755 "$AGH_UNPACK/AdGuardHome" "${AGH_DST}/AdGuardHome"
    else
      echo "✗ AdGuard Home binary not found after extract"; exit 12
    fi
    echo "$agh_ref_sha" >"$AGH_SHA_FILE"
  fi

  # sanity-check: бинарь на месте и исполним
  if [[ ! -x "${AGH_DST}/AdGuardHome" ]]; then
      echo "✗ AdGuard Home binary not found after extract"; exit 12
  fi

  # Создаём системного пользователя для безопасного запуска сервиса
  if ! id adguardhome &>/dev/null; then
      NLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
      [[ -x "$NLOGIN" ]] || NLOGIN="/bin/false"
      useradd --system --home-dir "${AGH_DST}" --shell "$NLOGIN" adguardhome
  fi
  chown -R adguardhome:adguardhome "${AGH_DST}"

  echo 'AdGuard Home installed; service will be enabled later.'
} || { echo "✗ AdGuard Home installation failed"; exit 12; }

# ── Fail2Ban: УСТАНАВЛИВАЕМ ВСЕГДА, включаем по флагу ───────────────────
if ! apt_safe install -y fail2ban; then
    ERRORS+="\nFail2ban installation failed"
else
    # гасим, если автозапустился после установки
    SYSTEMD_LOG_LEVEL=err systemctl --no-pager stop fail2ban.service >/dev/null 2>&1 || true
    # базовые каталоги + файлы (кладём сразу, jail панели AGH безопасен —
    # лог уже создан; если сервис выключен, правил не будет)
    JLOCAL="$REPO_TMP/setup/etc/fail2ban/jail.local"
    JRECID="$REPO_TMP/setup/etc/fail2ban/jail.d/recidive.conf"
    JADGU="$REPO_TMP/setup/etc/fail2ban/jail.d/adguard-panel.conf"
    ACT_IP="$REPO_TMP/setup/etc/fail2ban/action.d/ipset-block.conf"
    FLT_AG="$REPO_TMP/setup/etc/fail2ban/filter.d/adguard-home-auth.conf"

    # НЕ перетираем пользовательский /etc/fail2ban/jail.local, если он уже есть
    [[ -f /etc/fail2ban/jail.local ]] || cp "$JLOCAL" /etc/fail2ban/jail.local \
      || ERRORS+=$'\nMissing jail.local in repo'
    install -d /etc/fail2ban/{action.d,filter.d,jail.d}
    cp "$JRECID"  /etc/fail2ban/jail.d/recidive.conf \
      || ERRORS+=$'\nMissing recidive.conf'
    cp "$ACT_IP"  /etc/fail2ban/action.d/ipset-block.conf \
      || ERRORS+=$'\nMissing ipset-block.conf'
    cp "$FLT_AG"  /etc/fail2ban/filter.d/adguard-home-auth.conf 2>/dev/null || true
    cp "$JADGU"   /etc/fail2ban/jail.d/adguard-panel.conf       2>/dev/null || true

    # по умолчанию — выключен
    SYSTEMD_LOG_LEVEL=err systemctl --no-pager disable --now fail2ban.service >/dev/null 2>&1 || true
fi

apt_safe autoremove -y
apt_safe clean

# dnslib из PyPI (без локального клона)
# Флаг --break-system-packages добавляем только если поддерживается
PIP_BSP=""
python3 -m pip help install 2>/dev/null | grep -q -- '--break-system-packages' && PIP_BSP="--break-system-packages"
python3 -m pip install --no-cache-dir --force-reinstall --no-deps $PIP_BSP "dnslib>=0.9.24"

# ────────────────────────────────────────────────────────────────────────────
# Развёртывание: раскладываем репозиторий в / и возвращаем оверлей-бэкап
# ────────────────────────────────────────────────────────────────────────────
find "$REPO_TMP" -name '.gitkeep' -delete 2>/dev/null || true
rm -rf --preserve-root /opt/rzans_vpn_main
cp -a "$REPO_TMP"/setup/* /
# Возвращаем пользовательские файлы поверх
cp -a "$STAGE/." /
SYSTEMD_LOG_LEVEL=err systemctl --no-pager daemon-reload >/dev/null 2>&1 || true
# ── Нормализация прав дерева репозитория
#   • каталоги: 0755
#   • файлы:    0644
#   • *.sh, *.py: исполняемые (0755)
#   • settings.yaml не трогаем (его чинит settings_fix_perms → 0600)
find /opt/rzans_vpn_main -type d -exec chmod 0755 {} +
find /opt/rzans_vpn_main -type f \
     -not -path '/opt/rzans_vpn_main/settings.yaml' \
     -not -name '*.sh' -not -name '*.py' -exec chmod 0644 {} +
find /opt/rzans_vpn_main -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 0755 {} +

 # ── FS sanity: чтобы сервисы не падали на /usr/bin/env и /usr/sbin/kresd ──
 # На некоторых системах /usr мог оказаться 0750 → юниты под неблаг. пользователями
 # не могут пройти по /usr и /usr/{bin,sbin}. Приводим к стандарту 0755.
 _fix_traverse_dir() {
   local d="$1"
   [[ -d "$d" ]] || return 0
   chown root:root "$d" 2>/dev/null || true
   chmod u+rwx,go+rx,go-w "$d" 2>/dev/null || true   # 0755
 }
 for d in /usr /usr/bin /usr/sbin; do
   _fix_traverse_dir "$d"
 done

 # Подсветим noexec на /usr (лечить монтирование здесь не будем)
 if command -v findmnt >/dev/null 2>&1; then
   if findmnt -no OPTIONS /usr 2>/dev/null | grep -qw noexec; then
     echo -e "\e[1;33mWARNING:\e[0m /usr смонтирован с noexec — бинарники не запустятся."
   fi
 fi

##############################################################################
# PREPARE + применение ответов (после возврата бэкапа)                       #
##############################################################################
# Укажем явный путь к settings.yaml ДО prepare/source, чтобы все хелперы
# использовали один и тот же файл.
export SETTINGS_YAML="${SETTINGS_YAML:-/opt/rzans_vpn_main/settings.yaml}"
echo "Using settings file: $SETTINGS_YAML"

/usr/bin/env bash /opt/rzans_vpn_main/settings/settings.sh --prepare
# shellcheck source=/opt/rzans_vpn_main/settings/settings.sh
source /opt/rzans_vpn_main/settings/settings.sh

echo
echo "yq version: $(/usr/bin/yq --version 2>/dev/null || echo unknown)"
echo 'Saving answers…'
set -u
if [[ -s "$ANS_FILE" ]]; then
  # Покажем, что именно попало в answers, до применения к YAML
  echo "Captured installer answers (debug):"
  # Отфильтруем ключевые строки для краткости
  grep -E '^(DNS_UPSTREAM|ADGUARD_HOME|SSH_PROTECTION|SERVER_HOST|ROUTE_ALL|[A-Z_]+_INCLUDE)=' "$ANS_FILE" \
    | LC_ALL=C sort || true
  # При необходимости можно вывести весь файл:
  # sed -n '1,200p' "$ANS_FILE" || true
  echo
  # Снапшот настроек ДО применения
  cp -f "$SETTINGS_YAML" "$TMP_DIR/settings.before.yaml" 2>/dev/null || true
  # shellcheck disable=SC1090
  source "$ANS_FILE"
else
  echo "✗ answers file missing: $ANS_FILE"; exit 50
fi

# дефолты на случай неполного ANS_FILE
: "${DNS_UPSTREAM:=cloudflare}"
: "${ADGUARD_HOME:=n}"; : "${SSH_PROTECTION:=n}"
: "${SERVER_HOST:=}"; : "${ROUTE_ALL:=n}"
: "${DISCORD_INCLUDE:=y}"; : "${CLOUDFLARE_INCLUDE:=y}"
: "${AMAZON_INCLUDE:=n}"; : "${HETZNER_INCLUDE:=n}"
: "${DIGITALOCEAN_INCLUDE:=n}"; : "${OVH_INCLUDE:=n}"
: "${TELEGRAM_INCLUDE:=n}"; : "${GOOGLE_INCLUDE:=n}"
: "${AKAMAI_INCLUDE:=n}"

# y/n → true/false (для YAML)
yn2bool() {
  case "${1,,}" in
    y|yes|true|1|on|enable|enabled)  echo true ;;
    *)                               echo false ;;
  esac
}

# Сформировать overlay YAML из ответов установщика
make_answers_yaml() {
  local _domain="${SERVER_HOST:-}"
  [[ -z "$_domain" ]] && _domain="auto"
  cat <<EOF
dns:
  upstream: "${DNS_UPSTREAM}"

adguard_home:
  enable: $(yn2bool "$ADGUARD_HOME")

fail2ban:
  enable: $(yn2bool "$SSH_PROTECTION")

server:
  domain: "${_domain}"

routing:
  route_all: $(yn2bool "$ROUTE_ALL")
  flags:
    discord:      $(yn2bool "$DISCORD_INCLUDE")
    cloudflare:   $(yn2bool "$CLOUDFLARE_INCLUDE")
    amazon:       $(yn2bool "$AMAZON_INCLUDE")
    hetzner:      $(yn2bool "$HETZNER_INCLUDE")
    digitalocean: $(yn2bool "$DIGITALOCEAN_INCLUDE")
    ovh:          $(yn2bool "$OVH_INCLUDE")
    telegram:     $(yn2bool "$TELEGRAM_INCLUDE")
    google:       $(yn2bool "$GOOGLE_INCLUDE")
    akamai:       $(yn2bool "$AKAMAI_INCLUDE")
EOF
}

# Атомарная запись под локом (yaml_set сам умеет брать лок, внешний — для партии)
_ensure_settings_lock 2>/dev/null || true

ANS_YAML="${TMP_DIR}/answers.yaml"
make_answers_yaml > "$ANS_YAML"

# Глубокий merge: settings := settings * answers
yq ea -i 'select(fileIndex==0) * select(fileIndex==1)' \
  "$SETTINGS_YAML" "$ANS_YAML" \
  || { echo "✗ failed to merge installer answers into $SETTINGS_YAML"; exit 51; }

# Привести права как обычно
settings_fix_perms || true

_release_settings_lock 2>/dev/null || true
sync || true
rm -f -- "$ANS_YAML" 2>/dev/null || true

# Покажем diff настроек «до → после» (если есть чем сравнить)
if [[ -s "$TMP_DIR/settings.before.yaml" ]]; then
  echo "settings.yaml diff (before → after):"
  if command -v diff >/dev/null 2>&1; then
    diff -u "$TMP_DIR/settings.before.yaml" "$SETTINGS_YAML" || true
  else
    echo "(diff utility not found)"
  fi
  echo
fi

# ⮕ Диагностика: покажем, откуда читаем, и ключевые строки файла
echo
echo "DEBUG: SETTINGS_YAML -> $SETTINGS_YAML"
if [[ -f "$SETTINGS_YAML" ]]; then
  ls -l -- "$SETTINGS_YAML" || true
  echo "DEBUG: head of settings.yaml:"
  sed -n '1,25p' -- "$SETTINGS_YAML" || true
else
  echo "✗ settings.yaml not found at $SETTINGS_YAML"
fi

# Явная верификация того, что в файле действительно наши ответы
echo
echo "Verifying applied settings (from: $SETTINGS_YAML):"
/usr/bin/yq e -r '
  .dns.upstream,
  .adguard_home.enable,
  .fail2ban.enable,
  .server.domain
' "$SETTINGS_YAML" || true
echo "routing.flags effective (from: $SETTINGS_YAML):"
/usr/bin/yq e -P '.routing.flags' "$SETTINGS_YAML" || true

# На всякий случай — сверка ожиданий против файла
echo -n "EXPECT dns.upstream=$DNS_UPSTREAM ; GOT="
/usr/bin/yq e -r '.dns.upstream' "$SETTINGS_YAML" || true
echo -n "EXPECT adguard_home.enable=$( [[ $(normalize_yn "$ADGUARD_HOME") == y ]] && echo true || echo false ) ; GOT="
/usr/bin/yq e -r '.adguard_home.enable' "$SETTINGS_YAML" || true
echo -n "EXPECT fail2ban.enable=$( [[ $(normalize_yn "$SSH_PROTECTION") == y ]] && echo true || echo false ) ; GOT="
/usr/bin/yq e -r '.fail2ban.enable' "$SETTINGS_YAML" || true
echo -n "EXPECT routing.flags.telegram=$( [[ $(normalize_yn "$TELEGRAM_INCLUDE") == y ]] && echo true || echo false ) ; GOT="
/usr/bin/yq e -r '.routing.flags.telegram' "$SETTINGS_YAML" || true

# и как это увидит downloader (через yaml_bool, как в update.sh)
echo "yaml_bool checks:"
for f in discord cloudflare amazon hetzner digitalocean ovh telegram google akamai; do
  printf '%s=%s ' "$f" "$(yaml_bool "routing.flags.$f" n)"
done
echo

echo
echo 'Proceeding with installation…'

echo -e '\nDownloading base lists (lists-mode)…'
/opt/rzans_vpn_main/doall.sh lists

# sanity-check: подсветим, если что-то не сгенерилось
if [[ ! -s /etc/knot-resolver/upstream_dns.lua ]]; then
  ERRORS+=$'\nMissing /etc/knot-resolver/upstream_dns.lua after prepare'
fi
if [[ "$ADGUARD_HOME" == y && ! -s /opt/AdGuardHome/AdGuardHome.yaml ]]; then
  ERRORS+=$'\nMissing /opt/AdGuardHome/AdGuardHome.yaml after prepare'
fi

# теперь перерегистрируем юниты и включаем всё после генерации конфигов
SYSTEMD_LOG_LEVEL=err systemctl --no-pager daemon-reload >/dev/null 2>&1 || true
enable_if_present() {
  SYSTEMD_LOG_LEVEL=err systemctl --no-pager cat "$1" &>/dev/null \
    && SYSTEMD_LOG_LEVEL=err systemctl --no-pager enable "$1" >/dev/null 2>&1 \
    || true
}

enable_post_install() {
  # 1) Системные — ничего дополнительно включать не нужно
  :
  # 2) Потенциально мешающие — не включаем
  :
  # 3) Зависимости проекта
  if [[ -s /etc/knot-resolver/upstream_dns.lua ]]; then
    enable_if_present kresd@1.service
    enable_if_present kresd@2.service
    enable_if_present kresd@3.service
    enable_if_present kresd@4.service
  else
    ERRORS+=$'\nSkip enabling kresd@* (no upstream_dns.lua)'
  fi
  enable_if_present wg-quick@rzans_svpn_main.service
  enable_if_present wg-quick@rzans_fvpn_main.service
  # AdGuard Home — по выбору мастера и при наличии YAML
  if [[ "$ADGUARD_HOME" == y ]] && [[ -s /opt/AdGuardHome/AdGuardHome.yaml ]] \
     && SYSTEMD_LOG_LEVEL=err systemctl --no-pager cat AdGuardHome.service >/dev/null 2>&1; then
    SYSTEMD_LOG_LEVEL=err systemctl --no-pager enable AdGuardHome.service >/dev/null 2>&1 || true
  fi
  # Fail2Ban — по выбору мастера
  if [[ "$SSH_PROTECTION" == y ]] \
     && SYSTEMD_LOG_LEVEL=err systemctl --no-pager cat fail2ban.service >/dev/null 2>&1; then
    SYSTEMD_LOG_LEVEL=err systemctl --no-pager enable fail2ban.service >/dev/null 2>&1 || true
  fi
  # Системные сервисы, которые используем (не кастомные)
  enable_if_present logrotate.timer
  # если активен systemd-таймер logrotate — уберём возможный дубль из cron.daily
  if SYSTEMD_LOG_LEVEL=err systemctl --no-pager is-enabled logrotate.timer >/dev/null 2>&1 \
     && [ -f /etc/cron.daily/logrotate ]; then
    mv /etc/cron.daily/logrotate /etc/cron.daily/logrotate.disabled 2>/dev/null || true
  fi
  # 4) Наши кастомные
  enable_if_present lo_ipv6@::2.service
  enable_if_present first_init.service
  enable_if_present apply.path
  enable_if_present firewall.service
  enable_if_present proxy.service
  enable_if_present dwnld_update.timer
}

enable_post_install

# ── Настраиваем swap (512 МБ) только если сейчас нет активного swap ───────────
if [[ -z "$(swapon --show)" ]]; then
  SWAPFILE="/swapfile"
  SWAPSIZE=512

  # если файла нет — создаём; если есть — используем существующий
  if [[ ! -f $SWAPFILE ]]; then
    if command -v fallocate &>/dev/null; then
      fallocate -l "${SWAPSIZE}M" "$SWAPFILE" 2>/dev/null \
        || ERRORS+=$'\nSwap creation failed (fallocate)'
    else
      dd if=/dev/zero of="$SWAPFILE" bs=1M count="$SWAPSIZE" status=none \
        || ERRORS+=$'\nSwap creation failed (dd)'
    fi
  fi

  if [[ -s $SWAPFILE ]]; then
    # Нормализуем права с учётом SELinux-меток, если доступно
    _root0600 "$SWAPFILE" 2>/dev/null || true
    # пробуем просто включить; при отсутствии сигнатуры создаём её
    swapon "$SWAPFILE" 2>/dev/null || { mkswap "$SWAPFILE" && swapon "$SWAPFILE"; }
    grep -q "^$SWAPFILE " /etc/fstab \
      || echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  fi
fi

# выводим накопленные ошибки (красным)
if [[ -n "$ERRORS" ]]; then
  echo -e "\e[1;31m$ERRORS\e[0m"
fi

echo
echo -e '\e[1;32mRzaNs_VPN_main installed successfully!\e[0m'
for t in 5 4 3 2 1; do
  printf '\r\033[1;33mRebooting in %s seconds… (Ctrl-C to cancel)\033[0m ' "$t"
  sleep 1
done
echo
trap - EXIT
cleanup_tmp
reboot
