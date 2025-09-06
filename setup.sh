#!/bin/bash
# ==============================================================================
# Скрипт для установки на своём сервере RzaNs_VPN_main
# ==============================================================================
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027
export LC_ALL=C
set -euo pipefail
set -E -o errtrace

# ── helper: строгое y/n ─────────────────────────────────────────────────────
# ask_yn "Prompt (без [y/n])" [default:y|n]  → печатает 'y' или 'n'
ask_yn() {
  local prompt="$1"
  local def="${2:-y}"
  [[ "$def" != "y" && "$def" != "n" ]] && def="y"
  local ans=""
  while true; do
    # Readline + дефолт; приводим к нижнему регистру, чистим \r и пробелы
    read -rp "${prompt} [y/n]: " -e -i "$def" ans
    # нижний регистр
    ans="${ans,,}"
    # убираем CR, потом тримим пробелы по краям
    ans="${ans//$'\r'/}"
    ans="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$ans")"
    case "$ans" in
      y|n) printf '%s' "$ans"; return 0 ;;
      *) : ;;  # повтор вопроса
    esac
  done
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

echo
echo -e '\e[1;32mInstalling RzaNs_VPN_main (split + full VPN)...\e[0m'
echo 'AmneziaWG'
echo 'More details: https://github.com/RazisID12/RzaNs_VPN_main'

# Спрашиваем о настройках
set +u
echo
echo -e 'Choose upstream \e[1;32mDNS\e[0m (applies to Split&Full):'
echo '    1) Cloudflare'
echo '    2) Quad9'
echo '    3) Google'
until [[ "$UPSTREAM_DNS" =~ ^[1-3]$ ]]; do
	read -rp 'DNS choice [1-3]: ' -e -i 1 UPSTREAM_DNS
done

# ── AdGuard Home сразу как единственный фильтр ────────────────────────
ADGUARD_HOME="$(ask_yn $'Install and use \001\e[1;36m\002AdGuard Home\001\e[0m\002 for DNS filtering?' y)"

echo
SSH_PROTECTION="$(ask_yn $'Enable \001\e[1;36m\002SSH protection\001\e[0m\002?' y)"

echo
while true; do
  read -rp $'Enter valid \001\e[1;36m\002domain name\001\e[0m\002 for this server or press Enter to skip: ' -e SERVER_HOST
  [[ -z $SERVER_HOST ]] && break
  readarray -t _ip_test < <(getent ahostsv4 "$SERVER_HOST") || true
  [[ ${#_ip_test[@]} -gt 0 ]] && break
done
unset _ip_test
echo
ROUTE_ALL="$(ask_yn $'Enable \001\e[1;36m\002route all\001\e[0m\002 traffic via Split VPN, excluding Russian domains and domains from exclude-hosts.txt?' n)"
echo
DISCORD_INCLUDE="$(ask_yn $'Include \001\e[1;36m\002Discord\001\e[0m\002 voice IPs in Split VPN?' y)"
echo
CLOUDFLARE_INCLUDE="$(ask_yn $'Include \001\e[1;36m\002Cloudflare\001\e[0m\002 IPs in Split VPN?' y)"
echo
AMAZON_INCLUDE="$(ask_yn $'Include \001\e[1;36m\002Amazon\001\e[0m\002 IPs in Split VPN?' n)"
echo
HETZNER_INCLUDE="$(ask_yn $'Include \001\e[1;36m\002Hetzner\001\e[0m\002 IPs in Split VPN?' n)"
echo
DIGITALOCEAN_INCLUDE="$(ask_yn $'Include \001\e[1;36m\002DigitalOcean\001\e[0m\002 IPs in Split VPN?' n)"
echo
OVH_INCLUDE="$(ask_yn $'Include \001\e[1;36m\002OVH\001\e[0m\002 IPs in Split VPN?' n)"
echo
TELEGRAM_INCLUDE="$(ask_yn $'Include \001\e[1;36m\002Telegram\001\e[0m\002 IPs in Split VPN?' n)"
echo
GOOGLE_INCLUDE="$(ask_yn $'Include \001\e[1;36m\002Google\001\e[0m\002 IPs in Split VPN?' n)"
echo
AKAMAI_INCLUDE="$(ask_yn $'Include \001\e[1;36m\002Akamai\001\e[0m\002 IPs in Split VPN?' n)"
echo
echo 'Preparing for installation, please wait...'
set -u   # ◄ возвращаем строгий режим после всех read/until

# Ожидание, пока пакетный менеджер не освободит lock (если есть pidof)
if command -v pidof &>/dev/null; then
# ждём максимум 5 мин (300 с), пока не освободятся apt-get / dpkg …
lock_t0=$(date +%s)
while pidof apt apt-get dpkg unattended-upgrade apt.systemd.daily apt.systemd.daily-update &>/dev/null; do
  [[ $(( $(date +%s) - lock_t0 )) -ge 300 ]] && {
      echo '✗ APT lock is still held after 5 min — aborting.' >&2
      exit 12
  }
  echo 'Waiting for package manager to finish…'
  sleep 5
done
fi

# Отключим фоновые обновления системы
systemctl stop unattended-upgrades.service &>/dev/null || true
systemctl stop apt-daily.timer            &>/dev/null || true
systemctl stop apt-daily-upgrade.timer    &>/dev/null || true

# Удаление или перемещение файлов и папок при обновлении
systemctl stop dnsmap.service  &>/dev/null || true
systemctl disable dnsmap.service &>/dev/null || true
systemctl stop ferm.service    &>/dev/null || true
systemctl disable ferm.service &>/dev/null || true

rm -f /etc/sysctl.d/10-conntrack.conf
rm -f /etc/sysctl.d/20-network.conf
rm -f /etc/sysctl.d/99-rzans_vpn_main.conf
rm -f /etc/systemd/network/eth.network
rm -f /etc/systemd/network/host.network
rm -f /etc/systemd/system/dnsmap.service
rm -f /usr/share/keyrings/cznic-labs-pkg.gpg
rm -f /opt/upgrade.sh
rm -f /opt/generate.sh
rm -f /opt/create-swap.sh
rm -f /opt/add-client.sh
rm -f /opt/delete-client.sh
rm -f /opt/rzans_*.conf
rm -rf --preserve-root /opt/vpn
rm -rf --preserve-root /opt/easy-rsa-ipsec
rm -rf --preserve-root /opt/.gnupg
rm -rf --preserve-root /opt/dnsmap

apt-get purge -y python3-dnslib &>/dev/null || true
apt-get purge -y yq python3-yq  &>/dev/null || true
apt-get purge -y gnupg2           &>/dev/null || true
apt-get purge -y ferm             &>/dev/null || true
apt-get purge -y libpam0g-dev     &>/dev/null || true
apt-get purge -y sshguard         &>/dev/null || true

# Остановим и выключим обновляемые службы
for service in kresd@ wg-quick@; do
	systemctl list-units --type=service --no-pager | awk -v s="$service" '$1 ~ s"[^.]+\\.service" {print $1}' | xargs -r systemctl stop &>/dev/null
	systemctl list-unit-files --type=service --no-pager | awk -v s="$service" '$1 ~ s"[^.]+\\.service" {print $1}' | xargs -r systemctl disable &>/dev/null
done

# останавливаем/отключаем наши юниты ДО любых правок YAML/конфигов
systemctl stop    core.service dwnld_update.service dwnld_update.timer apply.path apply.service init.service &>/dev/null || true
systemctl disable core.service dwnld_update.service dwnld_update.timer apply.path apply.service init.service &>/dev/null || true

# Остановим и выключим ненужные службы
systemctl stop firewalld.service &>/dev/null || true
if command -v ufw &>/dev/null; then
  ufw disable &>/dev/null || true
  systemctl stop ufw.service &>/dev/null || true
fi

systemctl disable firewalld.service &>/dev/null || true
if command -v ufw &>/dev/null; then systemctl disable ufw.service &>/dev/null || true; fi

# Удаляем старые файлы и кеш Knot Resolver
shopt -s nullglob
rm -rf /var/cache/knot-resolver/* /etc/knot-resolver/* /var/lib/knot-resolver/*
shopt -u nullglob

# Удаляем старые файлы AmneziaWG
#rm -rf /etc/wireguard/templates/*

# Обновляем систему
apt-get clean
apt-get update
export DEBIAN_FRONTEND=noninteractive
apt-get -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        dist-upgrade -y
apt-get -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        install --reinstall -y curl gpg

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

apt-get update

# Ставим необходимые пакеты
apt-get -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        install --reinstall -y --no-install-recommends \
                              git iptables gawk knot-resolver sipcalc python3 python3-pip \
                              wireguard-tools diffutils socat lua-cqueues ipset at file \
                              libcap2-bin logrotate gettext-base ca-certificates \
                              acl attr uuid-runtime binutils
#
# libidn (idn) vs libidn2 (idn2) отличаются по дистрибутивам — пробуем по очереди, не валим установку
apt-get install -y idn || apt-get install -y idn2 || true
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

# инициализируем накопитель ошибок СРАЗУ,
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
if ! apt-get -o Dpkg::Options::=--force-confdef \
              -o Dpkg::Options::=--force-confold \
              install -y fail2ban; then
    ERRORS+="\nFail2ban installation failed"
else
    # гасим, если автозапустился после установки
    systemctl stop fail2ban.service 2>/dev/null || true
    # базовые каталоги + файлы (кладём сразу, jail панели AGH безопасен —
    # лог уже создан; если сервис выключен, правил не будет)
    JLOCAL="$REPO_TMP/setup/etc/fail2ban/jail.local"
    JRECID="$REPO_TMP/setup/etc/fail2ban/jail.d/recidive.conf"
    JADGU="$REPO_TMP/setup/etc/fail2ban/jail.d/adguard-panel.conf"
    ACT_IP="$REPO_TMP/setup/etc/fail2ban/action.d/ipset-block.conf"
    FLT_AG="$REPO_TMP/setup/etc/fail2ban/filter.d/adguard-home-auth.conf"

    install -d /etc/fail2ban/{action.d,filter.d,jail.d}
    cp "$JLOCAL"  /etc/fail2ban/jail.local         || ERRORS+=$'\nMissing jail.local'
    cp "$JRECID"  /etc/fail2ban/jail.d/recidive.conf \
      || ERRORS+=$'\nMissing recidive.conf'
    cp "$ACT_IP"  /etc/fail2ban/action.d/ipset-block.conf \
      || ERRORS+=$'\nMissing ipset-block.conf'
    cp "$FLT_AG"  /etc/fail2ban/filter.d/adguard-home-auth.conf 2>/dev/null || true
    cp "$JADGU"   /etc/fail2ban/jail.d/adguard-panel.conf       2>/dev/null || true

    # по умолчанию — выключен
    systemctl disable --now fail2ban.service 2>/dev/null || true
fi

apt-get autoremove -y
apt-get clean

# dnslib из PyPI (без локального клона)
# Флаг --break-system-packages добавляем только если поддерживается
PIP_BSP=""
python3 -m pip help install 2>/dev/null | grep -q -- '--break-system-packages' && PIP_BSP="--break-system-packages"
python3 -m pip install --no-cache-dir --force-reinstall --no-deps $PIP_BSP "dnslib>=0.9.24"

# ────────────────────────────────────────────────────────────────────────────
# Persist user config + settings.yaml и серверные WG-конфиги (clean install)
# ────────────────────────────────────────────────────────────────────────────
# Стейдж-директории
install -d "$REPO_TMP"/setup/opt/rzans_vpn_main
install -d "$REPO_TMP"/setup/opt/rzans_vpn_main/config
install -d -m 0700 "$REPO_TMP"/setup/etc/wireguard

# 1) Полный перенос /opt/rzans_vpn_main/config (рекурсивно, с атрибутами)
if [[ -d /opt/rzans_vpn_main/config ]]; then
  # копируем содержимое каталога, включая скрытые файлы
  cp -a /opt/rzans_vpn_main/config/. "$REPO_TMP"/setup/opt/rzans_vpn_main/config/ 2>/dev/null || true
fi

# 2) Перенос settings.yaml (если существовал) в корень /opt/rzans_vpn_main/
if [[ -s /opt/rzans_vpn_main/settings.yaml ]]; then
  install -D -m 0600 /opt/rzans_vpn_main/settings.yaml \
    "$REPO_TMP"/setup/opt/rzans_vpn_main/settings.yaml
fi

# 3) WireGuard: сохраняем только серверные артефакты, чтобы клиенты не отвалились
#    (конфиги интерфейсов, ключ, карта IP; плюс внешние файлы ключей, если на них есть ссылки)
for f in rzans_svpn_main.conf rzans_fvpn_main.conf; do
  if [[ -s "/etc/wireguard/$f" ]]; then
    install -m 0600 "/etc/wireguard/$f" "$REPO_TMP"/setup/etc/wireguard/
  fi
done
for f in key ips; do
  if [[ -s "/etc/wireguard/$f" ]]; then
    install -m 0600 "/etc/wireguard/$f" "$REPO_TMP"/setup/etc/wireguard/
  fi
done
# Подтянем внешние файлы ключей/PSK, если конфиги ссылаются на них
mapfile -t _refs < <(
  grep -Eh '^(PrivateKeyFile|PresharedKeyFile)[[:space:]]*=' \
    /etc/wireguard/rzans_*vpn_main.conf 2>/dev/null \
  | awk -F= '{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' \
  | awk 'NF'
)
for p in "${_refs[@]}"; do
  [[ -s "$p" ]] || continue
  install -D -m 0600 "$p" "$REPO_TMP"/setup"$p"
done

# Копируем нужное, удаляем не нужное
find "$REPO_TMP" -name '.gitkeep' -delete
rm -rf --preserve-root /opt/rzans_vpn_main
cp -a "$REPO_TMP"/setup/* /
systemctl daemon-reload
chmod +x /opt/rzans_vpn_main/settings/settings.sh 2>/dev/null || true

# --- Итоговые ответы мастера → overlay + prepare ----------------------------
# Выбор DNS → имя провайдера
case "$UPSTREAM_DNS" in
  1) DNS_UPSTREAM=cloudflare ;;
  2) DNS_UPSTREAM=quad9      ;;
  3) DNS_UPSTREAM=google     ;;
esac

# Сформировать overlay из ответов мастера
OVER="${TMP_DIR}/installer.overlay.yaml"
cat >"$OVER" <<EOF
dns:
  upstream: ${DNS_UPSTREAM}
adguard_home:
  enable: $( [[ $ADGUARD_HOME   == y ]] && echo true || echo false )
fail2ban:
  enable: $( [[ $SSH_PROTECTION == y ]] && echo true || echo false )
server:
  domain: ${SERVER_HOST:-auto}
routing:
  route_all: $( [[ $ROUTE_ALL == y ]] && echo true || echo false )
  flags:
    discord:      $( [[ $DISCORD_INCLUDE      == y ]] && echo true || echo false )
    cloudflare:   $( [[ $CLOUDFLARE_INCLUDE   == y ]] && echo true || echo false )
    amazon:       $( [[ $AMAZON_INCLUDE       == y ]] && echo true || echo false )
    hetzner:      $( [[ $HETZNER_INCLUDE      == y ]] && echo true || echo false )
    digitalocean: $( [[ $DIGITALOCEAN_INCLUDE == y ]] && echo true || echo false )
    ovh:          $( [[ $OVH_INCLUDE          == y ]] && echo true || echo false )
    telegram:     $( [[ $TELEGRAM_INCLUDE     == y ]] && echo true || echo false )
    google:       $( [[ $GOOGLE_INCLUDE       == y ]] && echo true || echo false )
    akamai:       $( [[ $AKAMAI_INCLUDE       == y ]] && echo true || echo false )
EOF

echo -e '\nPreparing configs from installer answers…'
/usr/bin/env bash /opt/rzans_vpn_main/settings/settings.sh --prepare-overlay "$OVER"

S=/opt/rzans_vpn_main/settings.yaml
echo "[DEBUG] overlay written to: $S"
echo "[DEBUG] adguard_home.enable=$(yq e -r '.adguard_home.enable' "$S")"
echo "[DEBUG] fail2ban.enable=$(yq e -r '.fail2ban.enable' "$S")"
echo "[DEBUG] dns.upstream=$(yq e -r '.dns.upstream' "$S")"
echo "[DEBUG] routing.route_all=$(yq e -r '.routing.route_all' "$S")"

# Универсальная проверка: всё, что положили в $OVER, обязано
# один-в-один оказаться в /opt/rzans_vpn_main/settings.yaml.
# Сравниваем только скаляры (строки/числа/bool), игнорируя структуры.
echo "[DEBUG] verifying overlay → settings.yaml…"
MISM="$(yq ea -o=json -I=0 '
  # fi==0 → overlay, fi==1 → settings.yaml
  select(fi==0) as $OV | select(fi==1) as $SET |
  paths(scalars) as $p |
  { key: ($p|join(".")), exp: ($OV|getpath($p)), got: ($SET|getpath($p)//"__absent__") } |
  select(.got != .exp)
' "$OVER" "$S")"
if [[ -n "$MISM" ]]; then
  echo "✗ overlay mismatch(es) detected:"
  # Красиво распечатаем список несовпадений (если yq можно задействовать повторно)
  printf '%s\n' "$MISM" | yq e -P - 2>/dev/null || printf '%s\n' "$MISM"
  exit 50
fi

# --- Права для Knot Resolver и RPZ-файлов -------------------------------
# каталоги (после того как мы всё подчистили выше)
install -d -o knot-resolver -g knot-resolver -m 755 /etc/knot-resolver
install -d -o knot-resolver -g knot-resolver -m 755 /var/lib/knot-resolver

# ── каталоги LMDB-кэша для ЧЕТЫРЁХ инстансов (@1…@4)
# новая схема: /var/cache/knot-resolver/{1,2,3,4}
install -d -o knot-resolver -g knot-resolver -m 755 /var/cache/knot-resolver
# прибьём легаси-пути, если такие вдруг остались
rm -rf /var/cache/knot-resolver1 /var/cache/knot-resolver2 2>/dev/null || true
for d in 1 2 3 4; do
    install -d -o knot-resolver -g knot-resolver -m 755 "/var/cache/knot-resolver/$d"
    find "/var/cache/knot-resolver/$d" -mindepth 1 -delete 2>/dev/null || true
done

# RPZ из репозитория: привести владельца/права; если нет — создать пустой
if [[ -f /etc/knot-resolver/proxy.rpz ]]; then
  chown knot-resolver:knot-resolver /etc/knot-resolver/proxy.rpz || true
  chmod 644 /etc/knot-resolver/proxy.rpz || true
else
  install -o knot-resolver -g knot-resolver -m 644 /dev/null /etc/knot-resolver/proxy.rpz
fi

# ── единый блок прав на ВСЁ содержимое
find /opt/rzans_vpn_main -type d -exec chmod 755 {} +
find /opt/rzans_vpn_main -type f ! -name '*.sh' ! -name '*.py' ! -name 'settings.yaml' -exec chmod 644 {} +
find /opt/rzans_vpn_main -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod +x {} +

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
systemctl daemon-reload
enable_if_present() { systemctl cat "$1" &>/dev/null && systemctl enable "$1" || true; }
enable_if_present init.service
enable_if_present apply.path
enable_if_present firewall.service
enable_if_present proxy.service
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
# AdGuard Home: включаем по выбору мастера (старт — после ребута) только если YAML есть
if [[ "$ADGUARD_HOME" == y ]] && [[ -s /opt/AdGuardHome/AdGuardHome.yaml ]] \
   && systemctl cat AdGuardHome.service >/dev/null 2>&1; then
  systemctl enable AdGuardHome.service
fi
# Fail2Ban: включаем по выбору мастера (старт — после ребута)
if [[ "$SSH_PROTECTION" == y ]] && systemctl cat fail2ban.service >/dev/null 2>&1; then
  systemctl enable fail2ban.service
fi
enable_if_present atd.service
enable_if_present dwnld_update.timer
enable_if_present logrotate.timer
# если активен systemd-таймер logrotate — уберём возможный дубль из cron.daily
if systemctl is-enabled logrotate.timer >/dev/null 2>&1 && [ -f /etc/cron.daily/logrotate ]; then
  mv /etc/cron.daily/logrotate /etc/cron.daily/logrotate.disabled 2>/dev/null || true
fi

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
    if declare -F _root0600 >/dev/null 2>&1; then
      _root0600 "$SWAPFILE" || true
    else
      chmod 600 "$SWAPFILE" || true
    fi
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
