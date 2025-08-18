#!/bin/bash
# ==============================================================================
# Скрипт для установки на своём сервере RzaNs_VPN_main
# ==============================================================================
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027
export LC_ALL=C
set -euo pipefail
set -E -o errtrace

# ──────────────────────────────────────────────────────────────────────────────
# helper: ensure_agh_perms
#   • чинит права AdGuardHome.yaml
#   • вызов безопасен повторно (идемпотентен)
# ──────────────────────────────────────────────────────────────────────────────
ensure_agh_perms() {
  local agh_yaml="/opt/AdGuardHome/AdGuardHome.yaml"
  if [[ -f $agh_yaml ]]; then
    chown adguardhome:adguardhome "$agh_yaml" || true
    chmod 640 "$agh_yaml" || true
  fi
}

# ── локальный tmp и его авточистка ────────────────────────────────────────────
TMP_DIR=$(mktemp -d -t rzansvpn.XXXXXX)
cleanup_tmp() {
  rm -rf "$TMP_DIR" 2>/dev/null || true
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

# Проверка на OpenVZ и LXC (если утилита есть)
if command -v systemd-detect-virt &>/dev/null && \
   [[ "$(systemd-detect-virt)" == "openvz" || "$(systemd-detect-virt)" == "lxc" ]]; then
	echo 'Error: OpenVZ and LXC are not supported!'
	exit 3
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
until [[ "$ADGUARD_HOME" =~ (y|n) ]]; do
  read -rp $'Install and use \001\e[1;36m\002AdGuard Home\001\e[0m\002 for DNS filtering? [y/n]: ' -e -i y ADGUARD_HOME
done

echo
until [[ "$SSH_PROTECTION" =~ (y|n) ]]; do
  read -rp $'Enable \001\e[1;36m\002SSH brute-force protection\001\e[0m\002? [y/n]: ' -e -i y SSH_PROTECTION
done

echo
while true; do
  read -rp 'Enter valid domain name for this server or press Enter to skip: ' -e SERVER_HOST
  [[ -z $SERVER_HOST ]] && break
  readarray -t _ip_test < <(getent ahostsv4 "$SERVER_HOST") || true
  [[ ${#_ip_test[@]} -gt 0 ]] && break
done
unset _ip_test
echo
until [[ "$ROUTE_ALL" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002ROUTE_ALL\001\e[0m\002 – route all traffic via Split VPN, excluding Russian domains and domains from exclude-hosts.txt? [y/n]: ' -e -i n ROUTE_ALL
done
echo
until [[ "$DISCORD_INCLUDE" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002DISCORD_INCLUDE\001\e[0m\002 – include Discord voice IPs in Split VPN? [y/n]: ' -e -i y DISCORD_INCLUDE
done
echo
until [[ "$CLOUDFLARE_INCLUDE" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002CLOUDFLARE_INCLUDE\001\e[0m\002 – include Cloudflare IPs in Split VPN? [y/n]: ' -e -i y CLOUDFLARE_INCLUDE
done
echo
until [[ "$AMAZON_INCLUDE" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002AMAZON_INCLUDE\001\e[0m\002 – include Amazon IPs in Split VPN? [y/n]: ' -e -i n AMAZON_INCLUDE
done
echo
until [[ "$HETZNER_INCLUDE" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002HETZNER_INCLUDE\001\e[0m\002 – include Hetzner IPs in Split VPN? [y/n]: ' -e -i n HETZNER_INCLUDE
done
echo
until [[ "$DIGITALOCEAN_INCLUDE" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002DIGITALOCEAN_INCLUDE\001\e[0m\002 – include DigitalOcean IPs in Split VPN? [y/n]: ' -e -i n DIGITALOCEAN_INCLUDE
done
echo
until [[ "$OVH_INCLUDE" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002OVH_INCLUDE\001\e[0m\002 – include OVH IPs in Split VPN? [y/n]: ' -e -i n OVH_INCLUDE
done
echo
until [[ "$TELEGRAM_INCLUDE" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002TELEGRAM_INCLUDE\001\e[0m\002 – include Telegram IPs in Split VPN? [y/n]: ' -e -i n TELEGRAM_INCLUDE
done
echo
until [[ "$GOOGLE_INCLUDE" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002GOOGLE_INCLUDE\001\e[0m\002 – include Google IPs in Split VPN? [y/n]: ' -e -i n GOOGLE_INCLUDE
done
echo
until [[ "$AKAMAI_INCLUDE" =~ (y|n) ]]; do
  read -rp $'\001\e[1;32m\002AKAMAI_INCLUDE\001\e[0m\002 – include Akamai IPs in Split VPN? [y/n]: ' -e -i n AKAMAI_INCLUDE
done
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
tmp_dir=$(mktemp -d)
if curl --retry 3 -fsSL \
     "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xD959241751179EC7" \
     | gpg --dearmor >"$tmp_dir/D959241751179EC7.gpg"; then
  cat "$tmp_dir/D959241751179EC7.gpg" >> /etc/apt/keyrings/cznic-labs-pkg.gpg
fi
rm -rf "$tmp_dir"
chmod 644 /etc/apt/keyrings/cznic-labs-pkg.gpg

echo "deb [signed-by=/etc/apt/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-resolver ${CODENAME} main" \
  > /etc/apt/sources.list.d/cznic-labs-knot-resolver.list

# Добавим репозиторий Debian Backports
if [[ "$OS" == "debian" ]]; then
	echo "deb http://deb.debian.org/debian ${CODENAME}-backports main" > /etc/apt/sources.list.d/backports.list
fi

apt-get update

# Ставим необходимые пакеты
apt-get -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        install --reinstall -y git iptables gawk knot-resolver dns-root-data sipcalc python3 python3-pip \
                              wireguard-tools diffutils socat lua-cqueues ipset at file \
                              libcap2-bin logrotate gettext-base ca-certificates
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
  if curl --retry 3 -fsSL -L \
       "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${yq_arch}" \
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
REPO_TMP="$TMP_DIR/rzans_vpn_main"
git clone https://github.com/RazisID12/RzaNs_VPN_main.git "$REPO_TMP"

# инициализируем накопитель ошибок СРАЗУ,
ERRORS=""

# ── AdGuard Home: УСТАНАВЛИВАЕМ ВСЕГДА, старт откладываем ───────────────
{
  echo
  echo -e '\e[1;36mInstalling AdGuard Home...\e[0m'
  
  AGH_DST="/opt/AdGuardHome"   # целевой каталог, всегда /opt/AdGuardHome

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

  if ! curl --retry 3 -fsSL "$agh_url" -o "$agh_tar"; then
    echo "✗ AdGuard Home download failed" >&2; exit 10
  fi
  if ! echo "${agh_ref_sha}  $agh_tar" | sha256sum -c - --status; then
      echo "✗ AdGuard Home checksum mismatch"; exit 9
  fi
  # Остановим сервис и гарантированно выключим автозапуск; пересоздадим целевой каталог «с нуля»
  systemctl disable --now AdGuardHome.service 2>/dev/null || true
  rm -rf "${AGH_DST}" 2>/dev/null || true
  install -d "${AGH_DST}"

  # Распаковка во временный каталог с последующим переносом содержимого
  AGH_UNPACK="$TMP_DIR/agh_unpack"
  install -d "$AGH_UNPACK"
  tar -xzf "$agh_tar" -C "$AGH_UNPACK"
  if [[ -d "$AGH_UNPACK/AdGuardHome" ]]; then
      AGH_SRC="$AGH_UNPACK/AdGuardHome"
  else
      AGH_SRC="$AGH_UNPACK"
  fi
  # переносим содержимое, безопасно обрабатывая пустой каталог
  shopt -s dotglob nullglob
  files=( "$AGH_SRC"/* )
  if (( ${#files[@]} )); then
      mv "${files[@]}" "${AGH_DST}/"
  fi
  shopt -u dotglob nullglob
  rmdir "$AGH_SRC" 2>/dev/null || true
  # На всякий случай «сплющим» вложенный каталог, если вдруг появился
  if [[ -d "${AGH_DST}/AdGuardHome" ]]; then
      shopt -s dotglob
      mv "${AGH_DST}/AdGuardHome"/* "${AGH_DST}/" 2>/dev/null || true
      shopt -u dotglob
      rmdir "${AGH_DST}/AdGuardHome" 2>/dev/null || true
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

  # ── права и владелец ──────────────────────────────────────────────────────
  ensure_agh_perms

  # финальная проверка на отсутствие вложенного каталога после всех действий
  if [[ -d "${AGH_DST}/AdGuardHome" ]]; then
      shopt -s dotglob
      mv "${AGH_DST}/AdGuardHome"/* "${AGH_DST}/" 2>/dev/null || true
      shopt -u dotglob
      rmdir "${AGH_DST}/AdGuardHome" 2>/dev/null || true
  fi
  
  # ── подготовим лог-файл под Fail2Ban ──────────────────────────
  LOG_DIR="/var/log/adguardhome"
  LOG_FILE="$LOG_DIR/access.log"

  # создаём каталог и файл, если их нет
  mkdir -p "$LOG_DIR"
  touch "$LOG_FILE"

  # права на лог — под пользователя сервиса
  chown adguardhome:adguardhome "$LOG_DIR" "$LOG_FILE"
  chmod 0640 "$LOG_FILE"

  # ── logrotate: ротация access.log (daily / 50 МБ, 7 копий) ────────────────
  LOGROT="/etc/logrotate.d/adguardhome"
  cat >"$LOGROT" <<'EOF'
/var/log/adguardhome/access.log {
    daily
    rotate 7
    size 50M
    compress
    delaycompress
    missingok
    notifempty
    create 0640 adguardhome adguardhome
    postrotate
        systemctl kill -s USR1 AdGuardHome.service 2>/dev/null || true
    endscript
}
EOF
  chmod 644 "$LOGROT"

  echo -e '\e[1;36mLog file prepared for Fail2Ban:\e[0m '"$LOG_FILE"

  echo -e '\e[1;36mAdGuard Home installed; service will be enabled later.\e[0m'
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

    # ── ipset: дамп‑файл + logrotate (daily / 20 МБ, 7 копий) ───────────────
    install -d -m 755 /var/lib/ipset
    : > /var/lib/ipset/ipset-bans.rules
    chmod 0640 /var/lib/ipset/ipset-bans.rules

    IPSET_LOGROT="/etc/logrotate.d/ipset-bans"
    cat >"$IPSET_LOGROT" <<'EOF'
/var/lib/ipset/ipset-bans.rules {
    daily
    rotate 7
    size 20M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 0640 root root
}
EOF

    # ── logrotate: ротация /var/log/fail2ban.log ────────────────────────────
    FB_LOGROT="/etc/logrotate.d/fail2ban"
    cat >"$FB_LOGROT" <<'EOF'
/var/log/fail2ban.log {
    daily
    rotate 7
    size 20M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 0640 root adm
    postrotate
        fail2ban-client flushlogs >/dev/null 2>&1 || true
    endscript
}
EOF
fi

apt-get autoremove -y
apt-get clean

# Клонируем репозиторий и устанавливаем dnslib
DNSLIB_DIR="$TMP_DIR/dnslib"
git clone https://github.com/paulc/dnslib.git "$DNSLIB_DIR"
# Ставим системно; флаг --break-system-packages добавляем только если поддерживается
PIP_BSP=""
python3 -m pip help install 2>/dev/null | grep -q -- '--break-system-packages' && PIP_BSP="--break-system-packages"
python3 -m pip install --force-reinstall --no-deps $PIP_BSP "$DNSLIB_DIR"

# Сохраняем пользовательские настройки и пользовательские обработчики custom*.sh
[[ -d /opt/rzans_vpn_main/config ]] && \
  cp /opt/rzans_vpn_main/config/* "$REPO_TMP"/setup/opt/rzans_vpn_main/config/ 2>/dev/null || true

# Восстанавливаем из бэкапа пользовательские настройки и пользователей WireGuard
shopt -s nullglob
for _b in /opt/backup*.tar.gz; do
  tar -xzf "$_b" &>/dev/null || true
  rm -f "$_b"    &>/dev/null || true
done
shopt -u nullglob
mkdir -p "$REPO_TMP"/setup/etc/wireguard
mkdir -p "$REPO_TMP"/setup/opt/rzans_vpn_main/config
if [[ -d /opt/wireguard ]]; then
   cp /opt/wireguard/* "$REPO_TMP"/setup/etc/wireguard 2>/dev/null || true
   rm -rf --preserve-root /opt/wireguard

fi
if [[ -d /opt/config ]]; then
   cp /opt/config/* "$REPO_TMP"/setup/opt/rzans_vpn_main/config 2>/dev/null || true
   rm -rf --preserve-root /opt/config
fi

# Копируем нужное, удаляем не нужное
find "$REPO_TMP" -name '.gitkeep' -delete
rm -rf --preserve-root /opt/rzans_vpn_main
cp -r "$REPO_TMP"/setup/* /
systemctl daemon-reload

# --- YAML-поток вместо settings.map -----------------------------------
. /opt/rzans_vpn_main/settings/settings.sh
__SET_LOCKED=0
if declare -F _ensure_settings_lock >/dev/null; then
  _ensure_settings_lock || { echo "settings lock busy: another apply is running" >&2; exit 90; }
  __SET_LOCKED=1
fi
_ensure_settings_yaml

# Выбор DNS → имя провайдера
case "$UPSTREAM_DNS" in
  1) DNS_UPSTREAM=cloudflare ;;
  2) DNS_UPSTREAM=quad9      ;;
  3) DNS_UPSTREAM=google     ;;
esac

# Ответы мастера → settings.yaml
yaml_set dns.upstream            "$DNS_UPSTREAM"
yaml_set adguard_home.enable     "$([[ $ADGUARD_HOME   == y ]] && echo true || echo false)"
yaml_set fail2ban.enable         "$([[ $SSH_PROTECTION == y ]] && echo true || echo false)"
if [[ -n "$SERVER_HOST" ]]; then
  yaml_set server.domain "$SERVER_HOST"
else
  yaml_set server.domain auto
fi
yaml_set routing.route_all         "$([[ $ROUTE_ALL            == y ]] && echo true || echo false)"
yaml_set routing.flags.discord     "$([[ $DISCORD_INCLUDE      == y ]] && echo true || echo false)"
yaml_set routing.flags.cloudflare  "$([[ $CLOUDFLARE_INCLUDE   == y ]] && echo true || echo false)"
yaml_set routing.flags.amazon      "$([[ $AMAZON_INCLUDE       == y ]] && echo true || echo false)"
yaml_set routing.flags.hetzner     "$([[ $HETZNER_INCLUDE      == y ]] && echo true || echo false)"
yaml_set routing.flags.digitalocean "$([[ $DIGITALOCEAN_INCLUDE == y ]] && echo true || echo false)"
yaml_set routing.flags.ovh         "$([[ $OVH_INCLUDE          == y ]] && echo true || echo false)"
yaml_set routing.flags.telegram    "$([[ $TELEGRAM_INCLUDE     == y ]] && echo true || echo false)"
yaml_set routing.flags.google      "$([[ $GOOGLE_INCLUDE       == y ]] && echo true || echo false)"
yaml_set routing.flags.akamai      "$([[ $AKAMAI_INCLUDE       == y ]] && echo true || echo false)"

# освобождаем лок, если брали
if [[ $__SET_LOCKED -eq 1 ]] && declare -F _release_settings_lock >/dev/null; then
  _release_settings_lock || true
fi

# Приватность файла настроек
chown root:root /opt/rzans_vpn_main/settings.yaml 2>/dev/null || true
chmod 600 /opt/rzans_vpn_main/settings.yaml

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

# Загружаем и создаем списки исключений IP‑адресов
# Обновление баз (doall → update) в режиме **install**
#   • INSTALL_STAGE=1 —> update.sh пропускает apt‑upgrade,
#     AGH/F2B апгрейды и dump ipset‑банов.
#   • NO_REBOOT=1     —> даже если ядро обновилось, ребута не будет.
export INSTALL_STAGE=1
export NO_REBOOT=1
/opt/rzans_vpn_main/doall.sh ip
unset INSTALL_STAGE NO_REBOOT

echo -e '\n\033[1;36mGenerating first-boot configs (bootstrap)…\033[0m'
SET_SH=/opt/rzans_vpn_main/settings/settings.sh
# Генерация БЕЗ рестартов: используем CLI settings.sh, передаём BOOTSTRAP=1 там, где нужно
"$SET_SH" --bootstrap            || true   # kresd_upstream + agh_heal + косметика (BOOTSTRAP=1 внутри)
"$SET_SH" --autofill             || true   # .dns.ipv4/.dns.ipv6/.dns.dot и версии
BOOTSTRAP=1 "$SET_SH" --apply-upstream || true
BOOTSTRAP=1 "$SET_SH" --apply-services || true

# выровняем права, если файлы появились
if [[ -f /etc/knot-resolver/upstream_dns.lua ]]; then
  chown knot-resolver:knot-resolver /etc/knot-resolver/upstream_dns.lua || true
  chmod 0644 /etc/knot-resolver/upstream_dns.lua || true
fi
ensure_agh_perms

# sanity-check: подсветим, если что-то не сгенерилось
if [[ ! -s /etc/knot-resolver/upstream_dns.lua ]]; then
  ERRORS+=$'\nMissing /etc/knot-resolver/upstream_dns.lua after apply-upstream'
fi
if [[ "$ADGUARD_HOME" == y && ! -s /opt/AdGuardHome/AdGuardHome.yaml ]]; then
  ERRORS+=$'\nMissing /opt/AdGuardHome/AdGuardHome.yaml after apply-services'
fi

# теперь перерегистрируем юниты и включаем всё после генерации конфигов
systemctl daemon-reload
enable_if_present() { systemctl cat "$1" &>/dev/null && systemctl enable "$1" || true; }
enable_if_present init.service
enable_if_present core.service
enable_if_present apply.path
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
    chmod 600 "$SWAPFILE"
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

# ── снять EXIT-trap и подчистить TMP_DIR вручную ────────────────────────────
trap - EXIT
cleanup_tmp

reboot
