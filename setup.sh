#!/bin/bash
# ==============================================================================
# Скрипт для установки на своём сервере RzaNs_VPN_main
# ==============================================================================
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 027 
export LC_ALL=C
set -euo pipefail

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

# Проверка на OpenVZ и LXC
if [[ "$(systemd-detect-virt)" == "openvz" || "$(systemd-detect-virt)" == "lxc" ]]; then
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
	read -rp 'Enable SSH brute-force protection? [y/n]: ' -e -i y SSH_PROTECTION
done

echo
while true; do
  read -rp 'Enter valid domain name for this AmneziaWG server or press Enter to skip: ' -e WIREGUARD_HOST
  [[ -z $WIREGUARD_HOST ]] && break
  readarray -t _ip_test < <(getent ahostsv4 "$WIREGUARD_HOST") || true
  [[ ${#_ip_test[@]} -gt 0 ]] && break
done
unset _ip_test
echo
until [[ "$ROUTE_ALL" =~ (y|n) ]]; do
	read -rp $'Route all traffic for domains via \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002, excluding Russian domains and domains from exclude-hosts.txt? [y/n]: ' -e -i n ROUTE_ALL
done
echo
until [[ "$DISCORD_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Discord voice IPs in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002? [y/n]: ' -e -i y DISCORD_INCLUDE
done
echo
until [[ "$CLOUDFLARE_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Cloudflare IPs in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002? [y/n]: ' -e -i y CLOUDFLARE_INCLUDE
done
echo
until [[ "$AMAZON_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Amazon IPs in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002? [y/n]: ' -e -i n AMAZON_INCLUDE
done
echo
until [[ "$HETZNER_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Hetzner IPs in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002? [y/n]: ' -e -i n HETZNER_INCLUDE
done
echo
until [[ "$DIGITALOCEAN_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include DigitalOcean IPs in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002? [y/n]: ' -e -i n DIGITALOCEAN_INCLUDE
done
echo
until [[ "$OVH_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include OVH IPs in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002? [y/n]: ' -e -i n OVH_INCLUDE
done
echo
until [[ "$TELEGRAM_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Telegram IPs in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002? [y/n]: ' -e -i n TELEGRAM_INCLUDE
done
echo
until [[ "$GOOGLE_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Google IPs in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002? [y/n]: ' -e -i n GOOGLE_INCLUDE
done
echo
until [[ "$AKAMAI_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Akamai IPs in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002? [y/n]: ' -e -i n AKAMAI_INCLUDE
done
echo
echo 'Preparing for installation, please wait...'
set -u   # ◄ возвращаем строгий режим после всех read/until

# Ожидание, пока пакетный менеджер не освободит lock (если есть pidof)
if command -v pidof &>/dev/null; then
# ждём максимум 5 мин (300 с), пока не освободятся apt-get / dpkg …
lock_t0=$(date +%s)
while pidof apt-get dpkg unattended-upgrade apt.systemd.daily apt.systemd.daily-update &>/dev/null; do
  [[ $(( $(date +%s) - lock_t0 )) -ge 300 ]] && {
      echo '✗ APT lock is still held after 5 min — aborting.' >&2
      exit 12
  }
  echo 'Waiting for package manager to finish…'
  sleep 5
done
fi

# Отключим фоновые обновления системы
systemctl stop unattended-upgrades        &>/dev/null || true
systemctl stop apt-daily.timer            &>/dev/null || true
systemctl stop apt-daily-upgrade.timer    &>/dev/null || true

# Удаление или перемещение файлов и папок при обновлении
systemctl stop dnsmap  &>/dev/null || true
systemctl disable dnsmap &>/dev/null || true
systemctl stop ferm    &>/dev/null || true
systemctl disable ferm &>/dev/null || true

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
rm -f /opt/*.conf
rm -rf --preserve-root /opt/vpn
rm -rf --preserve-root /opt/easy-rsa-ipsec
rm -rf --preserve-root /opt/.gnupg
rm -rf --preserve-root /opt/dnsmap

apt-get purge -y python3-dnslib &>/dev/null || true
apt-get purge -y gnupg2           &>/dev/null || true
apt-get purge -y ferm             &>/dev/null || true
apt-get purge -y libpam0g-dev     &>/dev/null || true
apt-get purge -y sshguard         &>/dev/null || true

# Остановим и выключим обновляемые службы
for service in kresd@ wg-quick@; do
	systemctl list-units --type=service --no-pager | awk -v s="$service" '$1 ~ s"[^.]+\\.service" {print $1}' | xargs -r systemctl stop &>/dev/null
	systemctl list-unit-files --type=service --no-pager | awk -v s="$service" '$1 ~ s"[^.]+\\.service" {print $1}' | xargs -r systemctl disable &>/dev/null
done

# останавливаем/отключаем только актуальные юниты
systemctl stop    core              dwnld_update dwnld_update.timer           &>/dev/null || true
systemctl disable core              dwnld_update dwnld_update.timer           &>/dev/null || true

# Остановим и выключим ненужные службы
systemctl stop firewalld    &>/dev/null || true
command -v ufw &>/dev/null && ufw disable &>/dev/null || true

systemctl disable firewalld &>/dev/null || true
command -v ufw &>/dev/null && systemctl disable ufw &>/dev/null || true

# Удаляем старые файлы и кеш Knot Resolver
rm -rf "/var/cache/knot-resolver/"*
rm -rf "/etc/knot-resolver/"*
rm -rf "/var/lib/knot-resolver/"*

# Удаляем старые файлы AmneziaWG
#rm -rf /etc/wireguard/templates/*

# Обновляем систему
apt-get clean
apt-get update
apt-get dist-upgrade -y
apt-get install --reinstall -y curl gpg

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
apt-get install --reinstall -y git iptables gawk knot-resolver idn sipcalc python3-pip \
                              wireguard-tools diffutils socat lua-cqueues ipset

# ── yq v4 (mikefarah) — нужен для корректного YAML‑merge в agh_heal ──────────
#  `yq --version` → «yq (…github…) version 4.44.2», поэтому ищем «version 4».
if ! command -v yq >/dev/null 2>&1 \
   || ! yq --version 2>/dev/null | grep -Eq 'version[[:space:]]+4(\.|$)'; then
  echo 'Installing yq v4…'
  case "$(uname -m)" in
    x86_64|amd64)   yq_arch=amd64 ;;
    aarch64|arm64)  yq_arch=arm64 ;;
    armv7l)         yq_arch=arm   ;;
    armv6l)         yq_arch=arm   ;;
    i386|i686)      yq_arch=386   ;;
    *)              yq_arch=amd64 ;;
  esac
  curl --retry 3 -fsSL \
    "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${yq_arch}" \
    -o /usr/local/bin/yq
  chmod 0755 /usr/local/bin/yq
fi

# ── systemd drop‑in: AdGuard Home стартует ТОЛЬКО после WG и kresd ───────────
AGH_DROPIN="/etc/systemd/system/AdGuardHome.service.d/10-rzans-deps.conf"
install -d "$(dirname "$AGH_DROPIN")"
cat >"$AGH_DROPIN" <<'EOF'
[Unit]
After=network-online.target wg-quick@rzans_svpn_main.service wg-quick@rzans_fvpn_main.service \
      kresd@1.service kresd@2.service
Wants=network-online.target wg-quick@rzans_svpn_main.service wg-quick@rzans_fvpn_main.service
EOF
systemctl daemon-reload

# ==== единственное клонирование репозитория =====
REPO_TMP="$TMP_DIR/rzans_vpn_main"
git clone https://github.com/RazisID12/RzaNs_VPN_main.git "$REPO_TMP"

# инициализируем накопитель ошибок СРАЗУ,
ERRORS=""

# ── AdGuard Home: УСТАНАВЛИВАЕМ ВСЕГДА, старт откладываем ───────────────
{
  echo
  echo -e '\e[1;36mInstalling AdGuard Home...\e[0m'
  
  mkdir -p /opt/AdGuardHome
  cd /opt/AdGuardHome || exit 8

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
  # на всякий случай остановим сервис до замены файлов (если он есть)
  systemctl stop AdGuardHome 2>/dev/null || true
  # Полностью очищаем рабочий каталог и распаковываем архив
  rm -rf /opt/AdGuardHome/* 2>/dev/null || true
  tar -xzf "$agh_tar" --strip-components=1 -C /opt/AdGuardHome

  # После strip-components ожидаем файл /opt/AdGuardHome/AdGuardHome.
  # Если архив внезапно содержит вложенную директорию, обработаем и её.
  if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
      if [[ -d /opt/AdGuardHome/AdGuardHome ]]; then
          # структура: /opt/AdGuardHome/AdGuardHome/AdGuardHome (файл)
          AGH_BIN="/opt/AdGuardHome/AdGuardHome/AdGuardHome"
      else
          # структура: /opt/AdGuardHome/AdGuardHome (файл)
          AGH_BIN="/opt/AdGuardHome/AdGuardHome"
      fi
  else
      # fallback: ищем бинарник вручную
      AGH_BIN="$(find /opt/AdGuardHome -maxdepth 3 -type f -name AdGuardHome -perm -111 | head -n1)"
  fi
  if [[ -z "${AGH_BIN:-}" || ! -x "$AGH_BIN" ]]; then
      echo "✗ AdGuard Home binary not found after extract"; exit 12
  fi

  # Если сервис уже установлен (unit-файл существует) — только обновляем бинарник и перезапускаем
  if systemctl list-unit-files | grep -qiE '^(AdGuardHome|adguardhome)\.service' \
        || [[ -f /etc/systemd/system/AdGuardHome.service ]] \
        || [[ -f /etc/systemd/system/adguardhome.service ]]; then
      echo "AdGuard Home service already exists — updating binary (start deferred)."
      systemctl stop AdGuardHome 2>/dev/null || true
      chown -R adguardhome:adguardhome /opt/AdGuardHome 2>/dev/null || true
      systemctl daemon-reload
  else
      "$AGH_BIN" -s install
      systemctl daemon-reload
      # после установки удостоверимся, что у каталога корректный владелец
      if id adguardhome &>/dev/null; then
        chown -R adguardhome:adguardhome /opt/AdGuardHome 2>/dev/null || true
      fi
  fi
  
  # ── подготовим лог-файл под Fail2Ban ──────────────────────────
  LOG_DIR="/var/log/adguardhome"
  LOG_FILE="$LOG_DIR/access.log"

  # создаём каталог и файл, если их нет
  mkdir -p "$LOG_DIR"
  touch "$LOG_FILE"

  # если система уже добавила пользователя adguardhome – дадим ему права
  if id "adguardhome" &>/dev/null; then
    chown adguardhome:adguardhome "$LOG_DIR" "$LOG_FILE"
  fi

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
    copytruncate
    create 0640 adguardhome adguardhome
    postrotate
        systemctl kill -s USR1 AdGuardHome 2>/dev/null || true
    endscript
}
EOF
  chmod 644 "$LOGROT"

  echo -e '\e[1;36mLog file prepared for Fail2Ban:\e[0m '"$LOG_FILE"

  echo -e '\e[1;36mAdGuard Home installed; service is disabled by default.\e[0m'
  systemctl disable --now AdGuardHome 2>/dev/null || true
} || { echo "✗ AdGuard Home installation failed"; exit 12; }

# ── Fail2Ban: УСТАНАВЛИВАЕМ ВСЕГДА, включаем по флагу ───────────────────
if ! apt-get install -y fail2ban; then
    ERRORS+="\nFail2ban installation failed"
else
    # гасим, если автозапустился после установки
    systemctl stop fail2ban 2>/dev/null || true
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
    systemctl disable --now fail2ban 2>/dev/null || true

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

# ВКЛЮЧЕНИЕ/ВЫКЛЮЧЕНИЕ сервисов по флагам пользователя
if [[ "$SSH_PROTECTION" == "y" ]]; then
    systemctl enable --now fail2ban 2>/dev/null || true
    systemctl restart       fail2ban 2>/dev/null || true
else
    systemctl disable --now fail2ban 2>/dev/null || true
fi

apt-get autoremove -y
apt-get clean

# Клонируем репозиторий и устанавливаем dnslib
DNSLIB_DIR="$TMP_DIR/dnslib"
git clone https://github.com/paulc/dnslib.git "$DNSLIB_DIR"
# Убедимся, что pip поддерживает --break-system-packages (pip ≥ 23)
if ! python3 - <<'PY' 2>/dev/null | grep -q true
import sys, pip, re
print('true' if re.search(r'break-system-packages', pip.__doc__ or '') else 'false')
PY
then
  python3 -m pip install -U pip
fi
# Ставим системно: Python гарантированно найдёт пакет при запуске от root
python3 -m pip install --force-reinstall --no-deps --break-system-packages "$DNSLIB_DIR"

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
OLD_SETTINGS_TMP=""
if [[ -f /opt/rzans_vpn_main/settings.map ]]; then
  OLD_SETTINGS_TMP="$TMP_DIR/old_settings.map"
  cp /opt/rzans_vpn_main/settings.map "$OLD_SETTINGS_TMP"
fi
rm -rf --preserve-root /opt/rzans_vpn_main
cp -r "$REPO_TMP"/setup/* /

. /opt/rzans_vpn_main/settings.sh
if [[ -f "$OLD_SETTINGS_TMP" ]]; then
  mv "$OLD_SETTINGS_TMP" /opt/rzans_vpn_main/settings.map
fi
settings_heal   # создаёт или обновляет файл, подтягивает нижние теги

# перезаписываем верхние теги значениями из install-wizard
_set_tag() {
  local tag="$1" val="$2"

  # если значение пустое — ничего не записываем (напр. пустой WIREGUARD_HOST)
  [[ -z $val ]] && return

  if [[ "$tag" == "WIREGUARD_HOST" ]]; then
    # экранируем возможные двойные кавычки в значении
    val="${val//\"/\\\"}"
    val="\"$val\""
  fi
  # экранируем / & | \
  local val_esc
  val_esc=$(printf '%s' "$val" | sed -e 's/[\/&|\\]/\\&/g')
  if grep -q -E "^[[:space:]]*$tag[[:space:]]" "$SETTINGS"; then
    sed -i -E "s|^[[:space:]]*$tag[[:space:]]+.*$|$(printf '%-22s %s' "$tag" "$val_esc")|" "$SETTINGS"
  else
    # при первом добавлении пишем НЕэкранированное значение
    printf '%-22s %s\n' "$tag" "$val" >>"$SETTINGS"
  fi
}
for t in UPSTREAM_DNS ADGUARD_HOME \
         SSH_PROTECTION WIREGUARD_HOST ROUTE_ALL DISCORD_INCLUDE CLOUDFLARE_INCLUDE \
         AMAZON_INCLUDE HETZNER_INCLUDE DIGITALOCEAN_INCLUDE OVH_INCLUDE \
         TELEGRAM_INCLUDE GOOGLE_INCLUDE AKAMAI_INCLUDE; do
  _set_tag "$t" "${!t}"
done

# ── общий апстрим для kresd + systemd‑resolved + /etc/network/interfaces ──
case "$UPSTREAM_DNS" in
  1) DNS4_1=1.1.1.1  ; DNS4_2=1.0.0.1  ; DNS6_1=2606:4700:4700::1111 ; DNS6_2=2606:4700:4700::1001 ;;
  2) DNS4_1=9.9.9.10 ; DNS4_2=149.112.112.10 ; DNS6_1=2620:fe::10      ; DNS6_2=2620:fe::fe:10 ;;
  3) DNS4_1=8.8.8.8  ; DNS4_2=8.8.4.4  ; DNS6_1=2001:4860:4860::8888 ; DNS6_2=2001:4860:4860::8844 ;;
esac

# ── Проверка доступности IPv6: выключен ли стек и есть ли default‑маршрут ──
if [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" == "1" ]]; then
  IPV6_AVAILABLE=n
else
  if ip -6 route show default 2>/dev/null | grep -q .; then
    IPV6_AVAILABLE=y
  else
    IPV6_AVAILABLE=n
  fi
fi

# 1. upstream list for kresd (common)
install -d -o knot-resolver -g knot-resolver /etc/knot-resolver
cat >/etc/knot-resolver/upstream_dns.lua <<EOF
return { up = {'${DNS4_1}','${DNS4_2}'} }
EOF

# 2. systemd-resolved – IPv4 + (опционально) IPv6 в одной строке DNS=
RESCONF=/etc/systemd/resolved.conf
# секция [Resolve] должна существовать
grep -q '^\[Resolve\]' "$RESCONF" || echo '[Resolve]' >>"$RESCONF"
# удаляем ТОЛЬКО строки DNS= (FallbackDNS и прочие параметры не трогаем)
sed -i -E '/^[[:space:]]*DNS=/d' "$RESCONF"
# формируем итоговую строку: IPv4 всегда, IPv6 добавляем только при доступном стеке
DNS_LINE="DNS=${DNS4_1} ${DNS4_2}"
[[ "$IPV6_AVAILABLE" == "y" ]] && DNS_LINE+=" ${DNS6_1} ${DNS6_2}"
# вставляем строку сразу после [Resolve]
sed -i "/^\[Resolve\]/a ${DNS_LINE}" "$RESCONF"

# 3. /etc/network/interfaces – правим v4 всегда; v6 — только при наличии IPv6
if [[ -f /etc/network/interfaces ]]; then
  if [[ "$IPV6_AVAILABLE" == "y" ]]; then
    awk -v v4="dns-nameservers ${DNS4_1} ${DNS4_2}" \
        -v v6="dns-nameservers ${DNS6_1} ${DNS6_2}" '
      function flush(){if(sec=="v4"&&!dns)print "    "v4; if(sec=="v6"&&!dns)print "    "v6; sec=""; dns=0}
      /^[[:space:]]*iface .* inet6 static/{flush();sec="v6";dns=0;print;next}
      /^[[:space:]]*iface .* inet static/{flush();sec="v4";dns=0;print;next}
      sec!="" && /^[[:space:]]*dns-nameservers/{dns=1; if(sec=="v4")print "    "v4; else print "    "v6; next}
      {print}
      END{flush()}
    ' /etc/network/interfaces >"$TMP_DIR/intf.new" && mv "$TMP_DIR/intf.new" /etc/network/interfaces
  else
    awk -v v4="dns-nameservers ${DNS4_1} ${DNS4_2}" '
      function flush(){if(sec=="v4"&&!dns)print "    "v4; sec=""; dns=0}
      /^[[:space:]]*iface .* inet static/{flush();sec="v4";dns=0;print;next}
      sec!="" && /^[[:space:]]*dns-nameservers/{dns=1; print "    "v4; next}
      {print}
      END{flush()}
    ' /etc/network/interfaces >"$TMP_DIR/intf.new" && mv "$TMP_DIR/intf.new" /etc/network/interfaces
  fi
fi
echo "✓ kresd и resolved.conf обновлены на ${DNS4_1}/${DNS4_2}"

# ── фиксируем начальные комментарии версий AGH и Fail2Ban ──────────────
#   • при установке они ещё не записаны;
#   • update.sh потом будет менять их ТОЛЬКО при апгрейдах.

# AdGuard Home
if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
  AGH_VER=$(/opt/AdGuardHome/AdGuardHome -v 2>&1 \
            | sed -n 's/.*version[[:space:]]\+//p' || true)
  if [[ -n $AGH_VER ]]; then
    settings_set_agh_comment "$AGH_VER" "$(date +%d.%m.%Y)"
  else
    echo "[WARN] cannot detect AGH version"
  fi
fi

# Fail2Ban
if dpkg -s fail2ban &>/dev/null; then
  F2B_VER=$(dpkg -s fail2ban 2>/dev/null | awk '/^Version:/{print $2}')
  if [[ -n $F2B_VER ]]; then
    settings_set_ssh_comment "$F2B_VER" "$(date +%d.%m.%Y)"
  else
    echo "[WARN] cannot detect Fail2Ban version"
  fi
fi

echo "✓ settings.map updated (settings_heal + wizard overrides)"

# финальное выравнивание — после всех изменений settings.map
settings_pretty

# --- Права для Knot Resolver и RPZ-файлов -------------------------------
# каталоги (после того как мы всё подчистили выше)
install -d -o knot-resolver -g knot-resolver -m 755 /etc/knot-resolver
install -d -o knot-resolver -g knot-resolver -m 755 /var/lib/knot-resolver

# если RPZ уже существуют — привести права к норме
chown knot-resolver:knot-resolver /etc/knot-resolver/*.rpz 2>/dev/null || true
chmod 644 /etc/knot-resolver/*.rpz 2>/dev/null || true

# ── единый блок прав на ВСЁ содержимое
find /opt/rzans_vpn_main -type d -exec chmod 755 {} +
find /opt/rzans_vpn_main -type f -exec chmod 644 {} +
find /opt/rzans_vpn_main -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod +x {} +
# settings.map должен быть приватным
chmod 600 /opt/rzans_vpn_main/settings.map 2>/dev/null || true

# ── DNS‑строки в клиентских шаблонах: брать адреса из settings.map ───────────
#  • Split‑VPN → DNS = <первый хост из SVPN_NET4>
#  • Full‑VPN  → DNS = <первый хост из FVPN_NET4>
#    (адреса одинаковы при AGH ON и AGH OFF; апстримы задаются в kresd)
SVPN_NET4="$(settings_get_tag SVPN_NET4 "10.29.8.0/24")"
FVPN_NET4="$(settings_get_tag FVPN_NET4 "10.28.8.0/24")"
vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" || {
    echo "⚠️  не удалось вычислить адреса из CIDR, использую дефолт" >&2
    SVPN_IP=${SVPN_IP:-10.29.8.1}
    FVPN_IP=${FVPN_IP:-10.28.8.1}
}

shopt -s nullglob
# FullVPN шаблон(ы)
for f in /etc/wireguard/templates/rzans_fvpn_main.conf; do
  if grep -q -E '^[[:space:]]*DNS[[:space:]]*=' "$f"; then
    sed -i -E "s/^[[:space:]]*DNS[[:space:]]*=.*/DNS = ${FVPN_IP}/" "$f"
  else
    sed -i "/^\[Interface\]/a DNS = ${FVPN_IP}" "$f"
  fi
done
# SplitVPN шаблон(ы)
for f in /etc/wireguard/templates/rzans_svpn_main.conf; do
  if grep -q -E '^[[:space:]]*DNS[[:space:]]*=' "$f"; then
    sed -i -E "s/^[[:space:]]*DNS[[:space:]]*=.*/DNS = ${SVPN_IP}/" "$f"
  else
    sed -i "/^\[Interface\]/a DNS = ${SVPN_IP}" "$f"
  fi
done
shopt -u nullglob

# Загружаем и создаем списки исключений IP-адресов
/opt/rzans_vpn_main/doall.sh ip

# гарантируем, что каталоги уже существуют
mkdir -p /etc/wireguard \
         /opt/rzans_vpn_main/client/{rzans_svpn_main,rzans_fvpn_main}

# Настраиваем сервер AmneziaWG для первого запуска, пересоздаём профили (если ключей/клиентов ещё нет — client.sh создаст их)
/opt/rzans_vpn_main/client.sh 4

# ── Включим сервисы и таймеры ────────────────────────────────────────────────
systemctl daemon-reload

# kresd-инстансы и wg
for u in kresd@1 kresd@2 wg-quick@rzans_svpn_main wg-quick@rzans_fvpn_main; do
  systemctl enable "$u" 2>/dev/null || true
done

# ── core‑прокси и таймер обновлений ────────────────────────────────
systemctl enable core.service               2>/dev/null || true
systemctl enable dwnld_update.service       2>/dev/null || true
systemctl enable dwnld_update.timer         2>/dev/null || true

# ── path‑юнит, который запускает settings.sh при изменениях ────────
systemctl enable --now settings.path        2>/dev/null || true

# ── Генерация конфигурации AdGuard Home и отложенный старт ───────────────────
echo -e '\e[1;36mGenerating AdGuard Home config (AdGuardHome.yaml)…\e[0m'
agh_heal || true

if [[ "${ADGUARD_HOME:-n}" == "y" ]]; then
  # Включаем сервис. Запускать прямо сейчас будем только если интерфейсы уже подняты.
  systemctl enable AdGuardHome 2>/dev/null || true
  # проверяем, что на адресах уже можно биндинг сделать (есть хотя бы один из IP)
  if ip -o addr show | awk '{print $4}' | grep -qE "^${SVPN_IP}/|^${FVPN_IP}/"; then
    systemctl restart AdGuardHome 2>/dev/null || true
  else
    echo "AGH start deferred: WG interfaces not up yet; will start after reboot."
  fi
else
  systemctl disable --now AdGuardHome 2>/dev/null || true
fi

# Настроим swap (512 МБ):
#  • если swap не активирован, но файл уже есть → попробуем активировать;
#  • если файла нет → создадим и активируем.
if [[ -z "$(swapon --show)" ]]; then
  SWAPFILE="/swapfile"
  SWAPSIZE=512
  if [[ -f $SWAPFILE ]]; then            # файл уже существует —- пробуем просто включить
    chmod 600 "$SWAPFILE"
    mkswap "$SWAPFILE"      2>/dev/null
  else                                   # файла нет —- создаём
    if command -v fallocate &>/dev/null; then
      fallocate -l "${SWAPSIZE}M" "$SWAPFILE" 2>/dev/null
    else
      dd if=/dev/zero of="$SWAPFILE" bs=1M count="$SWAPSIZE" status=none
    fi
    if [[ $? -ne 0 ]]; then
      ERRORS+="\nSwap creation failed (disk space insufficient?)"
    fi
  fi
  if [[ -s $SWAPFILE ]]; then            # файл существует и ненулевой
    chmod 600 "$SWAPFILE"
    mkswap "$SWAPFILE"
    swapon "$SWAPFILE"
    grep -q "^$SWAPFILE " /etc/fstab || echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  fi
fi

# выводим накопленные ошибки (красным)
if [[ -n "$ERRORS" ]]; then
  echo -e "\e[1;31m$ERRORS\e[0m"
fi

echo
echo -e '\e[1;32mRzaNs_VPN_main installed successfully!\e[0m'
echo 'Rebooting in 5 seconds… (Ctrl-C to cancel)'

# ── снять EXIT‑trap и подчистить TMP_DIR вручную, чтобы
#    avoid “device or resource busy” warnings перед ребутом ───────────────
trap - EXIT
cleanup_tmp

sleep 5
reboot
