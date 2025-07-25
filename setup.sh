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
  # не ругаемся, если переменные пусты
  [[ -n ${TMP_FILE:-} ]] && rm -f "$TMP_FILE" 2>/dev/null || true
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
set +u   # ► разрешаем обращаться к пока не-инициализированным переменным
echo
echo -e 'Choose DNS resolvers for \e[1;32mRzaNs_sVPN_main\e[0m (RzaNs_sVPN_main-*):'
echo '    1) Cloudflare+Quad9  - Recommended by default'
echo '       +Russian *'
echo '    2) Cloudflare+Quad9  - Use if default choice fails to resolve domains'
echo '    3) Comss **          - More details: https://comss.ru/disqus/page.php?id=7315'
echo '    4) Xbox **           - More details: https://xbox-dns.ru'
echo '    5) Malw **           - More details: https://info.dns.malw.link'
echo
echo '  * - Resolvers optimized for users in Russia'
echo ' ** - Enable additional proxying and hide this server IP on some internet resources'
echo '      Use only if this server is geolocated in Russia or problems accessing some internet resources'
until [[ "$RZANS_SVPN_MAIN_DNS" =~ ^[1-5]$ ]]; do
	read -rp 'DNS choice [1-5]: ' -e -i 1 RZANS_SVPN_MAIN_DNS
done
echo
echo -e 'Choose DNS resolvers for \e[1;32mRzaNs_fVPN_main\e[0m (RzaNs_fVPN_main-*):'
echo '    1) Cloudflare  - Recommended by default'
echo '    2) Quad9       - Use if Cloudflare fails to resolve domains'
echo '    3) Google *    - Use if Cloudflare/Quad9 fails to resolve domains'
echo '    4) AdGuard *   - Use for blocking ads, trackers, malware and phishing websites'
echo '    5) Comss **    - More details: https://comss.ru/disqus/page.php?id=7315'
echo '    6) Xbox **     - More details: https://xbox-dns.ru'
echo '    7) Malw **     - More details: https://info.dns.malw.link'
echo
echo '  * - Resolvers supports EDNS Client Subnet'
echo ' ** - Enable additional proxying and hide this server IP on some internet resources'
echo '      Use only if this server is geolocated in Russia or problems accessing some internet resources'
until [[ "$RZANS_FVPN_MAIN_DNS" =~ ^[1-7]$ ]]; do
	read -rp 'DNS choice [1-7]: ' -e -i 1 RZANS_FVPN_MAIN_DNS
done
echo
until [[ "$BLOCK_ADS" =~ (y|n) ]]; do
	read -rp $'Enable blocking ads, trackers, malware and phishing websites in \001\e[1;32m\002RzaNs_sVPN_main\001\e[0m\002 (RzaNs_sVPN_main-*) based on AdGuard and OISD rules? [y/n]: ' -e -i y BLOCK_ADS
done

if [[ "$BLOCK_ADS" == "n" ]]; then
  echo
  until [[ "$ADGUARD_HOME" =~ (y|n) ]]; do
    read -rp $'Would you like to install \001\e[1;36m\002AdGuard Home\001\e[0m\002 as a DNS-level ad blocker? [y/n]: ' -e -i n ADGUARD_HOME
  done
else
  ADGUARD_HOME="n"
fi

#-- гарантируем, что переменная существует даже если вопрос про AGH пропустили
: "${ADGUARD_HOME:=n}"

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

systemctl stop    rzans_vpn_main              &>/dev/null || true
systemctl disable rzans_vpn_main              &>/dev/null || true
systemctl stop    rzans_vpn_main-update       &>/dev/null || true
systemctl disable rzans_vpn_main-update       &>/dev/null || true
systemctl stop    rzans_vpn_main-update.timer &>/dev/null || true
systemctl disable rzans_vpn_main-update.timer &>/dev/null || true

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
install -d /etc/apt/keyrings
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

# ==== единственное клонирование репозитория =====
REPO_TMP="$TMP_DIR/rzans_vpn_main"
git clone https://github.com/RazisID12/RzaNs_VPN_main.git "$REPO_TMP"

# инициализируем накопитель ошибок СРАЗУ,
ERRORS=""

# Установка AdGuard Home (если выбрано)
if [[ "${ADGUARD_HOME:-n}" == "y" ]]; then
  echo
  echo -e '\e[1;36mInstalling AdGuard Home...\e[0m'
  
  mkdir -p /opt/AdGuardHome
  cd /opt/AdGuardHome || exit 8

  # универсальная загрузка с SHA256
  agh_base="https://static.adtidy.org/adguardhome/release"
  agh_file="AdGuardHome_linux_amd64.tar.gz"
  agh_url="${agh_base}/${agh_file}"
  agh_tar="$TMP_DIR/${agh_file}"

  # Получаем контрольную сумму из checksums.txt
  curl --retry 3 -fsSL "${agh_base}/checksums.txt" \
      | grep "  ./${agh_file}$" > "$TMP_DIR/checksum.txt"
  read agh_ref_sha _ < "$TMP_DIR/checksum.txt" || { echo "✗ Cannot parse checksum"; exit 11; }

  if ! curl --retry 3 -fsSL "$agh_url" -o "$agh_tar"; then
      echo "✗ AdGuard Home download failed" >&2; exit 10
  fi
  if ! echo "${agh_ref_sha}  $agh_tar" | sha256sum -c - --status; then
      echo "✗ AdGuard Home checksum mismatch"; exit 9
  fi
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
  if systemctl list-unit-files | grep -qi '^AdGuardHome\.service' \
        || [[ -f /etc/systemd/system/AdGuardHome.service ]] \
        || [[ -f /etc/systemd/system/adguardhome.service ]]; then
      echo "AdGuard Home service already exists — updating binary and restarting."
      systemctl stop AdGuardHome 2>/dev/null || true
      chown -R adguardhome:adguardhome /opt/AdGuardHome 2>/dev/null || true
      systemctl daemon-reload
      systemctl start AdGuardHome 2>/dev/null || "$AGH_BIN" -s start
  else
      "$AGH_BIN" -s install
      "$AGH_BIN" -s start
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

  echo -e '\e[1;36mLog file prepared for Fail2Ban:\e[0m '"$LOG_FILE"

  echo -e '\e[1;36mAdGuard Home installed and running.\e[0m'
fi

# Защита SSH — по желанию + интеграция с AdGuard Home
if [[ "$SSH_PROTECTION" == "y" ]]; then
  # 2) ставим Fail2Ban и настраиваем
  if ! apt-get install -y fail2ban; then
      ERRORS+="\nFail2ban installation failed"
  else
      JLOCAL="$REPO_TMP/setup/etc/fail2ban/jail.local"
      JRECID="$REPO_TMP/setup/etc/fail2ban/jail.d/recidive.conf"
      JADGU="$REPO_TMP/setup/etc/fail2ban/jail.d/adguard-panel.conf"
      ACT_IP="$REPO_TMP/setup/etc/fail2ban/action.d/ipset-block.conf"
      FLT_AG="$REPO_TMP/setup/etc/fail2ban/filter.d/adguard-home-auth.conf"

      # каталоги
      install -d /etc/fail2ban/{action.d,filter.d,jail.d}

      # базовый jail.local
      cp "$JLOCAL"  /etc/fail2ban/jail.local     || ERRORS+=$'\nMissing jail.local'

      # recidive ‒ всегда
      cp "$JRECID"  /etc/fail2ban/jail.d/recidive.conf \
        || ERRORS+=$'\nMissing recidive.conf'

      # ipset-action
      cp "$ACT_IP"  /etc/fail2ban/action.d/ipset-block.conf \
        || ERRORS+=$'\nMissing ipset-block.conf'

      # ── интеграция с AdGuard Home (по выбору) ────────
      if [[ "$ADGUARD_HOME" == "y" ]]; then
        cp "$FLT_AG"  /etc/fail2ban/filter.d/adguard-home-auth.conf \
          || ERRORS+=$'\nMissing adguard-home-auth.conf'
        cp "$JADGU"   /etc/fail2ban/jail.d/adguard-panel.conf \
          || ERRORS+=$'\nMissing adguard-panel.conf'
      fi

      systemctl enable --now fail2ban 2>/dev/null || true
      systemctl restart       fail2ban 2>/dev/null || true
  fi
fi
apt-get autoremove -y
apt-get clean

# Клонируем репозиторий и устанавливаем dnslib
DNSLIB_DIR="$TMP_DIR/dnslib"
git clone https://github.com/paulc/dnslib.git "$DNSLIB_DIR"
PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install --force-reinstall --user "$DNSLIB_DIR"

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

# ── settings.map через модуль settings.sh ------------------------------------
. /opt/rzans_vpn_main/settings.sh
if [[ -f "$OLD_SETTINGS_TMP" ]]; then
  mv "$OLD_SETTINGS_TMP" /opt/rzans_vpn_main/settings.map
fi
settings_heal   # создаёт или обновляет файл, подтягивает нижние теги

# перезаписываем верхние теги значениями из install-wizard
_set_tag() {
  local tag="$1" val="$2"
  [[ "$tag" == "WIREGUARD_HOST" ]] && val="\"$val\""
  # экранируем / и &
  local val_esc
  val_esc=$(printf '%s' "$val" | sed -e 's/[\/&]/\\&/g')
  if grep -q -E "^[[:space:]]*$tag[[:space:]]" "$SETTINGS"; then
    sed -i -E "s|^[[:space:]]*$tag[[:space:]]+.*$|$(printf '%-22s %s' "$tag" "$val_esc")|" "$SETTINGS"
  else
    printf '%-22s %s\n' "$tag" "$val_esc" >>"$SETTINGS"
  fi
}
for t in RZANS_SVPN_MAIN_DNS RZANS_FVPN_MAIN_DNS BLOCK_ADS ADGUARD_HOME \
         SSH_PROTECTION WIREGUARD_HOST ROUTE_ALL DISCORD_INCLUDE CLOUDFLARE_INCLUDE \
         AMAZON_INCLUDE HETZNER_INCLUDE DIGITALOCEAN_INCLUDE OVH_INCLUDE \
         TELEGRAM_INCLUDE GOOGLE_INCLUDE AKAMAI_INCLUDE; do
  _set_tag "$t" "${!t}"
done
settings_pretty
echo "✓ settings.map updated (settings_heal + wizard overrides)"

# ── единый блок прав на ВСЁ содержимое
find /opt/rzans_vpn_main -type d -exec chmod 755 {} +
find /opt/rzans_vpn_main -type f -exec chmod 644 {} +
find /opt/rzans_vpn_main -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod +x {} +
# settings.map должен быть приватным
chmod 600 /opt/rzans_vpn_main/settings.map 2>/dev/null || true

# Настраиваем DNS в RzaNs_fVPN_main
if [[ "$RZANS_FVPN_MAIN_DNS" == "2" ]]; then
	# Quad9
	shopt -s nullglob
    for f in /etc/wireguard/templates/rzans_fvpn_main.conf; do
      sed -i 's/1\.1\.1\.1, 1\.0\.0\.1/9.9.9.10, 149.112.112.10/' "$f"
    done
    shopt -u nullglob
elif [[ "$RZANS_FVPN_MAIN_DNS" == "3" ]]; then
	# Google
	shopt -s nullglob
    for f in /etc/wireguard/templates/rzans_fvpn_main.conf; do
      sed -i 's/1\.1\.1\.1, 1\.0\.0\.1/8.8.8.8, 8.8.4.4/' "$f"
    done
    shopt -u nullglob
elif [[ "$RZANS_FVPN_MAIN_DNS" == "4" ]]; then
	# AdGuard
	shopt -s nullglob
    for f in /etc/wireguard/templates/rzans_fvpn_main.conf; do
      sed -i 's/1\.1\.1\.1, 1\.0\.0\.1/94.140.14.14, 94.140.15.15/' "$f"
    done
    shopt -u nullglob
elif [[ "$RZANS_FVPN_MAIN_DNS" == "5" ]]; then
	# Comss
	shopt -s nullglob
    for f in /etc/wireguard/templates/rzans_fvpn_main.conf; do
      sed -i 's/1\.1\.1\.1, 1\.0\.0\.1/83.220.169.155, 212.109.195.93/' "$f"
    done
    shopt -u nullglob
elif [[ "$RZANS_FVPN_MAIN_DNS" == "6" ]]; then
	# Xbox
	shopt -s nullglob
    for f in /etc/wireguard/templates/rzans_fvpn_main.conf; do
      sed -i 's/1\.1\.1\.1, 1\.0\.0\.1/176.99.11.77, 80.78.247.254/' "$f"
    done
    shopt -u nullglob
elif [[ "$RZANS_FVPN_MAIN_DNS" == "7" ]]; then
	# Malw (пример — замените при необходимости)
	shopt -s nullglob
    for f in /etc/wireguard/templates/rzans_fvpn_main.conf; do
      sed -i 's/1\.1\.1\.1, 1\.0\.0\.1/45.90.28.0, 45.90.30.0/' "$f"
    done
    shopt -u nullglob
fi

# Настраиваем DNS в RzaNs_sVPN_main
if [[ -f /etc/knot-resolver/kresd.conf ]]; then
  if [[ "$RZANS_SVPN_MAIN_DNS" == "2" ]]; then
	# Cloudflare+Quad9
	sed -i "s/'193\.58\.251\.251', '212\.92\.149\.149', '212\.92\.149\.150'/'1.1.1.1', '1.0.0.1', '9.9.9.10', '149.112.112.10'/" /etc/knot-resolver/kresd.conf
  elif [[ "$RZANS_SVPN_MAIN_DNS" == "3" ]]; then
	# Comss
	sed -i "s/'193\.58\.251\.251', '212\.92\.149\.149', '212\.92\.149\.150'/'83.220.169.155', '212.109.195.93'/" /etc/knot-resolver/kresd.conf
	sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'83.220.169.155', '212.109.195.93'/" /etc/knot-resolver/kresd.conf
  elif [[ "$RZANS_SVPN_MAIN_DNS" == "4" ]]; then
	# Xbox
	sed -i "s/'193\.58\.251\.251', '212\.92\.149\.149', '212\.92\.149\.150'/'176.99.11.77', '80.78.247.254'/" /etc/knot-resolver/kresd.conf
	sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'176.99.11.77', '80.78.247.254'/" /etc/knot-resolver/kresd.conf
  elif [[ "$RZANS_SVPN_MAIN_DNS" == "5" ]]; then
	# Malw (пример — замените при необходимости)
	sed -i "s/'193\.58\.251\.251', '212\.92\.149\.149', '212\.92\.149\.150'/'45.90.28.0', '45.90.30.0'/" /etc/knot-resolver/kresd.conf
	sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'45.90.28.0', '45.90.30.0'/" /etc/knot-resolver/kresd.conf
  fi
fi

# Загружаем и создаем списки исключений IP-адресов
/opt/rzans_vpn_main/doall.sh ip

# гарантируем, что каталоги уже существуют
mkdir -p /etc/wireguard \
         /opt/rzans_vpn_main/client/{rzans_svpn_main,rzans_fvpn_main}

# Настраиваем сервер AmneziaWG для первого запуска, пересоздаём профили (если ключей/клиентов ещё нет — client.sh создаст их)
/opt/rzans_vpn_main/client.sh 4

# Включим обновляемые службы
# enable тех unit-ов, которые реально существуют
for u in kresd@1 kresd@2 rzans_vpn_main wg-quick@rzans_svpn_main wg-quick@rzans_fvpn_main; do
  systemctl enable "$u" 2>/dev/null || true
done

# enable updater, если такой unit присутствует
if systemctl list-unit-files | grep -q '^rzans_vpn_main-update\.service'; then
  systemctl enable rzans_vpn_main-update rzans_vpn_main-update.timer
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
sleep 5
reboot
