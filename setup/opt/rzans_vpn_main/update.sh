#!/bin/bash
set -eEuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

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

export LC_ALL=C

# ── подключаем общий модуль настроек и «лечим» settings.map ────────────────
. /opt/rzans_vpn_main/settings.sh
settings_heal

mkdir -p /opt/rzans_vpn_main/download

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

RPZ_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/rpz.txt"
RPZ_PATH="download/rpz.txt"

INCLUDE_HOSTS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/include-hosts.txt"
INCLUDE_HOSTS_PATH="download/include-hosts.txt"

EXCLUDE_HOSTS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/exclude-hosts.txt"
EXCLUDE_HOSTS_PATH="download/exclude-hosts.txt"

INCLUDE_ADBLOCK_HOSTS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/include-adblock-hosts.txt"
INCLUDE_ADBLOCK_HOSTS_PATH="download/include-adblock-hosts.txt"

EXCLUDE_ADBLOCK_HOSTS_LINK="https://raw.githubusercontent.com/RazisID12/RzaNs_VPN_main/main/setup/opt/rzans_vpn_main/download/exclude-adblock-hosts.txt"
EXCLUDE_ADBLOCK_HOSTS_PATH="download/exclude-adblock-hosts.txt"

ADGUARD_LINK="https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
ADGUARD_PATH="download/adguard.txt"

OISD_LINK="https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_small.txt"
OISD_PATH="download/oisd.txt"

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
FLAGS=(BLOCK_ADS ROUTE_ALL DISCORD_INCLUDE CLOUDFLARE_INCLUDE AMAZON_INCLUDE \
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
    download "$RPZ_PATH" "$RPZ_LINK"
    download "$INCLUDE_HOSTS_PATH" "$INCLUDE_HOSTS_LINK"

	if [[ "$ROUTE_ALL" = "y" ]]; then
        download "$EXCLUDE_HOSTS_PATH" "$EXCLUDE_HOSTS_LINK"
	else
       printf '# НЕ РЕДАКТИРУЙТЕ ЭТОТ ФАЙЛ!' > "/opt/rzans_vpn_main/$EXCLUDE_HOSTS_PATH"
	fi

	if [[ "$BLOCK_ADS" = "y" ]]; then
        download "$INCLUDE_ADBLOCK_HOSTS_PATH" "$INCLUDE_ADBLOCK_HOSTS_LINK"
        download "$EXCLUDE_ADBLOCK_HOSTS_PATH" "$EXCLUDE_ADBLOCK_HOSTS_LINK"
        download "$ADGUARD_PATH" "$ADGUARD_LINK"
        download "$OISD_PATH" "$OISD_LINK"
	else
        > "/opt/rzans_vpn_main/$INCLUDE_ADBLOCK_HOSTS_PATH"
        > "/opt/rzans_vpn_main/$EXCLUDE_ADBLOCK_HOSTS_PATH"
        > "/opt/rzans_vpn_main/$ADGUARD_PATH"
        > "/opt/rzans_vpn_main/$OISD_PATH"
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

