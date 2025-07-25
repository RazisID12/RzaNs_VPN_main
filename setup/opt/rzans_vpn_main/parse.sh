#!/bin/bash
# parse.sh — генерация списков IP/hosts для AmneziaWG и Knot Resolver
# соответствует обновлённым setup.sh / update.sh / doall.sh

export LC_ALL=C
set -eEuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# ── обработка ошибок ─────────────────────────────────────────────────────────
handle_error() {
    local os
    os="$(lsb_release -ds 2>/dev/null \
         || grep -oP '(?<=^PRETTY_NAME=).*' /etc/os-release | tr -d '\"')"
    echo "$os $(uname -r) $(date --iso-8601=seconds)"
    echo -e "\e[1;31mError at line $1: $2\e[0m"
    exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

echo "Parse RzaNs_VPN_main files…"

cd /opt/rzans_vpn_main

# ── рабочие каталоги ─────────────────────────────────────────────────────────
mkdir -p temp result
rm -f temp/* 2>/dev/null || true
rm -f result/* 2>/dev/null || true

# ── читаем нужные флаги из settings.map ──────────────────────────────────────
SETTINGS="/opt/rzans_vpn_main/settings.map"

get_tag() {   # get_tag TAG DEFAULT
  local tag="$1" def="$2" line
  line=$(awk -v t="^\\s*${tag}\\s+" \
             '$0~t && $0!~/^\\s*#/{ $1=""; sub(/^ +/,""); print; exit }' \
             "$SETTINGS" 2>/dev/null | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')
  [[ -n $line ]] && printf '%s' "$line" || printf '%s' "$def"
}

ROUTE_ALL="$(get_tag ROUTE_ALL n)"
BLOCK_ADS="$(get_tag BLOCK_ADS n)"

# ── PARSE IPs ────────────────────────────────────────────────────────────────
if [[ -z "${1:-}" || "$1" == "ip" || "$1" == "ips" ]]; then
    echo "IPs…"

    # include / exclude
    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' \
        config/exclude-ips.txt | sort -u > temp/exclude-ips.txt

    tmp_list="temp/include-ips.txt"
    : > "$tmp_list"
    files=(download/*-ips.txt config/include-ips.txt)   # may expand to itself if patterns empty
    for f in "${files[@]}"; do
        [[ -e $f ]] || continue
        sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' "$f" >> "$tmp_list"
    done
    sort -u "$tmp_list" -o "$tmp_list"

    # вычитаем исключения
    grep -vFxf temp/exclude-ips.txt "$tmp_list" > temp/ips.txt || : > temp/ips.txt

    # только CIDR
    awk '/([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}/ {print}' temp/ips.txt \
        > result/ips.txt

    echo "$(wc -l < result/ips.txt) - ips.txt"

    # Формат для AmneziaWG/WireGuard — одна строка, через запятую
    awk '{printf ", %s", $0}' result/ips.txt > result/ips

    # Копируем, если изменилось
    if [[ -f result/ips ]] && ! diff -q result/ips /etc/wireguard/ips &>/dev/null; then
        cp -f result/ips /etc/wireguard/ips
    fi
fi

# ── PARSE HOSTS / RPZ ────────────────────────────────────────────────────────
if [[ -z "${1:-}" || "$1" == "host" || "$1" == "hosts" ]]; then
    # чистим кеш knot-resolver
    # shellcheck disable=SC2016
    count=$(echo 'cache.clear()' | socat - /run/knot-resolver/control/1 2>/dev/null | grep -oE '[0-9]+')
    echo "DNS cache cleared: $count entries"

    echo "AdBlock-hosts…"

    # даже если BLOCK_ADS=n, update.sh создаёт пустые файлы — код ниже безопасен
    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' \
        download/include-adblock-hosts.txt config/include-adblock-hosts.txt \
        > temp/include-adblock-hosts.txt

    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' \
        download/exclude-adblock-hosts.txt config/exclude-adblock-hosts.txt \
        > temp/exclude-adblock-hosts.txt

    # AdGuard
    sed -n '/\*/!s/^||\([^ ]*\)\^.*$/\1/p'  download/adguard.txt | sed '/^[0-9.]*$/d' \
        >> temp/include-adblock-hosts.txt
    sed -n '/\*/!s/^@@||\([^ ]*\)\^.*$/\1/p' download/adguard.txt | sed '/^[0-9.]*$/d' \
        >> temp/exclude-adblock-hosts.txt

    # OISD
    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' download/oisd.txt \
        >> temp/include-adblock-hosts.txt

    sort -u temp/include-adblock-hosts.txt > result/include-adblock-hosts.txt
    sort -u temp/exclude-adblock-hosts.txt > result/exclude-adblock-hosts.txt

    echo "$(wc -l < result/include-adblock-hosts.txt) - include-adblock-hosts.txt"
    echo "$(wc -l < result/exclude-adblock-hosts.txt) - exclude-adblock-hosts.txt"

    # RPZ deny
    {
        echo '$TTL 3600'
        echo '@ SOA . . (0 0 0 0 0)'
        sed 's/$/ CNAME ./; p; s/^/*./' result/include-adblock-hosts.txt
        sed 's/$/ CNAME rpz-passthru./; p; s/^/*./' result/exclude-adblock-hosts.txt
        sed '/^;/d; /^$/d' download/rpz.txt
    } > result/deny.rpz

    if [[ -f result/deny.rpz ]] && ! diff -q result/deny.rpz /etc/knot-resolver/deny.rpz &>/dev/null; then
        cp -f result/deny.rpz /etc/knot-resolver/deny.rpz.tmp
        mv -f /etc/knot-resolver/deny.rpz.tmp /etc/knot-resolver/deny.rpz
    fi

    echo "Hosts…"

    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' \
        download/exclude-hosts.txt config/exclude-hosts.txt | sort -u > result/exclude-hosts.txt

    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' \
        download/include-hosts.txt config/include-hosts.txt > temp/include-hosts.txt

    # zapret-info dump.csv
    cut -d ';' -f 2 download/dump.csv | \
      iconv -f cp1251 -t utf8 | \
      grep -P '\.[а-яА-Яa-zA-Z]' | \
      sed -E 's/^[[:punct:]]+//; s/[[:punct:]]+$//' | \
      CHARSET=UTF-8 idn --no-tld >> temp/include-hosts.txt

    # antifilter.download
    sed -e 's/\.$//' -e 's/"//g' download/domains.lst | \
      CHARSET=UTF-8 idn --no-tld >> temp/include-hosts.txt

    # фильтрация NXDOMAIN и мусорных префиксов
    # shellcheck disable=SC2086
    grep -vFxf "download/nxdomain.txt" "temp/include-hosts.txt" | \
        sed -E '/\..*\./ s/^([-0-9a-zA-Z]{1,2}|www|msk|spb)[0-9]*\.//' \
        | sort -u > temp/include-hosts2.txt

    # удаляем вложенные домены
    sed -e 's/$/$/' temp/include-hosts2.txt > temp/include-hosts3.txt
    sed -e 's/^/./' temp/include-hosts3.txt > temp/exclude-patterns.txt
    grep -vFf temp/exclude-patterns.txt temp/include-hosts3.txt \
        > temp/include-hosts4.txt

    if [[ "${ROUTE_ALL,,}" == "y" ]]; then
        echo '.' > result/include-hosts.txt
        sed -e 's/^/./' -e 's/$/$/' result/exclude-hosts.txt > temp/exclude-patterns2.txt
        grep -Ff temp/exclude-patterns2.txt temp/include-hosts4.txt \
            > temp/include-hosts5.txt
        sed 's/\$$//' temp/include-hosts5.txt >> result/include-hosts.txt
    else
        sed 's/\$$//' temp/include-hosts4.txt > result/include-hosts.txt
    fi

    echo "$(wc -l < result/include-hosts.txt) - include-hosts.txt"
    echo "$(wc -l < result/exclude-hosts.txt) - exclude-hosts.txt"

    # RPZ proxy
    {
        echo '$TTL 3600'
        echo '@ SOA . . (0 0 0 0 0)'
        sed '/^\.$/ s/.*/*. CNAME ./; t; s/$/ CNAME ./; p; s/^/*./'      result/include-hosts.txt
        sed '/^\.$/ s/.*/*. CNAME rpz-passthru./; t; s/$/ CNAME rpz-passthru./; p; s/^/*./' result/exclude-hosts.txt
    } > result/proxy.rpz

    if [[ -f result/proxy.rpz ]] && ! diff -q result/proxy.rpz /etc/knot-resolver/proxy.rpz &>/dev/null; then
        cp -f result/proxy.rpz /etc/knot-resolver/proxy.rpz.tmp
        mv -f /etc/knot-resolver/proxy.rpz.tmp /etc/knot-resolver/proxy.rpz
    fi
fi

exit 0
