#!/bin/bash
# parse.sh — умная генерация списков IP/hosts для AmneziaWG и Knot Resolver
# Сам определяет, что пересобирать (IP/HOSTS) по изменениям входов.
# Поддерживает drop-in конфиги: config/*include-ips.txt, config/*exclude-ips.txt, config/*include-hosts.txt, config/*exclude-hosts.txt
# Совместим с обновлёнными settings.sh / update.sh / doall.sh

set -eEuo pipefail
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

# ── обработка ошибок (без pcre) ─────────────────────────────────────────────
_handle_err() {
  local os now
  os="$(lsb_release -ds 2>/dev/null || sed -n 's/^PRETTY_NAME="\{0,1\}\(.*\)"\{0,1\}$/\1/p' /etc/os-release)"
  now="$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z)"
  echo "$os $(uname -r) $now"
  echo -e "\e[1;31mError at line $1: $2\e[0m"
  exit 1
}
trap '_handle_err $LINENO "$BASH_COMMAND"' ERR

echo "Parse RzaNs_VPN_main files…"

# ── базовые пути и helpers из settings.sh ────────────────────────────────────
: "${BASE_DIR:=/opt/rzans_vpn_main}"
cd "$BASE_DIR"
# Подтягиваем функции yaml_bool, kresd_fix_perms, kresd_flush_all и т.д.
. "${BASE_DIR}/settings/settings.sh"

# Каталоги
install -d -m 755 temp result 2>/dev/null || true
install -d -m 755 "${STATE_DIR}" 2>/dev/null || true   # STATE_DIR задан в settings.sh

# ── route_all (управляет логикой HOSTS) ──────────────────────────────────────
ROUTE_ALL="$(yaml_bool 'routing.route_all' n)"

# ── IDN бинарь (idn | idn2), если доступен ──────────────────────────────────
IDN_BIN=""
if command -v idn  >/dev/null 2>&1; then IDN_BIN="idn"
elif command -v idn2 >/dev/null 2>&1; then IDN_BIN="idn2"
fi
IDN_TLD='--no-tld'

# ── разбор опций: ручное принуждение/совместимость ──────────────────────────
FORCE=0; WANT_IP=0; WANT_HOSTS=0
for a in "${@:-}"; do
  case "$a" in
    --force) FORCE=1 ;;
    ip|ips)  WANT_IP=1 ;;
    host|hosts) WANT_HOSTS=1 ;;
    full|lists) : ;;      # из doall.sh — игнорируем, авто-детект сам решит
    *) : ;;
  esac
done

# ── подписи входных данных ───────────────────────────────────────────────────
_sha256() { sha256sum | awk '{print $1}'; }

_ip_sig() {
  {
    echo "IP_INPUTS_V2"
    for f in config/*exclude-ips.txt; do [[ -e "$f" ]] && cat "$f"; done
    for f in download/*-ips.txt;     do [[ -e "$f" ]] && cat "$f"; done
    for f in config/*include-ips.txt; do [[ -e "$f" ]] && cat "$f"; done
  } | _sha256
}

_hosts_sig() {
  {
    echo "HOSTS_INPUTS_V3"
    echo "ROUTE_ALL=${ROUTE_ALL}"
    echo "IDN_BIN=${IDN_BIN:-none}"
    [[ -s download/dump.csv        ]] && cat download/dump.csv
    [[ -s download/domains.lst     ]] && cat download/domains.lst
    [[ -s download/nxdomain.txt    ]] && cat download/nxdomain.txt
    [[ -s download/include-hosts.txt ]] && cat download/include-hosts.txt
    [[ -s download/exclude-hosts.txt ]] && cat download/exclude-hosts.txt
    for f in config/*include-hosts.txt; do [[ -e "$f" ]] && cat "$f"; done
    for f in config/*exclude-hosts.txt; do [[ -e "$f" ]] && cat "$f"; done
  } | _sha256
}

_needs() { # _needs <name> <sig>
  local f="${STATE_DIR}/parse_${1}.sha256"
  (( FORCE )) && { echo 1; return; }
  [[ -s "$f" ]] || { echo 1; return; }
  [[ "$(cat "$f" 2>/dev/null || true)" != "$2" ]] && echo 1 || echo 0
}
_save() { printf '%s\n' "$2" > "${STATE_DIR}/parse_${1}.sha256"; }

IP_SIG="$(_ip_sig)"
HOSTS_SIG="$(_hosts_sig)"
RUN_IP="$(_needs ip "$IP_SIG")"
RUN_HOSTS="$(_needs hosts "$HOSTS_SIG")"
# Ручное принуждение (для отладки)
(( WANT_IP ))    && RUN_IP=1
(( WANT_HOSTS )) && RUN_HOSTS=1

# ── PARSE IPs (только если нужно) ────────────────────────────────────────────
if (( RUN_IP )); then
  echo "IPs…"

  # exclude (drop-in)
  : > temp/exclude-ips.txt
  shopt -s nullglob
  for f in config/*exclude-ips.txt; do
    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' "$f" >> temp/exclude-ips.txt
  done
  sort -u temp/exclude-ips.txt -o temp/exclude-ips.txt

  : > temp/include-ips.txt
  for f in download/*-ips.txt config/*include-ips.txt; do
    [[ -e "$f" ]] || continue
    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' "$f" >> temp/include-ips.txt
  done
  shopt -u nullglob
  sort -u temp/include-ips.txt -o temp/include-ips.txt

  # вычитаем исключения
  grep -vFxf temp/exclude-ips.txt temp/include-ips.txt > temp/ips.raw || : > temp/ips.raw

  # строгая фильтрация только корректных IPv4 CIDR /1..32 (каждый октет 0..255)
  awk -F'[/.]' '
    NF==5 {
      o1=$1+0; o2=$2+0; o3=$3+0; o4=$4+0; m=$5+0;
      if (o1>=0 && o1<=255 && o2>=0 && o2<=255 && o3>=0 && o3<=255 && o4>=0 && o4<=255 && m>=1 && m<=32)
        print $0
    }
  ' temp/ips.raw > result/ips.txt

  echo "$(wc -l < result/ips.txt) - ips.txt"

  # строка для WG/AmneziaWG (как было — с ведущей запятой, совместимость)
  awk '{printf ", %s", $0}' result/ips.txt > result/ips

  # применяем только при изменении
  if [[ -f result/ips ]] && ! cmp -s result/ips /etc/wireguard/ips 2>/dev/null; then
    install -D -m 0644 result/ips /etc/wireguard/ips
  fi

  _save ip "$IP_SIG"
fi

# ── PARSE HOSTS / RPZ (только если нужно) ───────────────────────────────────
if (( RUN_HOSTS )); then
  echo "Hosts…"

  # exclude-hosts.txt
  : > result/exclude-hosts.txt.tmp
  [[ -e download/exclude-hosts.txt ]] && \
    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' download/exclude-hosts.txt >> result/exclude-hosts.txt.tmp
  shopt -s nullglob
  for f in config/*exclude-hosts.txt; do
    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' "$f" >> result/exclude-hosts.txt.tmp
  done
  shopt -u nullglob
  sort -u result/exclude-hosts.txt.tmp > result/exclude-hosts.txt
  rm -f result/exclude-hosts.txt.tmp

  # include-hosts (ручные)
  : > temp/include-hosts.txt
  [[ -e download/include-hosts.txt ]] && \
    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' download/include-hosts.txt >> temp/include-hosts.txt
  shopt -s nullglob
  for f in config/*include-hosts.txt; do
    sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' "$f" >> temp/include-hosts.txt
  done
  shopt -u nullglob

  # zapret-info dump.csv → колонка 2, в UTF-8, конвертим IDN (если есть)
  if [[ -s download/dump.csv ]]; then
    cut -d';' -f2 download/dump.csv \
      | iconv -f cp1251 -t utf8 2>/dev/null \
      | sed -E 's/^[[:space:][:punct:]]+//; s/[[:space:][:punct:]]+$//' \
      | awk 'NF' \
      | { [[ -n "$IDN_BIN" ]] && CHARSET=UTF-8 "$IDN_BIN" $IDN_TLD || cat; } \
      | sed -E 's/\.$//' \
      | grep -E '\.' >> temp/include-hosts.txt || true
  fi

  # antifilter.download
  if [[ -s download/domains.lst ]]; then
    sed -E 's/["[:space:]]+//g; s/\.$//' download/domains.lst \
      | { [[ -n "$IDN_BIN" ]] && CHARSET=UTF-8 "$IDN_BIN" $IDN_TLD || cat; } \
      | grep -E '\.' >> temp/include-hosts.txt || true
  fi

  # жёсткое удаление доменов с входа: NXDOMAIN + локальные remove-hosts
  : > temp/remove-hosts.txt
  [[ -s download/nxdomain.txt     ]] && cat download/nxdomain.txt     >> temp/remove-hosts.txt
  [[ -s config/remove-hosts.txt   ]] && cat config/remove-hosts.txt   >> temp/remove-hosts.txt
  if [[ -s temp/remove-hosts.txt ]]; then
    sort -u temp/remove-hosts.txt -o temp/remove-hosts.txt
    grep -vFxf temp/remove-hosts.txt temp/include-hosts.txt > temp/include-hosts.clean || : > temp/include-hosts.clean
  else
    cp -f temp/include-hosts.txt temp/include-hosts.clean
  fi

  # срезаем короткие техпрефиксы (www/msk/spb/1–2 символа) у поддоменов
  sed -E '/\..*\./ s/^([-0-9a-zA-Z]{1,2}|www|msk|spb)[0-9]*\.//' \
    temp/include-hosts.clean \
    | LC_ALL=C sort -u > temp/include-hosts.norm

  # удаляем вложенные домены (оставляем только верхний из цепочки)
  sed 's/$/$/'  temp/include-hosts.norm  > temp/include-hosts.eol
  sed 's/^/./'  temp/include-hosts.eol   > temp/_subs.mark
  grep -vFf     temp/_subs.mark          temp/include-hosts.eol > temp/include-hosts.top || true

  if [[ "${ROUTE_ALL,,}" == "y" ]]; then
    echo '.' > result/include-hosts.txt
    sed -e 's/^/./' -e 's/$/$/' result/exclude-hosts.txt > temp/_excl.$
    grep -Ff temp/_excl.$ temp/include-hosts.top | sed 's/\$$//' >> result/include-hosts.txt || true
  else
    sed 's/\$$//' temp/include-hosts.top > result/include-hosts.txt
  fi

  echo "$(wc -l < result/include-hosts.txt) - include-hosts.txt"
  echo "$(wc -l < result/exclude-hosts.txt) - exclude-hosts.txt"

  # ── RPZ proxy (атомарно) ──────────────────────────────────────────────────
  {
    echo '$TTL 3600'
    echo '@ SOA . . (0 0 0 0 0)'
    # include → NXDOMAIN (CNAME .)
    sed '/^\.$/ s/.*/*. CNAME ./; t; s/$/ CNAME ./; p; s/^/*./' result/include-hosts.txt
    # exclude → rpz-passthru.
    sed '/^\.$/ s/.*/*. CNAME rpz-passthru./; t; s/$/ CNAME rpz-passthru./; p; s/^/*./' result/exclude-hosts.txt
  } > result/proxy.rpz

  install -d -m 755 /etc/knot-resolver
  UPDATED=0
  if [[ ! -f /etc/knot-resolver/proxy.rpz ]] || ! cmp -s result/proxy.rpz /etc/knot-resolver/proxy.rpz; then
    install -m 0644 result/proxy.rpz /etc/knot-resolver/.proxy.rpz.tmp
    mv -f /etc/knot-resolver/.proxy.rpz.tmp /etc/knot-resolver/proxy.rpz
    # выровнять владельца/права/контекст (функция из settings.sh)
    kresd_fix_perms /etc/knot-resolver/proxy.rpz || true
    UPDATED=1
  fi

  # Чистим кэш всех экземпляров kresd только если RPZ реально обновился
  if (( UPDATED )); then
    kresd_flush_all || true
  fi

  _save hosts "$HOSTS_SIG"
fi

# Если ничего не требовалось — скажем об этом явно
if (( !RUN_IP && !RUN_HOSTS )); then
  echo "[parse] nothing changed — skip"
fi

exit 0