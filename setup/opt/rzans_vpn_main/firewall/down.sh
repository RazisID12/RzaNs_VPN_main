#!/usr/bin/env bash
# DOWN-script – снимает ровно то, что ставит up.sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027
set -eEuo pipefail
trap 'echo "ERR on line $LINENO – cmd: $BASH_COMMAND" >&2; exit 1' ERR
shopt -s expand_aliases

# === CORE PATHS & SETTINGS ====================================================
BASE_DIR="/opt/rzans_vpn_main"
RUN_DIR="/run/rzans_vpn_main"
FW_DIR="${BASE_DIR}/firewall"
SETTINGS_SH="${BASE_DIR}/settings/settings.sh"
. "${SETTINGS_SH}"
mkdir -p "$RUN_DIR"

# === STATE / CONFIG DIRS & FILES =============================================
IPSET_STATE_DIR="${IPSET_STATE_DIR:-/var/lib/ipset}"
mkdir -p "$IPSET_STATE_DIR"
IPSET_BAN_STATE="${IPSET_BAN_STATE:-${IPSET_STATE_DIR}/ipset-bans.rules}"
IPSET_ALLOW_STATE="${IPSET_ALLOW_STATE:-${IPSET_STATE_DIR}/ipset-allow.rules}"
SYSCTL_DIR="${SYSCTL_DIR:-/etc/sysctl.d}"
mkdir -p "$SYSCTL_DIR"
SYSCTL_FILE="${SYSCTL_FILE:-${SYSCTL_DIR}/99-rzans_vpn_main.conf}"

# === CONSTANTS ================================================================
# keep in sync with up.sh
ABUSE_PORTS=(25 465 587 2525 23 21 69 135 137 138 139 445 1900 6666 6667 6668 6669)

## Аварийка: если down вызывается вручную — гасим таймер и чистим её правила.
if [[ -z "${RZANS_KEEP_FALLBACK:-}" ]]; then
  "${FW_DIR}/fallback.sh" cancel  || true
  "${FW_DIR}/fallback.sh" cleanup || true
fi

# --- choose iptables backend consistently (nft pinned) ---
IPT_BIN=$(command -v iptables-nft || command -v iptables || true)
IP6T_BIN=$(command -v ip6tables-nft || command -v ip6tables || true)
if [[ -x "$IPT_BIN" ]]; then
  echo "Using iptables backend: $("$IPT_BIN" -V)" >&2
else
  echo "ERROR: iptables backend not found" >&2
  exit 1
fi
ipt()  { "$IPT_BIN"  -w "$@"; }
HAS_IP6=n
if [[ -x "$IP6T_BIN" ]]; then HAS_IP6=y; fi
ipt6() { if [[ $HAS_IP6 == y ]]; then "$IP6T_BIN" -w "$@"; else return 0; fi; }

# helpers (такие же, как в up.sh)
is_ip_v4()   { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]; }
# mini-helper, нужен для проверки наличия yq
_have(){ command -v "$1" >/dev/null 2>&1; }

# точечное удаление правил (зеркало ins/add из up.sh)
del()  { local t=$1 c=$2; shift 2; ipt  -t "$t" -C "$c" "$@" 2>/dev/null && ipt  -t "$t" -D "$c" "$@" || true; }
del6() { local t=$1 c=$2; shift 2; ipt6 -t "$t" -C "$c" "$@" 2>/dev/null && ipt6 -t "$t" -D "$c" "$@" || true; }

# del_by_comment [TABLE] CHAIN [CHAIN6] REGEX
del_by_comment(){
  local table="filter" c4 c6 pat
  case "${1:-}" in filter|nat|mangle|raw|security) table="$1"; shift;; esac
  case "$#" in 2) c4="$1"; c6="$1"; pat="$2";; 3) c4="$1"; c6="$2"; pat="$3";; *) return 0;; esac
  { ipt  -t "$table" -S "$c4" 2>/dev/null || true; } \
    | awk -v p="$pat" '$0~p && $0~/^-A /{sub(/^-A /,"-D ");print}' \
    | while IFS=' ' read -r -a SPEC; do ipt  -t "$table" "${SPEC[@]}" || true; done
  { ipt6 -t "$table" -S "$c6" 2>/dev/null || true; } \
    | awk -v p="$pat" '$0~p && $0~/^-A /{sub(/^-A /,"-D ");print}' \
    | while IFS=' ' read -r -a SPEC; do ipt6 -t "$table" "${SPEC[@]}" || true; done
}

## ── 0a. Аккуратный демонтаж DNS egress-якорей в filter/OUTPUT ───────────────
# v4: снять переходы OUTPUT → RZANS_DNS_EGRESS и удалить цепь
ipt -t filter -S OUTPUT \
  | awk -v ch="RZANS_DNS_EGRESS" \
      '$0 ~ (" -A OUTPUT ") && $0 ~ (" -j " ch "($| )") {sub(/^-A OUTPUT /,""); print}' \
  | while IFS=' ' read -r -a SPEC; do ipt -t filter -D OUTPUT "${SPEC[@]}" 2>/dev/null || true; done
ipt -t filter -F RZANS_DNS_EGRESS 2>/dev/null || true
ipt -t filter -X RZANS_DNS_EGRESS 2>/dev/null || true

# v6: аналогично, если доступен ip6tables
if [[ "$HAS_IP6" == y ]]; then
  ipt6 -t filter -S OUTPUT \
    | awk -v ch="RZANS_DNS6_EGRESS" \
        '$0 ~ (" -A OUTPUT ") && $0 ~ (" -j " ch "($| )") {sub(/^-A OUTPUT /,""); print}' \
    | while IFS=' ' read -r -a SPEC; do ipt6 -t filter -D OUTPUT "${SPEC[@]}" 2>/dev/null || true; done
  ipt6 -t filter -F RZANS_DNS6_EGRESS 2>/dev/null || true
  ipt6 -t filter -X RZANS_DNS6_EGRESS 2>/dev/null || true
fi

del_by_comment OUTPUT OUTPUT 'RZANS_DOT_(ALLOW|REJECT)6?'

## ── 0-bis. Аккуратный демонтаж наших NAT-хуков/цепочек ─────────────
# Снимаем PREROUTING-правила, ведущие в наши цепочки, и удаляем сами цепочки.
# Делается ДО общего flush, чтобы не зависеть от «глухого» режима.
for CH in RZANS_VPN_MAIN-MAPPING RZANS_DNS_S RZANS_DNS_F; do
  ipt -t nat -S PREROUTING \
    | awk -v ch="$CH" \
        '$0 ~ (" -A PREROUTING ") && $0 ~ (" -j " ch "($| )") {sub(/^-A PREROUTING /,""); print}' \
    | while IFS=' ' read -r -a SPEC; do ipt -t nat -D PREROUTING "${SPEC[@]}" 2>/dev/null || true; done
  ipt -t nat -F "$CH" 2>/dev/null || true
  ipt -t nat -X "$CH" 2>/dev/null || true
done

## 1) читаем settings.yaml (симметрично up.sh)
read_settings() {
  # Значения по умолчанию используем те же, что в up.sh
  # --- SNAT-карты -----------------------------------------------------
  if command -v yq >/dev/null 2>&1; then
    readarray -t SNAT_MAP < <(
      _yaml_merged \
      | yq e -r '
          .snat // [] | .[] |
          .internal + "=" +
            (( .external | select(. != "") ) // "0.0.0.0")
        ' - \
      | tr -d ' \t\r' | awk '!seen[$0]++'       # убираем space/tab/CR и защитимся от дубликатов
    )
  else
    SNAT_MAP=()
  fi
}

read_settings

# ── 2. базовые переменные (симметрия с up.sh) ───────────────────────
if [[ -n "${1:-}" ]]; then
  INTERFACE=$1
else
  INTERFACE="$(server_iface)"
fi

# loopback-сервисы (точно как в up.sh)
KRESD2_IP="${KRESD2_IP:-127.0.0.2}"
KRESD3_IP="${KRESD3_IP:-127.0.0.3}"
KRESD4_IP="${KRESD4_IP:-127.0.0.4}"
PROXY_IP="${PROXY_IP:-127.0.0.5}"
AGH_IP="${AGH_IP:-127.0.0.6}"

# финальная проверка
[[ -z $INTERFACE ]] && { echo "Cannot determine external interface"; exit 1; }

# ── ipset ──────────────────────────
if command -v ipset &>/dev/null; then
  HAS_IPSET=y
else
  HAS_IPSET=n
fi

# ── 3. точечная симметрия к up.sh (без глобальных flush/политик) ────────────
# снять хук INPUT → RZANS_INPUT и удалить цепи-«якоря»
ipt  -t filter -C INPUT -j RZANS_INPUT  2>/dev/null && ipt  -t filter -D INPUT -j RZANS_INPUT  || true
ipt  -t filter -F RZANS_INPUT  2>/dev/null || true
ipt  -t filter -X RZANS_INPUT  2>/dev/null || true
if [[ "$HAS_IP6" == y ]]; then
  ipt6 -t filter -C INPUT -j RZANS_INPUT6 2>/dev/null && ipt6 -t filter -D INPUT -j RZANS_INPUT6 || true
  ipt6 -t filter -F RZANS_INPUT6 2>/dev/null || true
  ipt6 -t filter -X RZANS_INPUT6 2>/dev/null || true
fi

# снять хук FORWARD → RZANS_FORWARD и удалить цепи-«якоря»
ipt  -t filter -C FORWARD -j RZANS_FORWARD  2>/dev/null && ipt  -t filter -D FORWARD -j RZANS_FORWARD  || true
ipt  -t filter -F RZANS_FORWARD  2>/dev/null || true
ipt  -t filter -X RZANS_FORWARD  2>/dev/null || true
if [[ "$HAS_IP6" == y ]]; then
  ipt6 -t filter -C FORWARD -j RZANS_FORWARD6 2>/dev/null && ipt6 -t filter -D FORWARD -j RZANS_FORWARD6 || true
  ipt6 -t filter -F RZANS_FORWARD6 2>/dev/null || true
  ipt6 -t filter -X RZANS_FORWARD6 2>/dev/null || true
fi

# hygiene-правила (conntrack INVALID) из up.sh
del  filter FORWARD -m conntrack --ctstate INVALID -j DROP
del  filter OUTPUT  -m conntrack --ctstate INVALID -j DROP
del6 filter FORWARD -m conntrack --ctstate INVALID -j DROP
del6 filter OUTPUT  -m conntrack --ctstate INVALID -j DROP

# OUTBOUND anti-abuse (порт-лист) — убрать ровно наши правила
for P in "${ABUSE_PORTS[@]}"; do
  del  filter OUTPUT -p tcp --dport "$P" -j REJECT --reject-with tcp-reset
  del  filter OUTPUT -p udp --dport "$P" -j DROP
  del6 filter OUTPUT -p tcp --dport "$P" -j REJECT --reject-with tcp-reset
  del6 filter OUTPUT -p udp --dport "$P" -j DROP
done

# anti-scan OUTPUT-ограничители (RST/ICMP dest-unreach)
del  filter OUTPUT -o "$INTERFACE" -p tcp --tcp-flags RST RST -j DROP
del  filter OUTPUT -o "$INTERFACE" -p icmp --icmp-type destination-unreachable -j DROP
del6 filter OUTPUT -o "$INTERFACE" -p tcp --tcp-flags RST RST -j DROP

# MSS clamp в mangle
del  mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
del6 mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# POSTROUTING→RZANS_NAT: снять хук и убрать нашу NAT-цепочку целиком
ipt -t nat -S POSTROUTING \
  | awk -v ch="RZANS_NAT" \
      '$0 ~ (" -A POSTROUTING ") && $0 ~ (" -j " ch "($| )") {sub(/^-A POSTROUTING /,""); print}' \
  | while IFS=' ' read -r -a SPEC; do ipt -t nat -D POSTROUTING "${SPEC[@]}" 2>/dev/null || true; done
ipt -t nat -F RZANS_NAT 2>/dev/null || true
ipt -t nat -X RZANS_NAT 2>/dev/null || true

# никаких глобальных flush’ей filter/nat/mangle и смены политик — оставляем как есть

# ── 4. снимаем /32-адреса, добавленные для SNAT ─────────────────────
declare -A EXT_DONE
for MAP in "${SNAT_MAP[@]}"; do
  IFS='=' read -r _ ext <<< "$MAP"
    # MASQUERADE-вариант / пустое поле адрес не создавал — пропускаем
    [[ "$ext" == "0.0.0.0" || -z "$ext" ]] && continue
    is_ip_v4 "$ext" || { echo "⚠ bad IP $ext — пропущен"; continue; }
    [[ -n ${EXT_DONE[$ext]+x} ]] && continue
  if ip -4 addr show dev "$INTERFACE" to "$ext"/32 &>/dev/null; then
      # shellcheck disable=SC2086
      ip addr del "$ext/32" dev "$INTERFACE" 2>/dev/null || true
  fi
  EXT_DONE[$ext]=1
done

# — fallback: если SNAT_MAP пуст (нет yq), снимем все /32 с метками snat_N и sN
base="${INTERFACE%%:*}"
ip -o -4 addr show dev "$INTERFACE" \
 | awk -v base="$base" '
    { split($4,a,"/"); ip=a[1]; lbl=""; 
      for(i=1;i<NF;i++) if($i=="label"){lbl=$(i+1)}
      if(lbl=="" && $0 ~ / scope global /){
        for(i=1;i<=NF;i++) if($i=="scope" && (i+1)<=NF && $(i+1)=="global"){lbl=$(i+2); break}
      }
      if(lbl ~ ("^" base ":snat_") || lbl ~ ("^" base ":s[0-9]+$")) print ip;
    }' \
 | while read -r ip4; do ip addr del "$ip4/32" dev "$INTERFACE" 2>/dev/null || true; done

# ── 4-bis. снять /32 loopback-IP, поднятые up.sh ────────────────────
for ip in "$KRESD2_IP" "$KRESD3_IP" "$KRESD4_IP" "$PROXY_IP" "$AGH_IP"; do
  ip -4 addr del "${ip}/32" dev lo 2>/dev/null || true
done
if [[ "$HAS_IP6" == y ]]; then
  ip -6 addr del ::2/128 dev lo 2>/dev/null || true
fi
# ── 5. сохраняем ipset-баны (сами сеты не удаляем — up.sh их переиспользует) ─
if [[ "$HAS_IPSET" == y ]]; then
  # 1) Сохраняем ТОЛЬКО динамические allow (без comment "src=settings")
  _TMP_ALLOW="$(mktemp)"
  ipset save 2>/dev/null \
    | awk '/^add (ipset-allow|ipset-allow6) / && $0 !~ /comment "src=settings"($| )/' \
    > "$_TMP_ALLOW" || true
  mv -f "$_TMP_ALLOW" "$IPSET_ALLOW_STATE"

  # 2) Удаляем временные наборы (watch/allow) — содержимое уже сохранено
  for S in ipset-watch ipset-watch6 ipset-allow ipset-allow6; do
      ipset flush   "$S" 2>/dev/null || true
      ipset destroy "$S" 2>/dev/null || true
  done

  # 3) Сохраняем ТОЛЬКО бан-листы (строки create/add для ipset-block{,6})
  : > "$IPSET_BAN_STATE"
  ipset save 2>/dev/null \
    | awk '/^(create|add) (ipset-block|ipset-block6) /' \
    > "$IPSET_BAN_STATE" || true

  # 4) DoT-наборы держать не обязательно — удалим для чистоты
  for S in ipset-dot ipset-dot6; do
    ipset flush "$S"   2>/dev/null || true
    ipset destroy "$S" 2>/dev/null || true
  done
fi

# ── 6. симметричный откат sysctl ───────────────────────────────────
if [[ -f "$SYSCTL_FILE" ]]; then
  rm -f "$SYSCTL_FILE"
  sysctl --system >/dev/null || true
  # Если ключи не заданы в других sysctl-конфигах, вернуть к безопасным дефолтам
  _has_key() {
    grep -Rqs "^[[:space:]]*$1[[:space:]]*=" /etc/sysctl.conf "${SYSCTL_DIR}" 2>/dev/null
  }
  _has_key "net.ipv4.ip_forward" || sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
  _has_key "net.ipv4.conf.all.route_localnet" || sysctl -w net.ipv4.conf.all.route_localnet=0 >/dev/null 2>&1 || true
  # откат остальных рантайм‑тюнов, если не зафиксированы в других конфиг‑файлах
  _has_key "kernel.printk"                || sysctl -w kernel.printk="4 4 1 7"        >/dev/null 2>&1 || true
  _has_key "net.core.default_qdisc"       || sysctl -w net.core.default_qdisc=pfifo_fast >/dev/null 2>&1 || true
  _has_key "net.ipv4.tcp_congestion_control" || sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1 || true
  # симметрия с up.sh: вернуть rp_filter к дефолту, если не задан в других конфигах
  _has_key "net.ipv4.conf.all.rp_filter"     || sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
  _has_key "net.ipv4.conf.default.rp_filter" || sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
  # syncookies: не понижаем безопасность — возвращаем 1, если не переопределено где-то ещё
  _has_key "net.ipv4.tcp_syncookies" || sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 || true

  # IPv4 source route
  _has_key "net.ipv4.conf.all.accept_source_route"     || sysctl -w net.ipv4.conf.all.accept_source_route=0 >/dev/null 2>&1 || true
  _has_key "net.ipv4.conf.default.accept_source_route" || sysctl -w net.ipv4.conf.default.accept_source_route=0 >/dev/null 2>&1 || true
  # IPv6 source route (в up.sh они ставятся в 0 — фиксируем явный откат)
  _has_key "net.ipv6.conf.all.accept_source_route"     || sysctl -w net.ipv6.conf.all.accept_source_route=0 >/dev/null 2>&1 || true
  _has_key "net.ipv6.conf.default.accept_source_route" || sysctl -w net.ipv6.conf.default.accept_source_route=0 >/dev/null 2>&1 || true
  # IPv4 ICMP (в up.sh =1; оставляем 1, если не переопределено)
  _has_key "net.ipv4.icmp_echo_ignore_broadcasts"      || sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null 2>&1 || true
  _has_key "net.ipv4.icmp_ignore_bogus_error_responses"|| sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 >/dev/null 2>&1 || true
fi

# ── 7. сбросить хэш смарт-кэша (чтобы следующий up.sh гарантированно заметил изменения)
rm -f "${RUN_DIR}/cache_hash" 2>/dev/null || true

# явный маркер успешного завершения
echo "down: done"
