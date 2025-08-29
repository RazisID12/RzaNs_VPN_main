#!/usr/bin/env bash
# Up-script (structured: skeleton -> dynamic -> finalize)
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

# === settings & global lock ===================================================
. /opt/rzans_vpn_main/settings/settings.sh      # yaml_get / yaml_bool / _yaml_merged

if declare -F _ensure_settings_lock >/dev/null; then
  __UP_HAD_LOCK=0
  [[ -n "${_SETTINGS_LOCK_FD:-}" ]] && __UP_HAD_LOCK=1
  _ensure_settings_lock || { echo "settings lock busy: another apply is running" >&2; exit 1; }
  __UP_LOCK_ACTIVE=0
  [[ $__UP_HAD_LOCK -eq 0 ]] && __UP_LOCK_ACTIVE=1
  if [[ $__UP_HAD_LOCK -eq 1 ]] && declare -F _release_settings_lock >/dev/null; then
    _release_settings_lock() { :; }
  fi
  _up_unlock() {
    if [[ "${__UP_LOCK_ACTIVE:-0}" -eq 1 ]]; then
      _release_settings_lock || true
    fi
  }
else
  echo "⚠ _ensure_settings_lock not found in settings.sh — running without global lock" >&2
  _up_unlock() { :; }
fi

# единый обработчик выхода: снимаем лок; при успехе отменяем at-fallback
_on_exit() {
  local ec=$?
  _up_unlock
  if [[ $ec -eq 0 && -n "${AT_JOB_ID:-}" ]] && command -v atrm &>/dev/null; then
    atrm "$AT_JOB_ID" || true
  fi
}
trap _on_exit EXIT

# === prepare (heal + автозаполнение + agh/kresd косметика) ===================
# Делаем это ПОД локом и ДО любых read_settings.
if declare -F prepare_main >/dev/null; then
  echo "[up] prepare_main: start" >&2
  if ! prepare_main; then
    echo "[up] prepare_main: FAILED — aborting" >&2
    exit 1
  fi
  echo "[up] prepare_main: ok" >&2
else
  # fallback, если функций нет в окружении
  /opt/rzans_vpn_main/settings/settings.sh --prepare || {
    echo "[up] settings.sh --prepare: FAILED — aborting" >&2
    exit 1
  }
fi

# === constants ================================================================
mkdir -p /var/lib/ipset
IPSET_BAN_STATE=/var/lib/ipset/ipset-bans.rules
IPSET_ALLOW_STATE=/var/lib/ipset/ipset-allow.rules

# — fixed outbound «abuse» ports (used in up/down)
#   keep this list in sync with down.sh
ABUSE_PORTS=(25 465 587 2525 23 21 69 135 137 138 139 445 1900 6666 6667 6668 6669)

# === shell / env guards =======================================================
set -eEuo pipefail
trap 'echo "ERR on line $LINENO – cmd: $BASH_COMMAND" >&2; exit 1' ERR
shopt -s expand_aliases
YQ_BIN=${YQ_BIN:-yq}
FIREWALL_DIR=${FIREWALL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}

# --- choose iptables backend consistently (nft pinned) ---
IPT_BIN=$(command -v iptables-nft || command -v iptables || true)
IP6T_BIN=$(command -v ip6tables-nft || command -v ip6tables || true)
if [[ -x "$IPT_BIN" ]]; then
  echo "Using iptables backend: $("$IPT_BIN" -V)" >&2
else
  echo "ERROR: iptables backend not found" >&2
  exit 1
fi
alias ipt="$IPT_BIN -w"
HAS_IP6=n
if [[ -x "$IP6T_BIN" ]]; then HAS_IP6=y; fi
ipt6() { if [[ $HAS_IP6 == y ]]; then "$IP6T_BIN" -w "$@"; else return 0; fi; }

# === capability probe (one-time) =============================================
# Наличие ipset и xt-модулей для v4/v6 — используем флаги CAP_* везде ниже
CAP_IPSET=n; CAP_SET4=n; CAP_SET6=n; CAP_OWNER4=n; CAP_OWNER6=n
_have ipset && CAP_IPSET=y
"$IPT_BIN"  -m set   -h >/dev/null 2>&1 && CAP_SET4=y
[[ "$HAS_IP6" == y ]] && "$IP6T_BIN" -m set   -h >/dev/null 2>&1 && CAP_SET6=y
"$IPT_BIN"  -m owner -h >/dev/null 2>&1 && CAP_OWNER4=y
[[ "$HAS_IP6" == y ]] && "$IP6T_BIN" -m owner -h >/dev/null 2>&1 && CAP_OWNER6=y

# === helpers ==================================================================
MAX_LABEL_LEN=15  # IFNAMSIZ-1: максимальная длина label "iface:alias"
is_ip_v4()   { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]; }
is_ip_v6()   { [[ $1 =~ ^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(::)|(::ffff:(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$ ]]; }
is_cidr_v4() { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[12]?[0-9])$ ]]; }
is_v4_or_cidr(){ is_ip_v4 "$1" || is_cidr_v4 "$1"; }
is_cidr_v6(){ [[ $1 =~ ^([0-9A-Fa-f]{0,4}:){1,7}(:|[0-9A-Fa-f]{1,4})/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$ ]]; }
is_v6_or_cidr(){ is_ip_v6 "$1" || is_cidr_v6 "$1"; }

ins()  { local t=$1 c=$2; shift 2; ipt  -t "$t" -C "$c" "$@" 2>/dev/null || ipt  -t "$t" -I "$c" 1 "$@"; }
ins6() { local t=$1 c=$2; shift 2; ipt6 -t "$t" -C "$c" "$@" 2>/dev/null || ipt6 -t "$t" -I "$c" 1 "$@"; }
add()  { local t=$1 c=$2; shift 2; ipt  -t "$t" -C "$c" "$@" 2>/dev/null || ipt  -t "$t" -A "$c"   "$@"; }
add6() { local t=$1 c=$2; shift 2; ipt6 -t "$t" -C "$c" "$@" 2>/dev/null || ipt6 -t "$t" -A "$c"   "$@"; }

ensure_chain4(){ ipt  -t "$1" -N "$2" 2>/dev/null || true; ipt  -t "$1" -F "$2"; }   # для ЧИСТО динамических цепей (ok to flush)
ensure_chain6(){ ipt6 -t "$1" -N "$2" 2>/dev/null || true; ipt6 -t "$1" -F "$2"; }
create_chain4(){ ipt  -t "$1" -N "$2" 2>/dev/null || true; }                          # create-only (без flush)
create_chain6(){ ipt6 -t "$1" -N "$2" 2>/dev/null || true; }
hook4(){ ipt  -t "$1" -C "$2" -j "$3" 2>/dev/null || ipt  -t "$1" -I "$2" 1 -j "$3"; }
hook6(){ ipt6 -t "$1" -C "$2" -j "$3" 2>/dev/null || ipt6 -t "$1" -I "$2" 1 -j "$3"; }

list_label_indices() {
  # Печатает занятые индексы для меток с данным префиксом (например, "eth0:snat_" или "eth0:s")
  local prefix="$1"
  ip -o -4 addr show dev "$INTERFACE" 2>/dev/null \
    | awk -v pfx="$prefix" '
        {
          l="";
          # 1) Если есть явный токен "label <NAME>"
          for (i=1;i<NF;i++) if ($i=="label") { l=$(i+1); break }
          # 2) Иначе берём имя после "scope global" с пропуском обычных флагов
          if (l=="") {
            for (i=1;i<=NF;i++) if ($i=="scope" && (i+1)<=NF && $(i+1)=="global") {
              j=i+2;
              while (j<=NF && $(j) ~ /^(dynamic|secondary|deprecated|tentative|mngtmpaddr|noprefixroute|permanent)$/) j++;
              if (j<=NF) l=$(j);
              break;
            }
          }
          if (l!="" && index(l,pfx)==1) {
            n=substr(l, length(pfx)+1);
            if (n ~ /^[0-9]+$/) print n;
          }
        }
      ' | sort -n | uniq
}

next_label_index() {
  # Возвращает минимально свободный N для меток с данным префиксом
  local prefix="$1" idx=1 n
  while read -r n; do
    [[ -z "$n" ]] && continue
    if [[ "$n" -eq "$idx" ]]; then
      ((idx++))
    elif [[ "$n" -gt "$idx" ]]; then
      break
    fi
  done < <(list_label_indices "$prefix")
  echo "$idx"
}

# del_by_comment [TABLE] CHAIN [CHAIN6] REGEX  (backward compatible)
del_by_comment(){
  local table="filter" c4 c6 pat
  case "${1:-}" in filter|nat|mangle|raw|security) table="$1"; shift;; esac
  case "$#" in
    2) c4="$1"; c6="$1"; pat="$2";;
    3) c4="$1"; c6="$2"; pat="$3";;
    *) return 0;;
  esac
  { ipt  -t "$table" -S "$c4" 2>/dev/null || true; } | awk -v p="$pat" '$0~p && $0~/^-A /{sub(/^-A /,"-D ");print}' \
    | while read -r L; do ipt  -t "$table" $L || true; done
  { ipt6 -t "$table" -S "$c6" 2>/dev/null || true; } | awk -v p="$pat" '$0~p && $0~/^-A /{sub(/^-A /,"-D ");print}' \
    | while read -r L; do ipt6 -t "$table" $L || true; done
}

# --- atd ensure ---------------------------------------------------------------
ensure_atd() {
  if _have systemctl; then
    systemctl is-active --quiet atd || systemctl start atd 2>/dev/null || true
    sleep 1
    systemctl is-active --quiet atd
    return $?
  fi
  pgrep -x atd >/dev/null 2>&1 && return 0
  if _have service; then
    service atd start 2>/dev/null || service cron start 2>/dev/null || true
    sleep 1
    pgrep -x atd >/dev/null 2>&1 && return 0
  fi
  _have at
}

# --- point targets that depend on YAML ---------------------------------------
fw_apply_ssh(){
  read_settings
  create_chain4 filter RZANS_INPUT;  create_chain6 filter RZANS_INPUT6
  del_by_comment RZANS_INPUT  RZANS_INPUT6 'RZANS_SSH_ALLOW(6)?|RZANS_SSH_ALLOW_ANY'
  del_by_comment RZANS_INPUT  RZANS_INPUT6 'RZANS_SSH_BOOT(4|6)?'
  if [[ "$CAP_SET4" == y ]]; then
    ins  filter RZANS_INPUT  -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow  src -m comment --comment RZANS_SSH_ALLOW  -j ACCEPT
  else
    echo "⚠ ipset/xt_set недоступны — SSH по v4 временно открыт, по v6 оставлен закрытым" >&2
    ins  filter RZANS_INPUT  -p tcp --dport "$SSH_PORT" -m comment --comment RZANS_SSH_ALLOW_ANY  -j ACCEPT
    # v6: не добавляем allow-any, чтобы сохранить политику «закрыто без доверенных»
  fi
  if [[ "$CAP_SET6" == y ]]; then
    ins6 filter RZANS_INPUT6 -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow6 src -m comment --comment RZANS_SSH_ALLOW6 -j ACCEPT
  fi
}

fw_apply_vpn_ports(){
  read_settings
  create_chain4 filter RZANS_INPUT; create_chain6 filter RZANS_INPUT6
  del_by_comment RZANS_INPUT RZANS_INPUT6 '(RZANS_VPN_SPORT(6)?|RZANS_VPN_FPORT(6)?)'
  ins  filter RZANS_INPUT  -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT  -j ACCEPT
  ins6 filter RZANS_INPUT6 -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT6 -j ACCEPT
  ins  filter RZANS_INPUT  -p udp --dport "$FVPN_PORT" -m comment --comment RZANS_VPN_FPORT  -j ACCEPT
  ins6 filter RZANS_INPUT6 -p udp --dport "$FVPN_PORT" -m comment --comment RZANS_VPN_FPORT6 -j ACCEPT
}

fw_apply_dot_port(){
  read_settings
  local DOT="${DOT_PORT:-853}" KUID
  KUID="$(id -u knot-resolver 2>/dev/null || id -u kresd 2>/dev/null || echo '')"
  del_by_comment OUTPUT OUTPUT 'RZANS_DOT_(ALLOW|REJECT)6?'
  if [[ -n "$KUID" && "$CAP_OWNER4" == y ]]; then
    if [[ "$CAP_SET4" == y ]]; then
      ins  filter OUTPUT -p tcp --dport "$DOT" -m owner --uid-owner "$KUID" -m set --match-set ipset-dot  dst -m comment --comment RZANS_DOT_ALLOW  -j ACCEPT
      [[ "$CAP_OWNER6" == y && "$CAP_SET6" == y ]] \
        && ins6 filter OUTPUT -p tcp --dport "$DOT" -m owner --uid-owner "$KUID" -m set --match-set ipset-dot6 dst -m comment --comment RZANS_DOT_ALLOW6 -j ACCEPT
    else
      ins  filter OUTPUT -p tcp --dport "$DOT" -m owner --uid-owner "$KUID" -m comment --comment RZANS_DOT_ALLOW  -j ACCEPT
      [[ "$CAP_OWNER6" == y ]] \
        && ins6 filter OUTPUT -p tcp --dport "$DOT" -m owner --uid-owner "$KUID" -m comment --comment RZANS_DOT_ALLOW6 -j ACCEPT
    fi
  else
    if [[ "$CAP_SET4" == y ]]; then
      ins  filter OUTPUT -p tcp --dport "$DOT" -m set --match-set ipset-dot  dst -m comment --comment RZANS_DOT_ALLOW  -j ACCEPT
      [[ "$CAP_SET6" == y ]] \
        && ins6 filter OUTPUT -p tcp --dport "$DOT" -m set --match-set ipset-dot6 dst -m comment --comment RZANS_DOT_ALLOW6 -j ACCEPT
    else
      echo "⚠ Ни owner-match, ни ipset — пропускаю без узкого allow (только общий REJECT ниже)" >&2
    fi
  fi
  [[ "$DOT" = "443" ]] || {
    add  filter OUTPUT -p tcp --dport "$DOT" -m comment --comment RZANS_DOT_REJECT  -j REJECT --reject-with tcp-reset
    add6 filter OUTPUT -p tcp --dport "$DOT" -m comment --comment RZANS_DOT_REJECT6 -j REJECT --reject-with tcp-reset
  }
}

fw_apply_dns_map(){
  read_settings
  ensure_chain4 nat RZANS_DNS_S; ensure_chain4 nat RZANS_DNS_F   # это НАШИ динамические цепи — тут flush ок
  # убрать старые хуки PREROUTING на наши DNS-цепи (если сети менялись)
  del_by_comment nat PREROUTING PREROUTING 'RZANS_DNS_HOOK_(S|F)'
  local P
  for P in udp tcp; do
    ipt -t nat -C PREROUTING -s "$SVPN_NET4" -p "$P" --dport 53 \
      -m comment --comment RZANS_DNS_HOOK_S -j RZANS_DNS_S 2>/dev/null \
      || ipt -t nat -I PREROUTING 1 -s "$SVPN_NET4" -p "$P" --dport 53 \
         -m comment --comment RZANS_DNS_HOOK_S -j RZANS_DNS_S
    ipt -t nat -C PREROUTING -s "$FVPN_NET4" -p "$P" --dport 53 \
      -m comment --comment RZANS_DNS_HOOK_F -j RZANS_DNS_F 2>/dev/null \
      || ipt -t nat -I PREROUTING 1 -s "$FVPN_NET4" -p "$P" --dport 53 \
         -m comment --comment RZANS_DNS_HOOK_F -j RZANS_DNS_F
  done
  if [[ "$ADGUARD_HOME" == y ]]; then
    ipt -t nat -A RZANS_DNS_S -p udp -j DNAT --to-destination "${AGH_IP}:${DNS_PORT}"
    ipt -t nat -A RZANS_DNS_S -p tcp -j DNAT --to-destination "${AGH_IP}:${DNS_PORT}"
    ipt -t nat -A RZANS_DNS_F -p udp -j DNAT --to-destination "${AGH_IP}:${DNS_PORT}"
    ipt -t nat -A RZANS_DNS_F -p tcp -j DNAT --to-destination "${AGH_IP}:${DNS_PORT}"
  else
    ipt -t nat -A RZANS_DNS_S -p udp -j DNAT --to-destination "${KRESD3_IP}:${DNS_PORT}"
    ipt -t nat -A RZANS_DNS_S -p tcp -j DNAT --to-destination "${KRESD3_IP}:${DNS_PORT}"
    ipt -t nat -A RZANS_DNS_F -p udp -j DNAT --to-destination "${KRESD4_IP}:${DNS_PORT}"
    ipt -t nat -A RZANS_DNS_F -p tcp -j DNAT --to-destination "${KRESD4_IP}:${DNS_PORT}"
  fi

  # после DNAT всегда синхронизируем INPUT-allow для DNS-прослушивания
  fw_apply_dns_listen
}

#
# ЕДИНЫЙ апдейтер INPUT-правил для DNS-прослушивания (без дублей)
#
fw_apply_dns_listen(){
  read_settings
  create_chain4 filter RZANS_INPUT
  create_chain6 filter RZANS_INPUT6
  local NET _t TGT_RE
  # 1) убрать наши прошлые правила по комменту
  del_by_comment RZANS_INPUT RZANS_INPUT6 'RZANS_DNS_LISTEN(6)?'
  # 3) добавить актуальные правила в едином стиле (с комментом)
  if [[ "$ADGUARD_HOME" == y ]]; then
    while IFS= read -r NET; do
      is_cidr_v4 "$NET" || continue
      ins filter RZANS_INPUT -d "$AGH_IP"  -p udp --dport "$DNS_PORT" -s "$NET" -m comment --comment RZANS_DNS_LISTEN  -j ACCEPT
      ins filter RZANS_INPUT -d "$AGH_IP"  -p tcp --dport "$DNS_PORT" -s "$NET" -m comment --comment RZANS_DNS_LISTEN  -j ACCEPT
    done < <(all_dns)
  else
    while IFS= read -r NET; do
      is_cidr_v4 "$NET" || continue
      ins filter RZANS_INPUT -d "$KRESD3_IP" -p udp --dport "$DNS_PORT" -s "$NET" -m comment --comment RZANS_DNS_LISTEN  -j ACCEPT
      ins filter RZANS_INPUT -d "$KRESD3_IP" -p tcp --dport "$DNS_PORT" -s "$NET" -m comment --comment RZANS_DNS_LISTEN  -j ACCEPT
    done < <(split_nets_v4)
    while IFS= read -r NET; do
      is_cidr_v4 "$NET" || continue
      ins filter RZANS_INPUT -d "$KRESD4_IP" -p udp --dport "$DNS_PORT" -s "$NET" -m comment --comment RZANS_DNS_LISTEN  -j ACCEPT
      ins filter RZANS_INPUT -d "$KRESD4_IP" -p tcp --dport "$DNS_PORT" -s "$NET" -m comment --comment RZANS_DNS_LISTEN  -j ACCEPT
    done < <(full_nets_v4)
  fi
}

fw_apply_mapping(){
  read_settings
  ipt -t nat -N RZANS_VPN_MAIN-MAPPING 2>/dev/null || true
  # убрать прежние прыжки по нашему комменту
  del_by_comment nat PREROUTING PREROUTING 'RZANS_MAP_HOOK'
  ipt -t nat -C PREROUTING -s "$VPN_MAP_SRC4" -d "$VPN_MAP_DST4" \
      -m comment --comment RZANS_MAP_HOOK -j RZANS_VPN_MAIN-MAPPING 2>/dev/null || \
    ipt -t nat -A PREROUTING -s "$VPN_MAP_SRC4" -d "$VPN_MAP_DST4" \
      -m comment --comment RZANS_MAP_HOOK -j RZANS_VPN_MAIN-MAPPING
}

fw_apply_snat(){
  read_settings
  # fast-path compatibility: ensure INTERFACE is available even if called early
  if [[ -z "${INTERFACE:-}" ]]; then
    INTERFACE="$(server_iface)"
  fi
  del_by_comment nat POSTROUTING POSTROUTING 'RZANS_SNAT'
  local MAP SRC EXT
  for MAP in "${SNAT_MAP[@]}"; do
    IFS='=' read -r SRC EXT <<< "$MAP"
    is_ip_v4 "$SRC" || continue
    [[ -n "$EXT" && "$EXT" != "0.0.0.0" ]] || continue
    is_ip_v4 "$EXT" || continue
    add nat POSTROUTING -s "${SRC}/32" -o "$INTERFACE" \
        -m comment --comment RZANS_SNAT \
        -j SNAT --to-source "$EXT"
  done
}

fw_apply_nets(){
  read_settings
  local NET
  while IFS= read -r NET; do
    is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (FWD) — пропущен"; continue; }
    ins filter RZANS_FORWARD -s "$NET" -j ACCEPT
    ins filter RZANS_FORWARD -d "$NET" -j ACCEPT
  done < <(all_forward)
}

wg_listen_ports(){
  read_settings
  command -v wg >/dev/null || return 0
  local cur
  if ip link show rzans_svpn_main &>/dev/null; then
    cur=$(wg show rzans_svpn_main listen-port 2>/dev/null || true)
    [[ "$cur" != "$SVPN_PORT" ]] && wg set rzans_svpn_main listen-port "$SVPN_PORT" || true
  fi
  if ip link show rzans_fvpn_main &>/dev/null; then
    cur=$(wg show rzans_fvpn_main listen-port 2>/dev/null || true)
    [[ "$cur" != "$FVPN_PORT" ]] && wg set rzans_fvpn_main listen-port "$FVPN_PORT" || true
  fi
}

# --- settings read ------------------------------------------------------------
read_settings() {
  SSH_PORT="$(yaml_get_port 'server.port_ssh' 22)"
  ADGUARD_HOME="$(yaml_bool 'adguard_home.enable')"

  SVPN_PORT="$(yaml_get_port 'vpn.ports.split' 500)"
  FVPN_PORT="$(yaml_get_port 'vpn.ports.full'  4500)"

  SVPN_NET4="$(yaml_get 'vpn.nets.split' '10.29.8.0/24')"
  FVPN_NET4="$(yaml_get 'vpn.nets.full'  '10.28.8.0/24')"

  KRESD1_IP="${KRESD1_IP:-127.0.0.1}"
  KRESD2_IP="${KRESD2_IP:-127.0.0.2}"
  KRESD3_IP="${KRESD3_IP:-127.0.0.3}"
  KRESD4_IP="${KRESD4_IP:-127.0.0.4}"
  PROXY_IP="${PROXY_IP:-127.0.0.5}"
  AGH_IP="${AGH_IP:-127.0.0.6}"
  DNS_PORT="${DNS_PORT:-53}"

  readarray -t SNAT_MAP < <(
    _yaml_merged \
    | "$YQ_BIN" e -r '
        .snat // []
        | .[]
        | .internal + "=" +
          (( .external | select(. != "") ) // "0.0.0.0")
      ' - \
    | tr -d ' \t\r' | awk '!seen[$0]++'
  )

  [[ -z "$SVPN_NET4" ]] && SVPN_NET4="10.29.8.0/24"
  [[ -z "$FVPN_NET4" ]] && FVPN_NET4="10.28.8.0/24"

  all_dns()       { printf '%s\n' "$SVPN_NET4" "$FVPN_NET4"; }
  all_forward()   { printf '%s\n' "$SVPN_NET4" "$FVPN_NET4"; }
  all_postroute() { printf '%s\n' "$SVPN_NET4" "$FVPN_NET4"; }

  split_nets_v4() { printf '%s\n' "$SVPN_NET4"; }
  full_nets_v4()  { printf '%s\n' "$FVPN_NET4"; }

  vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" \
    || { echo "Bad SVPN_NET4/FVPN_NET4"; exit 1; }
  [[ -z "${SVPN_IP:-}" || -z "${FVPN_IP:-}" ]] && {
    echo "SVPN_IP/FVPN_IP not set by vpn_addrs_from_cidrs"; exit 1;
  }

  VPN_MAP_SRC4="$(yaml_get 'vpn.nets.split' "$SVPN_NET4")"
  VPN_MAP_DST4="$(yaml_get 'vpn.map_dns' '10.30.0.0/15')"

  read -r DOT_URL DOT_PORT < <(yaml_dot)
}

# === fast-path CLI ============================================================
case "${1:-}" in
  --flush-mapping)
    # safe: цепь может и не существовать (первый запуск/другой бэкенд)
    ipt  -t nat -F RZANS_VPN_MAIN-MAPPING 2>/dev/null || true
    ipt6 -t nat -F RZANS_VPN_MAIN-MAPPING 2>/dev/null || true
    exit 0 ;;
  --fw-ssh)        fw_apply_ssh; exit $? ;;
  --fw-vpn-ports)  fw_apply_vpn_ports; exit $? ;;
  --fw-dot-port)   fw_apply_dot_port; exit $? ;;
  --dns-map)       fw_apply_dns_map; exit $? ;;
  --dns-listen)    fw_apply_dns_listen; exit $? ;;
  --fw-mapping)    fw_apply_mapping; exit $? ;;
  --vpn-snat)      fw_apply_snat; exit $? ;;
  --wg-listen-ports) wg_listen_ports; exit $? ;;
  --fw-nets)       fw_apply_nets; exit $? ;;
esac

# === early settings (for fallback), iface & IPs ===============================
read_settings
INTERFACE="$(server_iface)"
[[ -z $INTERFACE ]] && { echo "Cannot determine external interface"; exit 1; }

EXT4_IP="$(server_ip4 30)"; export EXT4_IP
EXT6_IP="$(server_ip6 30)"; export EXT6_IP
if [[ "$EXT4_IP" == "0.0.0.0" ]]; then
  echo "No global IPv4 on $INTERFACE after 30 s – aborting" >&2; exit 1
fi

# === schedule fallback BEFORE changes ========================================
FALLBACK_OK=n
if command -v at &>/dev/null && ensure_atd; then FALLBACK_OK=y; else
  echo "⚠ 'at' или atd недоступны – аварийный откат не будет запланирован." >&2
fi

AT_JOB_ID=""
if [[ "$FALLBACK_OK" == y ]]; then
  FALLBACK_MIN=3
  AT_SIG="RZANS_FALLBACK_rzans_vpn_main"
  for jid in $(at -q Z -l | awk '$1 ~ /^[0-9]+$/ {print $1}'); do
    if at -c "$jid" 2>/dev/null | grep -Fq "$AT_SIG"; then atrm "$jid" || true; fi
  done
  WORD=$([[ $FALLBACK_MIN -eq 1 ]] && echo minute || echo minutes)
  AT_JOB_ID="$(
    LC_ALL=C at -q Z now + ${FALLBACK_MIN} ${WORD} 2>&1 <<AT_EOF | awk '/^job [0-9]+ at /{print $2; exit}'
# RZANS_FALLBACK_rzans_vpn_main
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${IPT_BIN} -w -F
${IPT_BIN} -w -t nat -F
${IPT_BIN} -w -t mangle -F
${IPT_BIN} -w -P INPUT   DROP
${IPT_BIN} -w -P FORWARD DROP
${IPT_BIN} -w -P OUTPUT  ACCEPT
${IPT_BIN} -w -A INPUT -i lo -j ACCEPT
${IPT_BIN} -w -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
${IPT_BIN} -w -A INPUT -p tcp --dport ${SSH_PORT} -j ACCEPT
${IPT_BIN} -w -A INPUT -p udp --dport ${SVPN_PORT} -j ACCEPT
${IPT_BIN} -w -A INPUT -p udp --dport ${FVPN_PORT} -j ACCEPT

if command -v ipset >/dev/null; then
  if [ -s "$IPSET_BAN_STATE" ]; then
    ipset flush ipset-block  2>/dev/null || true
    ipset flush ipset-block6 2>/dev/null || true
    ipset restore -exist < "$IPSET_BAN_STATE" || true
    ${IPT_BIN} -w -I INPUT 1 -m set --match-set ipset-block src -j DROP
  fi
fi

if command -v ip6tables-nft >/dev/null 2>&1 || command -v ip6tables >/dev/null 2>&1; then
  IP6T_BIN="$(command -v ip6tables-nft || command -v ip6tables)"
  ${IP6T_BIN} -w -F
  ${IP6T_BIN} -w -t nat    -F 2>/dev/null || true
  ${IP6T_BIN} -w -t mangle -F 2>/dev/null || true
  ${IP6T_BIN} -w -P INPUT   DROP
  ${IP6T_BIN} -w -P FORWARD DROP
  ${IP6T_BIN} -w -P OUTPUT  ACCEPT
  ${IP6T_BIN} -w -A INPUT -i lo -j ACCEPT
  ${IP6T_BIN} -w -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ${IP6T_BIN} -w -A INPUT  -p icmpv6 -j ACCEPT
  if command -v ipset >/dev/null 2>&1; then
    ipset list ipset-block6 >/dev/null 2>&1 && \
      ${IP6T_BIN} -w -I INPUT 1 -m set --match-set ipset-block6 src -j DROP
  fi
fi
AT_EOF
  )" || AT_JOB_ID=""

  if [[ -z "$AT_JOB_ID" ]]; then
    echo "⚠ couldn't parse AT job id; removing only our queued fallback from Z." >&2
    for jid in $(at -q Z -l | awk '$1 ~ /^[0-9]+$/ {print $1}'); do
      if at -c "$jid" 2>/dev/null | grep -Fq "$AT_SIG"; then atrm "$jid" || true; fi
    done
  fi
fi

# мы закончили с ранними YAML-читателями → если лок брали мы, отпустим его рано
if [[ "${__UP_LOCK_ACTIVE:-0}" -eq 1 ]]; then
  _release_settings_lock || true
  __UP_LOCK_ACTIVE=0
fi

# === clean previous state =====================================================
"${FIREWALL_DIR}/down.sh" "$INTERFACE" || echo "down.sh returned non-zero, continuing"

# === PHASE 1: static skeleton (no YAML) ======================================
phase_static_skeleton() {
  local T
  # anchors & hooks (INPUT)
  ipt  -t filter -N RZANS_INPUT   2>/dev/null || true
  ipt  -t filter -F RZANS_INPUT
  hook4 filter INPUT RZANS_INPUT

  ipt6 -t filter -N RZANS_INPUT6  2>/dev/null || true
  ipt6 -t filter -F RZANS_INPUT6
  hook6 filter INPUT RZANS_INPUT6

  # anchors & hooks (FORWARD)
  ipt  -t filter -N RZANS_FORWARD   2>/dev/null || true
  ipt  -t filter -F RZANS_FORWARD
  hook4 filter FORWARD RZANS_FORWARD
  ipt6 -t filter -N RZANS_FORWARD6  2>/dev/null || true
  ipt6 -t filter -F RZANS_FORWARD6
  hook6 filter FORWARD RZANS_FORWARD6

  # base v4
  add  filter RZANS_INPUT -i lo -j ACCEPT
  add  filter RZANS_INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  add  filter RZANS_INPUT -m conntrack --ctstate INVALID -j DROP
  add  filter RZANS_INPUT -s 127.0.0.0/8 ! -i lo -j DROP

  # base v6
  add6 filter RZANS_INPUT6 -i lo -j ACCEPT
  add6 filter RZANS_INPUT6 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  add6 filter RZANS_INPUT6 -m conntrack --ctstate INVALID -j DROP
  add6 filter RZANS_INPUT6 -s ::1/128 ! -i lo -j DROP
  for T in 1 2 3 4 129 133 134 135 136 143 144 145; do
    add6 filter RZANS_INPUT6 -p icmpv6 --icmpv6-type "$T" -j ACCEPT
  done

  # sysctl (invariant)
  local SYSCTL_FILE="/etc/sysctl.d/99-rzans_vpn_main.conf"
  cat >"$SYSCTL_FILE" <<'EOF'
# autogenerated by up.sh (RzaNs_VPN_main)
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
kernel.printk = 3 4 1 3
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
  sysctl --load="$SYSCTL_FILE" >/dev/null 2>&1 || sysctl -q -p "$SYSCTL_FILE" || true
  sysctl -qw net.ipv4.conf.all.route_localnet=1 || true

  # DNS egress skeleton
  local KRESD_UID
  KRESD_UID="$(id -u knot-resolver 2>/dev/null || id -u kresd 2>/dev/null || echo '')"

  ipt -t filter -N RZANS_DNS_EGRESS 2>/dev/null || true
  ipt -t filter -F RZANS_DNS_EGRESS
  add  filter RZANS_DNS_EGRESS -d 127.0.0.0/8 -p udp --dport 53 -j ACCEPT
  add  filter RZANS_DNS_EGRESS -d 127.0.0.0/8 -p tcp --dport 53 -j ACCEPT
  if "$IPT_BIN" -m owner -h >/dev/null 2>&1 && [[ -n "$KRESD_UID" ]]; then
    add  filter RZANS_DNS_EGRESS ! -d 127.0.0.0/8 -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable
    add  filter RZANS_DNS_EGRESS ! -d 127.0.0.0/8 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
  else
    add  filter RZANS_DNS_EGRESS ! -d 127.0.0.0/8 -p udp --dport 53 -j DROP
    add  filter RZANS_DNS_EGRESS ! -d 127.0.0.0/8 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
  fi
  ins  filter OUTPUT -p udp --dport 53 -j RZANS_DNS_EGRESS
  ins  filter OUTPUT -p tcp --dport 53 -j RZANS_DNS_EGRESS

  if [[ "$HAS_IP6" == y ]]; then
    ipt6 -t filter -N RZANS_DNS6_EGRESS 2>/dev/null || true
    ipt6 -t filter -F RZANS_DNS6_EGRESS
    add6 filter RZANS_DNS6_EGRESS -d ::1/128 -p udp --dport 53 -j ACCEPT
    add6 filter RZANS_DNS6_EGRESS -d ::1/128 -p tcp --dport 53 -j ACCEPT
    add6 filter RZANS_DNS6_EGRESS -d ::2/128 -p udp --dport 53 -j ACCEPT
    add6 filter RZANS_DNS6_EGRESS -d ::2/128 -p tcp --dport 53 -j ACCEPT
    if "$IP6T_BIN" -m owner -h >/dev/null 2>&1 && [[ -n "$KRESD_UID" ]]; then
      add6 filter RZANS_DNS6_EGRESS ! -d ::1/128 ! -d ::2/128 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable
      add6 filter RZANS_DNS6_EGRESS ! -d ::1/128 ! -d ::2/128 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
    else
      add6 filter RZANS_DNS6_EGRESS ! -d ::1/128 ! -d ::2/128 -p udp --dport 53 -j DROP
      add6 filter RZANS_DNS6_EGRESS ! -d ::1/128 ! -d ::2/128 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
    fi
    ins6 filter OUTPUT -p udp --dport 53 -j RZANS_DNS6_EGRESS
    ins6 filter OUTPUT -p tcp --dport 53 -j RZANS_DNS6_EGRESS
  fi

  # ipset skeleton централизованно (создание базовых наборов)
  ipset_ensure_skeleton || true

  # hygiene
  ins filter FORWARD -m conntrack --ctstate INVALID -j DROP
  ins filter OUTPUT  -m conntrack --ctstate INVALID -j DROP
  ins6 filter FORWARD -m conntrack --ctstate INVALID -j DROP
  ins6 filter OUTPUT  -m conntrack --ctstate INVALID -j DROP

  # OUTBOUND anti-abuse (fixed list)
  local P
  for P in "${ABUSE_PORTS[@]}"; do
    ins  filter OUTPUT -p tcp --dport "$P" -j REJECT --reject-with tcp-reset
    ins  filter OUTPUT -p udp --dport "$P" -j DROP
    ins6 filter OUTPUT -p tcp --dport "$P" -j REJECT --reject-with tcp-reset
    ins6 filter OUTPUT -p udp --dport "$P" -j DROP
  done
  
  # inbound SMTP off (kept from old up.sh)
  add  filter RZANS_INPUT  -p tcp --dport 25 -j DROP
  add6 filter RZANS_INPUT6 -p tcp --dport 25 -j DROP

  # anti-scan skeleton
  if command -v ipset &>/dev/null; then
    if [[ "$CAP_SET4" == y ]]; then
      ins  filter RZANS_INPUT  -m set --match-set ipset-block src \
                               -m set ! --match-set ipset-allow src -j DROP
    else
      echo "⚠ xt_set(v4) отсутствует — anti-scan (v4 via ipset) пропущен" >&2
    fi
    if [[ "$CAP_SET6" == y ]]; then
      ins6 filter RZANS_INPUT6 -m set --match-set ipset-block6 src \
                               -m set ! --match-set ipset-allow6 src -j DROP
    else
      echo "⚠ xt_set(v6) отсутствует — anti-scan (v6 via ipset) пропущен" >&2
    fi
    ins  filter OUTPUT -o "$INTERFACE" -p tcp  --tcp-flags RST RST                 -j DROP
    ins  filter OUTPUT -o "$INTERFACE" -p icmp --icmp-type destination-unreachable -j DROP
    ins6 filter OUTPUT -o "$INTERFACE" -p tcp --tcp-flags RST RST -j DROP

    # === restore active ipset watch/ban rules (v4) ===
    [[ "$CAP_SET4" == y ]] && add filter RZANS_INPUT -m conntrack --ctstate NEW \
          -m set ! --match-set ipset-watch src,dst \
          -m set ! --match-set ipset-allow src \
          -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 \
		  --hashlimit-htable-expire 60000 \
          --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name scan-det \
          -j SET --add-set ipset-block src
    [[ "$CAP_SET4" == y ]] && add filter RZANS_INPUT -m conntrack --ctstate NEW \
          -m set ! --match-set ipset-allow src \
          -m hashlimit --hashlimit-above 10000/hour --hashlimit-burst 10000 \
		  --hashlimit-htable-expire 10000 \
          --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name ddos-det \
          -j SET --add-set ipset-block src
    [[ "$CAP_SET4" == y ]] && add filter RZANS_INPUT -m conntrack --ctstate NEW \
          -m set ! --match-set ipset-allow src \
          -j SET --add-set ipset-watch src,dst

    # === restore active ipset watch/ban rules (v6) ===
    [[ "$CAP_SET6" == y ]] && add6 filter RZANS_INPUT6 -m conntrack --ctstate NEW \
          -m set ! --match-set ipset-watch6 src,dst \
          -m set ! --match-set ipset-allow6 src \
          -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 \
		  --hashlimit-htable-expire 60000 \
          --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name scan6-det \
          -j SET --add-set ipset-block6 src
    [[ "$CAP_SET6" == y ]] && add6 filter RZANS_INPUT6 -m conntrack --ctstate NEW \
          -m set ! --match-set ipset-allow6 src \
          -m hashlimit --hashlimit-above 10000/hour --hashlimit-burst 10000 \
		  --hashlimit-htable-expire 10000 \
          --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name ddos6-det \
          -j SET --add-set ipset-block6 src
    [[ "$CAP_SET6" == y ]] && add6 filter RZANS_INPUT6 -m conntrack --ctstate NEW \
          -m set ! --match-set ipset-allow6 src \
          -j SET --add-set ipset-watch6 src,dst
  fi
  add  filter RZANS_INPUT  -p tcp --syn -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP
  add6 filter RZANS_INPUT6 -p tcp --syn -m connlimit --connlimit-above 20 --connlimit-mask 128 -j DROP
  add  filter RZANS_INPUT  -p tcp --tcp-flags ALL NONE            -j DROP
  add  filter RZANS_INPUT  -p tcp --tcp-flags ALL FIN,URG,PSH     -j DROP
  add  filter RZANS_INPUT  -p tcp --tcp-flags SYN,RST SYN,RST     -j DROP
  add6 filter RZANS_INPUT6 -p tcp --tcp-flags ALL NONE            -j DROP
  add6 filter RZANS_INPUT6 -p tcp --tcp-flags ALL FIN,URG,PSH     -j DROP
  add6 filter RZANS_INPUT6 -p tcp --tcp-flags SYN,RST SYN,RST     -j DROP

  # ICMP echo policy (drop defaults; allows will be inserted later via ins/ins6)
  add  filter RZANS_INPUT -i "$INTERFACE" -p icmp --icmp-type echo-request -j DROP
  add  filter RZANS_INPUT -p icmp --icmp-type 3  -m limit --limit 4/second --limit-burst 20 -j ACCEPT
  add  filter RZANS_INPUT -p icmp --icmp-type 4 -j DROP
  add  filter RZANS_INPUT -p icmp --icmp-type 11 -m limit --limit 4/second --limit-burst 20 -j ACCEPT
  add  filter RZANS_INPUT -i "$INTERFACE" -s 224.0.0.0/3   -j DROP
  add  filter RZANS_INPUT -i "$INTERFACE" -s 169.254.0.0/16 -j DROP

  add6 filter RZANS_INPUT6 -i "$INTERFACE" -s ff00::/8 -j DROP
  add6 filter RZANS_INPUT6 -i "$INTERFACE" -p icmpv6 --icmpv6-type 128 -j DROP
  add6 filter RZANS_INPUT6 -i "$INTERFACE" -m addrtype --dst-type MULTICAST ! -p icmpv6 -j DROP

  # mangle MSS
  ins  mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  ins6 mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}
phase_static_skeleton

# === PHASE 2: dynamic from settings ==========================================
phase_dynamic_from_settings() {
  read_settings

  # service loopback IPs (settings-driven)
  local _loip
  for _loip in "$KRESD2_IP" "$KRESD3_IP" "$KRESD4_IP" "$PROXY_IP" "$AGH_IP"; do
    [[ -n "$_loip" ]] || continue
    ip -4 addr add "${_loip}/32" dev lo 2>/dev/null || true
  done
  [[ "$HAS_IP6" == y ]] && ip -6 addr add ::2/128 dev lo 2>/dev/null || true

  # ipset state restore + allow sync + dot sync (единая логика из settings.sh)
  if _have ipset; then
    if [ -s "$IPSET_BAN_STATE" ]; then
      ipset flush ipset-block  2>/dev/null || true
      ipset flush ipset-block6 2>/dev/null || true
      ipset restore -exist < "$IPSET_BAN_STATE" || true
    fi
    # 1) Restore сохранённого allow-состояния (если было)
    [ -s "$IPSET_ALLOW_STATE" ] && ipset restore -exist < "$IPSET_ALLOW_STATE" || true
    # 2) Единая синхронизация allow-наборов из settings.yaml (и обратная «усыновительная» синхронизация)
    allow_sync_ipsets || true
    # 3) Синхронизация DoT-наборов по dns.upstream
    dot_ipset_sync   || true
  fi

  # Bootstrap SSH (temp allow if allow-set empty)
  if _have ipset; then
    local cnt4
    cnt4=$(ipset list ipset-allow  2>/dev/null | awk '/Number of entries:/{print $4; exit}'); cnt4=${cnt4:-0}
    if (( cnt4==0 )); then
      add  filter RZANS_INPUT  -p tcp --dport "$SSH_PORT" -m comment --comment RZANS_SSH_BOOT4 -j ACCEPT
    else
      ipt  -t filter -D RZANS_INPUT  -p tcp --dport "$SSH_PORT" -m comment --comment RZANS_SSH_BOOT4 -j ACCEPT 2>/dev/null || true
    fi
  fi

  # flexible blocks (динамика)
  fw_apply_dot_port
  fw_apply_vpn_ports

  # transit
  fw_apply_nets

  # allow ping (rate-limited) for allow-sets — гарантированно выше DROP (ins/ins6)
  if _have ipset; then
    if [[ "$CAP_SET4" == y ]]; then
      ins  filter RZANS_INPUT  -p icmp  --icmp-type echo-request \
           -m set --match-set ipset-allow src \
           -m limit --limit 4/second --limit-burst 20 -j ACCEPT
    fi
    if [[ "$CAP_SET6" == y ]]; then
      ins6 filter RZANS_INPUT6 -p icmpv6 --icmpv6-type 128 \
           -m set --match-set ipset-allow6 src \
           -m limit --limit 4/second --limit-burst 20 -j ACCEPT
    fi
  fi

  # per-host SNAT and public-IP attach
  declare -A EXT_ADDED
  local MAP
  for MAP in "${SNAT_MAP[@]}"; do
    # локальные переменные, чтобы не «утекали» в глобальную область
    local base n cand short try _ SRC EXT
    IFS='=' read -r _ EXT <<< "$MAP"
    [[ "$EXT" == "0.0.0.0" || -z "$EXT" ]] && continue
    is_ip_v4 "$EXT" || { echo "⚠ bad IP $EXT — пропущен"; continue; }
    [[ -n ${EXT_ADDED[$EXT]+x} ]] && continue
    if ! ip -o -4 addr show dev "$INTERFACE" | awk '{split($4,a,"/"); print a[1]}' | grep -qx "$EXT"; then
      base="${INTERFACE%%:*}"
      # Сначала пробуем полную схему snat_N
      n="$(next_label_index "${base}:snat_")"
      cand="${base}:snat_${n}"
      if (( ${#cand} <= MAX_LABEL_LEN )); then
        ip addr add "${EXT}/32" dev "$INTERFACE" label "$cand" 2>/dev/null \
          || {  # если занято/нельзя — увеличим индекс несколько раз прежде чем сдаться
               for try in {1..5}; do
                 n="$((n+1))"; cand="${base}:snat_${n}"
                 (( ${#cand} > MAX_LABEL_LEN )) && break
                 ip addr add "${EXT}/32" dev "$INTERFACE" label "$cand" 2>/dev/null && break
               done
               ip -o -4 addr show dev "$INTERFACE" | awk '{split($4,a,"/"); print a[1]}' | grep -qx "$EXT" \
                 || ip addr add "${EXT}/32" dev "$INTERFACE" 2>/dev/null || true
             }
      else
        # Длинное имя интерфейса: используем короткие sN и считаем индекс отдельно по "s"
        n="$(next_label_index "${base}:s")"
        short="${base}:s${n}"
        if (( ${#short} <= MAX_LABEL_LEN )); then
          ip addr add "${EXT}/32" dev "$INTERFACE" label "$short" 2>/dev/null \
          || { for try in {1..5}; do
                 n="$((n+1))"; short="${base}:s${n}"
                 ip addr add "${EXT}/32" dev "$INTERFACE" label "$short" 2>/dev/null && break
               done
               ip -o -4 addr show dev "$INTERFACE" | awk '{split($4,a,"/"); print a[1]}' | grep -qx "$EXT" \
                 || ip addr add "${EXT}/32" dev "$INTERFACE" 2>/dev/null || true
             }
        else
          # Даже короткая форма не влазит — сразу добавляем без label
          ip addr add "${EXT}/32" dev "$INTERFACE" 2>/dev/null || true
        fi
      fi
    fi
    EXT_ADDED[$EXT]=1
  done
  fw_apply_snat

  # DNS-NAT / REDIRECT
  fw_apply_dns_map

  # mapping
  fw_apply_mapping

  # common MASQUERADE
  local NET
  while IFS= read -r NET; do
    is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (POSTROUTE) — пропущен"; continue; }
    add nat POSTROUTING -s "$NET" -o "$INTERFACE" \
	    -m comment --comment RZANS_MASQ -j MASQUERADE
  done < <(all_postroute)

  # strict SSH allow on sets
  if command -v ipset &>/dev/null; then
    if [[ "$CAP_SET4" == y ]]; then
      ins  filter RZANS_INPUT  -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow  src -m comment --comment RZANS_SSH_ALLOW  -j ACCEPT
    fi
    if [[ "$CAP_SET6" == y ]]; then
      ins6 filter RZANS_INPUT6 -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow6 src -m comment --comment RZANS_SSH_ALLOW6 -j ACCEPT
    fi
  fi

  # terminal default-deny внутри наших якорных цепей
  add  filter RZANS_INPUT    -m comment --comment RZANS_DEFAULT_DROP  -j DROP
  add6 filter RZANS_INPUT6   -m comment --comment RZANS_DEFAULT_DROP6 -j DROP
  add  filter RZANS_FORWARD  -m comment --comment RZANS_DEFAULT_DROP  -j DROP
  add6 filter RZANS_FORWARD6 -m comment --comment RZANS_DEFAULT_DROP6 -j DROP
}
phase_dynamic_from_settings

echo "up: done"
