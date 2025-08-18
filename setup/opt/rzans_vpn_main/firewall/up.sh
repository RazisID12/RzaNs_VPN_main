#!/bin/bash
# Up-script
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

# Подключаем общий модуль settings и приводим файл к эталону
. /opt/rzans_vpn_main/settings/settings.sh      # даёт yaml_get / yaml_bool / _yaml_merged
# ── Глобальный лок настроек: защищаемся от гонок с другими apply/dispatcher ──
if declare -F _ensure_settings_lock >/dev/null; then
  # если лок уже был взят «снаружи» (родитель держит FD) — не будем его отпускать здесь
  __UP_HAD_LOCK=0
  [[ -n "${_SETTINGS_LOCK_FD:-}" ]] && __UP_HAD_LOCK=1
  _ensure_settings_lock || { echo "settings lock busy: another apply is running" >&2; exit 1; }
  __UP_LOCK_ACTIVE=0
  [[ $__UP_HAD_LOCK -eq 0 ]] && __UP_LOCK_ACTIVE=1
  # ВАЖНО: если лок не мы брали, защитим родителя от случайного unlock внутри helpers
  if [[ $__UP_HAD_LOCK -eq 1 ]] && declare -F _release_settings_lock >/dev/null; then
    _release_settings_lock() { :; }
  fi
  _up_unlock() {
    if [[ "${__UP_LOCK_ACTIVE:-0}" -eq 1 ]]; then
      _release_settings_lock || true
    fi
  }
  trap _up_unlock EXIT
else
  echo "⚠ _ensure_settings_lock not found in settings.sh — running without global lock" >&2
  # чтобы _cancel_fallback_on_exit мог безопасно дергать _up_unlock:
  _up_unlock() { :; }
fi

_ensure_settings_yaml                  # гарантируем наличие settings.yaml

# --- константные пути --------------------------------------------------------
mkdir -p /var/lib/ipset
IPSET_BAN_STATE=/var/lib/ipset/ipset-bans.rules
IPSET_ALLOW_STATE=/var/lib/ipset/ipset-allow.rules

# ── 1. Служебные опции ─────────────────────────────────────────────────────────
set -eEuo pipefail
trap 'echo "ERR on line $LINENO – cmd: $BASH_COMMAND" >&2; exit 1' ERR
shopt -s expand_aliases
YQ_BIN=${YQ_BIN:-yq}
# На случай запуска напрямую без окружения:
FIREWALL_DIR=${FIREWALL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}

# --- choose iptables backend consistently (nft pinned) ---
IPT_BIN=$(command -v iptables-nft || echo iptables)
IP6T_BIN=$(command -v ip6tables-nft || echo ip6tables)
echo "Using iptables backend: $("$IPT_BIN" -V)" >&2
alias ipt="$IPT_BIN -w"
HAS_IP6=y; command -v "$IP6T_BIN" >/dev/null || HAS_IP6=n
ipt6() { if [[ $HAS_IP6 == y ]]; then "$IP6T_BIN" -w "$@"; else return 0; fi; }

# ---------------------------------------------------------------------------
# helpers (собраны вместе) ---------------------------------------------------
# валидаторы адресов/подсетей
is_ip_v4()   { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]; }
is_ip_v6()   { [[ $1 =~ ^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(::)|(::ffff:(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$ ]]; }
is_cidr_v4() { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[12]?[0-9])$ ]]; }
is_v4_or_cidr(){ is_ip_v4 "$1" || is_cidr_v4 "$1"; }
is_cidr_v6(){ [[ $1 =~ ^([0-9A-Fa-f]{0,4}:){1,7}(:|[0-9A-Fa-f]{1,4})/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$ ]]; }
is_v6_or_cidr(){ is_ip_v6 "$1" || is_cidr_v6 "$1"; }

# iptables/ip6tables удобные обёртки (check-or-insert / check-or-append)
ins()  { local t=$1 c=$2; shift 2; ipt  -t "$t" -C "$c" "$@" 2>/dev/null || ipt  -t "$t" -I "$c" 1 "$@"; }
ins6() { local t=$1 c=$2; shift 2; ipt6 -t "$t" -C "$c" "$@" 2>/dev/null || ipt6 -t "$t" -I "$c" 1 "$@"; }
add()  { local t=$1 c=$2; shift 2; ipt  -t "$t" -C "$c" "$@" 2>/dev/null || ipt  -t "$t" -A "$c"   "$@"; }
add6() { local t=$1 c=$2; shift 2; ipt6 -t "$t" -C "$c" "$@" 2>/dev/null || ipt6 -t "$t" -A "$c"   "$@"; }

# каркас/хуки
ensure_chain4(){ ipt  -t "$1" -N "$2" 2>/dev/null || true; ipt  -t "$1" -F "$2"; }
ensure_chain6(){ ipt6 -t "$1" -N "$2" 2>/dev/null || true; ipt6 -t "$1" -F "$2"; }
hook4(){ ipt  -t "$1" -C "$2" -j "$3" 2>/dev/null || ipt  -t "$1" -I "$2" 1 -j "$3"; }
hook6(){ ipt6 -t "$1" -C "$2" -j "$3" 2>/dev/null || ipt6 -t "$1" -I "$2" 1 -j "$3"; }

# helper: гарантированно запустить atd перед использованием «at»
ensure_atd() {
  command -v systemctl &>/dev/null || return 1
  systemctl is-active --quiet atd || systemctl start atd 2>/dev/null || true
  sleep 1
  systemctl is-active --quiet atd
}
# ---------------------------------------------------------------------------

read_settings() {
  # ── мгновенно читаем всё из settings.yaml ────────────────────────────
  SSH_PORT="$(yaml_get 'server.port_ssh' 22)"
  ADGUARD_HOME="$(yaml_bool 'adguard_home.enable')"      # → y | n
  SSH_PROTECTION="$(yaml_bool 'fail2ban.enable')"        # → y | n

  SVPN_PORT="$(yaml_get 'vpn.ports.split' 500)"
  FVPN_PORT="$(yaml_get 'vpn.ports.full'  4500)"

  SVPN_NET4="$(yaml_get 'vpn.nets.split' '10.29.8.0/24')"
  FVPN_NET4="$(yaml_get 'vpn.nets.full'  '10.28.8.0/24')"

  # таймаут отката берём из корня settings.yaml
  ROLLBACK_TIMEOUT="$(yaml_get 'rollback_timeout' 180)"
  
  # --- AdGuard Home: только local; никаких external/GUI/DNS-over-HTTPS/DoT/DoQ публикаций
  KRESD1_IP="${KRESD1_IP:-127.0.0.1}"  # kresd@1 (DoT hub)
  KRESD2_IP="${KRESD2_IP:-127.0.0.2}"  # kresd@2 (system v4+v6)
  KRESD3_IP="${KRESD3_IP:-127.0.0.3}"  # kresd@3 (SPLIT, IPv4-only, со списками)
  KRESD4_IP="${KRESD4_IP:-127.0.0.4}"  # kresd@4 (FULL,  IPv4-only, без списков)
  PROXY_IP="${PROXY_IP:-127.0.0.5}"    # proxy (RPZ helper для @3)
  AGH_IP="${AGH_IP:-127.0.0.6}"        # AdGuard Home (клиентский фронт для DNAT)
  DNS_PORT="${DNS_PORT:-53}"

  # --- SNAT-карты -----------------------------------------------------
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

  # ── fallback-проверки ────────────────────────────────────────────────
  is_port() { [[ $1 =~ ^[0-9]+$ ]] && (( 1 <= $1 && $1 <= 65535 )); }
  is_port "$SVPN_PORT" || SVPN_PORT="500"
  is_port "$FVPN_PORT" || FVPN_PORT="4500"
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
  
  # DoT параметры кешируем заранее, чтобы дальше не читать YAML под возможной гонкой
  read -r DOT_URL DOT_PORT < <(yaml_upstream_dot)
  DOT_PORT="${DOT_PORT:-853}"
}

read_settings

# ── 2. Переменные ──────────────────────────────────────────────────────────────
INTERFACE="$(server_iface)"
[[ -z $INTERFACE ]] && { echo "Cannot determine external interface"; exit 1; }

EXT4_IP="$(server_ip4 30)"; export EXT4_IP
EXT6_IP="$(server_ip6 30)"; export EXT6_IP
if [[ "$EXT4_IP" == "0.0.0.0" ]]; then
  echo "No global IPv4 on $INTERFACE after 30 s – aborting" >&2; exit 1
fi

# Мы закончили с ранними YAML-читателями → если лок брали мы, отпускаем его
if [[ "${__UP_LOCK_ACTIVE:-0}" -eq 1 ]]; then
  _release_settings_lock || true
  __UP_LOCK_ACTIVE=0
fi

# ── 3. Очистка старых правил ───────────────────────────────────────────────────
"${FIREWALL_DIR}/down.sh" "$INTERFACE" || echo "down.sh returned non-zero, continuing"

# ---- INPUT anchors (v4 & v6) — создавать ПОСЛЕ down.sh ----------------------
ipt  -t filter -N RZANS_INPUT   2>/dev/null || true
ipt  -t filter -F RZANS_INPUT
hook4 filter INPUT RZANS_INPUT

ipt6 -t filter -N RZANS_INPUT6  2>/dev/null || true
ipt6 -t filter -F RZANS_INPUT6
hook6 filter INPUT RZANS_INPUT6

# БАЗА v4
add  filter RZANS_INPUT -i lo -j ACCEPT
add  filter RZANS_INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
add  filter RZANS_INPUT -m conntrack --ctstate INVALID -j DROP
add  filter RZANS_INPUT -s 127.0.0.0/8 ! -i lo -j DROP

# БАЗА v6
add6 filter RZANS_INPUT6 -i lo -j ACCEPT
add6 filter RZANS_INPUT6 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
add6 filter RZANS_INPUT6 -m conntrack --ctstate INVALID -j DROP
# анти-спуф: пакеты с ::1 не с loopback — в DROP (как и 127/8 для v4)
add6 filter RZANS_INPUT6 -s ::1/128 ! -i lo -j DROP

# Разрешения ICMPv6 (после базы и анти-спуфа)
for T in 1 2 3 4 129 133 134 135 136 143 144 145; do
  add6 filter RZANS_INPUT6 -p icmpv6 --icmpv6-type "$T" -j ACCEPT
done

# ── Включаем route_localnet заранее ───────────────────────────────────────────
sysctl -qw net.ipv4.conf.all.route_localnet=1 || true

# ── Service loopback IPs ------------------------------------------------------
for _loip in "$KRESD2_IP" "$KRESD3_IP" "$KRESD4_IP" "$PROXY_IP" "$AGH_IP"; do
  [[ -n "$_loip" ]] || continue
  ip -4 addr add "${_loip}/32" dev lo 2>/dev/null || true
done
if [[ "$HAS_IP6" == y ]]; then
  # loopback-адрес для валидирующего системного резолвера kresd@2
  ip -6 addr add ::2/128 dev lo 2>/dev/null || true
fi

# ── Политика DNS (anti-leak) ─────────────────────────────────────────────────
KRESD_UID="$(id -u knot-resolver 2>/dev/null || id -u kresd 2>/dev/null || echo '')"

ipt -t filter -N RZANS_DNS_EGRESS 2>/dev/null || true
ipt -t filter -F RZANS_DNS_EGRESS
add  filter RZANS_DNS_EGRESS -d 127.0.0.0/8 -p udp --dport 53 -j ACCEPT
add  filter RZANS_DNS_EGRESS -d 127.0.0.0/8 -p tcp --dport 53 -j ACCEPT
if "$IPT_BIN" -m owner -h >/dev/null 2>&1 && [[ -n "$KRESD_UID" ]]; then
  add  filter RZANS_DNS_EGRESS ! -d 127.0.0.0/8 -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable
  add  filter RZANS_DNS_EGRESS ! -d 127.0.0.0/8 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
else
  echo "⚠ owner-match недоступен или KRESD_UID пуст — anti-leak без исключения для kresd" >&2
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
    add6 filter RZANS_DNS6_EGRESS ! -d ::1/128 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable
    add6 filter RZANS_DNS6_EGRESS ! -d ::2/128 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable
    add6 filter RZANS_DNS6_EGRESS ! -d ::1/128 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
    add6 filter RZANS_DNS6_EGRESS ! -d ::2/128 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
  else
    add6 filter RZANS_DNS6_EGRESS ! -d ::1/128 -p udp --dport 53 -j DROP
    add6 filter RZANS_DNS6_EGRESS ! -d ::2/128 -p udp --dport 53 -j DROP
    add6 filter RZANS_DNS6_EGRESS ! -d ::1/128 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
    add6 filter RZANS_DNS6_EGRESS ! -d ::2/128 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
  fi
  ins6 filter OUTPUT -p udp --dport 53 -j RZANS_DNS6_EGRESS
  ins6 filter OUTPUT -p tcp --dport 53 -j RZANS_DNS6_EGRESS
fi

## ── аварийный откат через at ────────────────────────────────────────────────
if command -v at &>/dev/null && ensure_atd; then
  FALLBACK_OK=y
else
  echo "⚠ 'at' или atd недоступны – аварийный откат не будет запланирован." >&2
  FALLBACK_OK=n
fi

AT_JOB_ID=""
if [[ "$FALLBACK_OK" == y ]]; then
  if (( ROLLBACK_TIMEOUT > 0 )); then
    FALLBACK_MIN=$(( (ROLLBACK_TIMEOUT + 59) / 60 ))
    (( FALLBACK_MIN == 0 )) && FALLBACK_MIN=1
    at -q Z -l | awk '$1 ~ /^[0-9]+$/ {print $1}' | xargs -r atrm
    WORD=$([[ $FALLBACK_MIN -eq 1 ]] && echo minute || echo minutes)
    AT_JOB_ID="$(
      LC_ALL=C at -q Z now + ${FALLBACK_MIN} ${WORD} 2>&1 <<AT_EOF | awk '/^job [0-9]+ at /{print $2; exit}'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${IPT_BIN} -F
${IPT_BIN} -t nat -F
${IPT_BIN} -t mangle -F
${IP6T_BIN} -t mangle -F 2>/dev/null || true

${IPT_BIN} -P INPUT   DROP
${IPT_BIN} -P FORWARD DROP
${IPT_BIN} -P OUTPUT  ACCEPT
${IPT_BIN} -A INPUT -i lo -j ACCEPT
${IPT_BIN} -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
${IPT_BIN} -A INPUT -p tcp --dport ${SSH_PORT} -j ACCEPT
${IPT_BIN} -A INPUT -p udp --dport ${SVPN_PORT} -j ACCEPT
${IPT_BIN} -A INPUT -p udp --dport ${FVPN_PORT} -j ACCEPT

if command -v ipset >/dev/null; then
    if [ -s "$IPSET_BAN_STATE" ]; then
    ipset flush ipset-block  2>/dev/null || true
    ipset flush ipset-block6 2>/dev/null || true
    ipset restore -exist < "$IPSET_BAN_STATE" || true
    ${IPT_BIN} -I INPUT 1 -m set --match-set ipset-block src -j DROP
  fi
fi

if ${IP6T_BIN} -L >/dev/null 2>&1; then
  ${IP6T_BIN} -F
  ${IP6T_BIN} -t nat -F 2>/dev/null || true
  ${IP6T_BIN} -P INPUT   DROP
  ${IP6T_BIN} -P FORWARD DROP
  ${IP6T_BIN} -P OUTPUT  ACCEPT
  ${IP6T_BIN} -A INPUT -i lo -j ACCEPT
  ${IP6T_BIN} -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ${IP6T_BIN} -A INPUT  -p icmpv6 -j ACCEPT
  if command -v ipset >/dev/null 2>&1; then
    ipset list ipset-block6 >/dev/null 2>&1 && \
      ${IP6T_BIN} -I INPUT 1 -m set --match-set ipset-block6 src -j DROP
  fi
fi
AT_EOF
        )" || AT_JOB_ID=""

    # На всякий случай: если ID не распарсился, удалим поставленную джобу из очереди Z,
    # чтобы не словить неожиданный откат через несколько минут.
    if [[ -z "$AT_JOB_ID" ]]; then
      echo "⚠ couldn't parse AT job id; removing queued fallback from Z." >&2
      at -q Z -l | awk '$1 ~ /^[0-9]+$/ {print $1}' | xargs -r atrm || true
    fi
  fi
fi

# Отмена fallback при УСПЕШНОМ завершении (и корректный unlock)
_cancel_fallback_on_exit() {
  local ec=$?
  _up_unlock
  if [[ $ec -eq 0 && -n "${AT_JOB_ID:-}" ]] && command -v atrm &>/dev/null; then
    atrm "$AT_JOB_ID" || true
  fi
}
trap _cancel_fallback_on_exit EXIT


# ── 4. Твики ядра ─────────────────────────────────────────────────────────────
SYSCTL_FILE="/etc/sysctl.d/99-rzans_vpn_main.conf"
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
# загружаем только наш файл и не валимся, если что-то не так
sysctl --load="$SYSCTL_FILE" >/dev/null 2>&1 || sysctl -q -p "$SYSCTL_FILE" || true

# определяем, доступна ли ipset
if command -v ipset &>/dev/null; then
  HAS_IPSET=y
else
  HAS_IPSET=n
fi

# ── 5. ipset ────────────────────────────────────────────────────────────
if [[ "$HAS_IPSET" == y ]]; then
  ipset create ipset-allow   hash:net                             comment -exist
  ipset create ipset-allow6  hash:net     family inet6            comment -exist
  ipset create ipset-block  hash:ip family inet  timeout 0 comment maxelem 200000 -exist
  ipset create ipset-block6 hash:ip family inet6 timeout 0 comment maxelem 200000 -exist
  ipset create ipset-watch   hash:ip,port              timeout 60  comment -exist
  ipset create ipset-watch6  hash:ip,port family inet6 timeout 60  comment -exist
  # DoT targets (апстримы для TLS_FORWARD)
  ipset create ipset-dot  hash:ip  family inet  comment -exist
  ipset create ipset-dot6 hash:ip  family inet6 comment -exist

  if [ -s "$IPSET_BAN_STATE" ]; then
    ipset flush ipset-block  2>/dev/null || true
    ipset flush ipset-block6 2>/dev/null || true
    ipset restore -exist < "$IPSET_BAN_STATE" || true
  fi

  # allow-наборы: база из settings.yaml → затем «подмешать» динамику (если была)
  while read -r IP4NET; do
    is_v4_or_cidr "$IP4NET" || continue
    ipset add ipset-allow "$IP4NET" comment "src=settings" -exist
  done < <(yaml_allow_all | grep -E '^[0-9.]+(/[0-9]+)?$' || true)
  while read -r IP6NET; do
    is_v6_or_cidr "$IP6NET" || continue
    ipset add ipset-allow6 "$IP6NET" comment "src=settings" -exist
  done < <(yaml_allow_all | grep -F ':' || true)
  if [ -s "$IPSET_ALLOW_STATE" ]; then
    ipset restore -exist < "$IPSET_ALLOW_STATE" || true
    # сразу «примем» динамические allow в YAML и нормализуем комментарии
    allow_sync_ipsets || true
  fi

  # DoT upstream наборы: единая функция
  dot_ipset_sync
fi

  # ── Bootstrap SSH per-family ───────────────────────────────────────
  if [[ "$HAS_IPSET" == y ]]; then
    cnt4=$(ipset list ipset-allow  2>/dev/null | awk '/Number of entries:/{print $4; exit}'); cnt4=${cnt4:-0}
    cnt6=$(ipset list ipset-allow6 2>/dev/null | awk '/Number of entries:/{print $4; exit}'); cnt6=${cnt6:-0}
  else
    cnt4=0; cnt6=0
  fi
  if (( cnt4==0 )); then
    add  filter RZANS_INPUT  -p tcp --dport "$SSH_PORT" -m comment --comment RZANS_SSH_BOOT4 -j ACCEPT
  else
    ipt  -t filter -D RZANS_INPUT  -p tcp --dport "$SSH_PORT" -m comment --comment RZANS_SSH_BOOT4 -j ACCEPT 2>/dev/null || true
  fi
  if (( cnt6==0 )); then
    add6 filter RZANS_INPUT6 -p tcp --dport "$SSH_PORT" -m comment --comment RZANS_SSH_BOOT6 -j ACCEPT
  else
    ipt6 -t filter -D RZANS_INPUT6 -p tcp --dport "$SSH_PORT" -m comment --comment RZANS_SSH_BOOT6 -j ACCEPT 2>/dev/null || true
  fi

# ── DoT egress allowlist: только kresd → только к апстрим-IP на port_tls
# DOT_URL/DOT_PORT уже кэшированы в read_settings()
DOT_PORT="${DOT_PORT:-853}"
# allow для DoT
if [[ "$HAS_IPSET" == y ]]; then
  # с ipset — матчим по целевым IP апстрима
  if [[ -n "$KRESD_UID" ]] && "$IPT_BIN" -m owner -h >/dev/null 2>&1; then
    ins  filter OUTPUT -p tcp --dport "$DOT_PORT" -m owner --uid-owner "$KRESD_UID" \
                       -m set --match-set ipset-dot  dst -m comment --comment RZANS_DOT_ALLOW -j ACCEPT
  else
    ins  filter OUTPUT -p tcp --dport "$DOT_PORT" -m set --match-set ipset-dot  dst -m comment --comment RZANS_DOT_ALLOW -j ACCEPT
  fi
  if [[ "$HAS_IP6" == y ]]; then
    if [[ -n "$KRESD_UID" ]] && "$IP6T_BIN" -m owner -h >/dev/null 2>&1; then
      ins6 filter OUTPUT -p tcp --dport "$DOT_PORT" -m owner --uid-owner "$KRESD_UID" \
                          -m set --match-set ipset-dot6 dst -m comment --comment RZANS_DOT_ALLOW6 -j ACCEPT
    else
      ins6 filter OUTPUT -p tcp --dport "$DOT_PORT" -m set --match-set ipset-dot6 dst -m comment --comment RZANS_DOT_ALLOW6 -j ACCEPT
    fi
  fi
else
  # без ipset — хотя бы ограничим по UID kresd
  if [[ -n "$KRESD_UID" ]] && "$IPT_BIN" -m owner -h >/dev/null 2>&1; then
    ins  filter OUTPUT -p tcp --dport "$DOT_PORT" -m owner --uid-owner "$KRESD_UID" -j ACCEPT
  fi
  if [[ "$HAS_IP6" == y ]] && [[ -n "$KRESD_UID" ]] && "$IP6T_BIN" -m owner -h >/dev/null 2>&1; then
    ins6 filter OUTPUT -p tcp --dport "$DOT_PORT" -m owner --uid-owner "$KRESD_UID" -j ACCEPT
  fi
fi
# жёстко запрещаем прочий трафик на port_tls (кроме особого случая 443)
if [[ "$DOT_PORT" = "443" ]]; then
  echo "⚠ DOT_PORT=443 — общий REJECT на 443 отключён, чтобы не ломать исходящий HTTPS" >&2
else
  add  filter OUTPUT -p tcp --dport "$DOT_PORT" -m comment --comment RZANS_DOT_REJECT  -j REJECT --reject-with tcp-reset
  add6 filter OUTPUT -p tcp --dport "$DOT_PORT" -m comment --comment RZANS_DOT_REJECT6 -j REJECT --reject-with tcp-reset
fi

# ── 6. Базовая гигиена ────────────────────────────────────────────────────────
ins filter FORWARD -m conntrack --ctstate INVALID -j DROP
ins filter OUTPUT  -m conntrack --ctstate INVALID -j DROP
ins6 filter FORWARD -m conntrack --ctstate INVALID -j DROP
ins6 filter OUTPUT  -m conntrack --ctstate INVALID -j DROP

## ── SSH $SSH_PORT/tcp — доступ только из allow-наборов (если ipset доступен) ──
if [[ "$HAS_IPSET" == y ]]; then
  ins  filter RZANS_INPUT  -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow  src -m comment --comment RZANS_SSH_ALLOW  -j ACCEPT
  ins6 filter RZANS_INPUT6 -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow6 src -m comment --comment RZANS_SSH_ALLOW6 -j ACCEPT
fi

# SMTP off
add  filter RZANS_INPUT  -p tcp --dport 25 -j DROP
add6 filter RZANS_INPUT6 -p tcp --dport 25 -j DROP

# OUTBOUND anti-abuse
for P in 25 465 587 2525 23 21 69 135 137 138 139 445 1900 6666 6667 6668 6669; do
  ins  filter OUTPUT -p tcp --dport "$P" -j REJECT --reject-with tcp-reset
  ins  filter OUTPUT -p udp --dport "$P" -j DROP
  ins6 filter OUTPUT -p tcp --dport "$P" -j REJECT --reject-with tcp-reset
  ins6 filter OUTPUT -p udp --dport "$P" -j DROP
done

# VPN-порты (помечаем отдельно split/full)
add  filter RZANS_INPUT  -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT  -j ACCEPT
add6 filter RZANS_INPUT6 -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT6 -j ACCEPT
add  filter RZANS_INPUT  -p udp --dport "$FVPN_PORT" -m comment --comment RZANS_VPN_FPORT  -j ACCEPT
add6 filter RZANS_INPUT6 -p udp --dport "$FVPN_PORT" -m comment --comment RZANS_VPN_FPORT6 -j ACCEPT

if [[ "$ADGUARD_HOME" == y ]]; then
  while IFS= read -r NET; do
    is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (DNS) — пропущен"; continue; }
    add filter RZANS_INPUT -d "$AGH_IP" -p udp --dport "$DNS_PORT" -s "$NET" -j ACCEPT
    add filter RZANS_INPUT -d "$AGH_IP" -p tcp --dport "$DNS_PORT" -s "$NET" -j ACCEPT
  done < <(all_dns)
fi

if [[ "$ADGUARD_HOME" == n ]]; then
  while IFS= read -r NET; do
    is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (DNS-split) — пропущен"; continue; }
    add filter RZANS_INPUT -d "$KRESD3_IP" -p udp --dport "$DNS_PORT" -s "$NET" -j ACCEPT
    add filter RZANS_INPUT -d "$KRESD3_IP" -p tcp --dport "$DNS_PORT" -s "$NET" -j ACCEPT
  done < <(split_nets_v4)
  while IFS= read -r NET; do
    is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (DNS-full) — пропущен"; continue; }
    add filter RZANS_INPUT -d "$KRESD4_IP" -p udp --dport "$DNS_PORT" -s "$NET" -j ACCEPT
    add filter RZANS_INPUT -d "$KRESD4_IP" -p tcp --dport "$DNS_PORT" -s "$NET" -j ACCEPT
  done < <(full_nets_v4)
fi

# Транзит VPN-подсетей
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (FWD) — пропущен"; continue; }
  ins filter FORWARD -s "$NET" -j ACCEPT
  ins filter FORWARD -d "$NET" -j ACCEPT
done < <(all_forward)

# ── 8. Анти-скан / лимиты (v4) ────────────────────────────────────────────────
if [[ "$HAS_IPSET" == y ]]; then
  # DROP для забаненных, но не трогаем источники из allow
  ins filter RZANS_INPUT  -m set --match-set ipset-block src \
                          -m set ! --match-set ipset-allow src -j DROP
  add filter RZANS_INPUT  -m conntrack --ctstate NEW -m set ! --match-set ipset-watch src,dst \
        -m set ! --match-set ipset-allow src \
        -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 \
        --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name scan-det \
        -j SET --add-set ipset-block src
  add filter RZANS_INPUT  -m conntrack --ctstate NEW \
        -m set ! --match-set ipset-allow src \
        -m hashlimit --hashlimit-above 10000/hour --hashlimit-burst 10000 \
        --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name ddos-det \
        -j SET --add-set ipset-block src
  add filter RZANS_INPUT  -m conntrack --ctstate NEW \
        -m set ! --match-set ipset-allow src \
        -j SET --add-set ipset-watch src,dst
  ins filter OUTPUT -o "$INTERFACE" -p tcp  --tcp-flags RST RST                 -j DROP
  ins filter OUTPUT -o "$INTERFACE" -p icmp --icmp-type destination-unreachable -j DROP
fi
add filter RZANS_INPUT -p tcp --syn -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP
add filter RZANS_INPUT -p tcp --tcp-flags ALL NONE            -j DROP
add filter RZANS_INPUT -p tcp --tcp-flags ALL FIN,URG,PSH     -j DROP
add filter RZANS_INPUT -p tcp --tcp-flags SYN,RST SYN,RST     -j DROP
if [[ "$HAS_IPSET" == y ]]; then
  add filter RZANS_INPUT -p icmp --icmp-type echo-request \
       -m set --match-set ipset-allow src \
       -m limit --limit 4/second --limit-burst 20 -j ACCEPT
fi
add filter RZANS_INPUT -i "$INTERFACE" -p icmp --icmp-type echo-request -j DROP
add filter RZANS_INPUT -p icmp --icmp-type 3  -m limit --limit 4/second --limit-burst 20 -j ACCEPT
add filter RZANS_INPUT -p icmp --icmp-type 4 -j DROP
add filter RZANS_INPUT -p icmp --icmp-type 11 -m limit --limit 4/second --limit-burst 20 -j ACCEPT
add filter RZANS_INPUT -i "$INTERFACE" -s 224.0.0.0/3   -j DROP
add filter RZANS_INPUT -i "$INTERFACE" -s 169.254.0.0/16 -j DROP

# ── 9. Анти-скан / лимиты (v6) ────────────────────────────────────────────────
if [[ "$HAS_IPSET" == y ]]; then
  # DROP для забаненных, но не трогаем источники из allow6
  ins6 filter RZANS_INPUT6 -m set --match-set ipset-block6 src \
                           -m set ! --match-set ipset-allow6 src -j DROP
  add6 filter RZANS_INPUT6 -m conntrack --ctstate NEW -m set ! --match-set ipset-watch6 src,dst \
        -m set ! --match-set ipset-allow6 src \
        -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 \
        --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name scan6-det \
        -j SET --add-set ipset-block6 src
  add6 filter RZANS_INPUT6 -m conntrack --ctstate NEW \
        -m set ! --match-set ipset-allow6 src \
        -m hashlimit --hashlimit-above 10000/hour --hashlimit-burst 10000 \
        --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name ddos6-det \
        -j SET --add-set ipset-block6 src
  add6 filter RZANS_INPUT6 -m conntrack --ctstate NEW \
        -m set ! --match-set ipset-allow6 src \
        -j SET --add-set ipset-watch6 src,dst
  ins6 filter OUTPUT -o "$INTERFACE" -p tcp --tcp-flags RST RST -j DROP
fi
add6 filter RZANS_INPUT6 -p tcp --syn -m connlimit --connlimit-above 20 --connlimit-mask 128 -j DROP
add6 filter RZANS_INPUT6 -p tcp --tcp-flags ALL NONE        -j DROP
add6 filter RZANS_INPUT6 -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
add6 filter RZANS_INPUT6 -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
if [[ "$HAS_IPSET" == y ]]; then
  add6 filter RZANS_INPUT6 -p icmpv6 --icmpv6-type 128 \
        -m set --match-set ipset-allow6 src \
        -m limit --limit 4/second --limit-burst 20 -j ACCEPT
fi
add6 filter RZANS_INPUT6 -i "$INTERFACE" -s ff00::/8 -j DROP
add6 filter RZANS_INPUT6 -i "$INTERFACE" -p icmpv6 --icmpv6-type 128 -j DROP
add6 filter RZANS_INPUT6 -i "$INTERFACE" -m addrtype --dst-type MULTICAST ! -p icmpv6 -j DROP

# ── mangle: Clamp MSS до PMTU ────────────────────────────────────────────────
ins  mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ins6 mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# финальные политики
ipt  -P INPUT   DROP
ipt  -P FORWARD DROP
ipt  -P OUTPUT  ACCEPT
ipt6 -P INPUT   DROP
ipt6 -P FORWARD DROP
ipt6 -P OUTPUT  ACCEPT

# ── 10-bis. Подключаем дополнительные public-IP для SNAT ─────────────────────
declare -A EXT_ADDED
for MAP in "${SNAT_MAP[@]}"; do
  IFS='=' read -r _ EXT <<< "$MAP"
  [[ "$EXT" == "0.0.0.0" || -z "$EXT" ]] && continue
  is_ip_v4 "$EXT" || { echo "⚠ bad IP $EXT — пропущен"; continue; }
  [[ -n ${EXT_ADDED[$EXT]+x} ]] && continue
  if ! ip -o -4 addr show dev "$INTERFACE" \
        | awk '{split($4,a,"/"); print a[1]}' | grep -qx "$EXT"; then
    # помечаем адрес, чтобы down.sh мог снять его даже без SNAT_MAP
    ip addr add "${EXT}/32" dev "$INTERFACE" label "${INTERFACE}:snat" 2>/dev/null || true
  fi
  EXT_ADDED[$EXT]=1
done

# ── 11. NAT ───────────────────────────────────────────────────────────────────
# ── 11-A. Персональный SNAT (без per-host MASQUERADE) ------------------------
for MAP in "${SNAT_MAP[@]}"; do
  IFS='=' read -r SRC EXT <<< "$MAP"
  is_ip_v4 "$SRC" || { echo "⚠ bad SNAT internal $SRC — пропущен"; continue; }
  if [[ -n "$EXT" && "$EXT" != "0.0.0.0" ]]; then
    is_ip_v4 "$EXT" || { echo "⚠ bad SNAT external $EXT — пропущен"; continue; }
    add nat POSTROUTING -s "${SRC}/32" -o "$INTERFACE" -j SNAT --to-source "$EXT"
  fi
done

# ── DNS-NAT / REDIRECT --------------------------------------------------------
#AGH_START
ensure_chain4 nat RZANS_DNS_S
ensure_chain4 nat RZANS_DNS_F
for PROTO in udp tcp; do
  ipt -t nat -C PREROUTING -s "$SVPN_NET4" -p "$PROTO" --dport 53 -j RZANS_DNS_S 2>/dev/null || \
    ipt -t nat -I PREROUTING 1 -s "$SVPN_NET4" -p "$PROTO" --dport 53 -j RZANS_DNS_S
  ipt -t nat -C PREROUTING -s "$FVPN_NET4" -p "$PROTO" --dport 53 -j RZANS_DNS_F 2>/dev/null || \
    ipt -t nat -I PREROUTING 1 -s "$FVPN_NET4" -p "$PROTO" --dport 53 -j RZANS_DNS_F
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
#AGH_END

# RZANS_VPN_MAIN-MAPPING — не трогаем логику
ipt -t nat -N RZANS_VPN_MAIN-MAPPING 2>/dev/null || true
ipt -t nat -C PREROUTING -s "$VPN_MAP_SRC4" -d "$VPN_MAP_DST4" -j RZANS_VPN_MAIN-MAPPING 2>/dev/null || \
  ipt -t nat -A PREROUTING -s "$VPN_MAP_SRC4" -d "$VPN_MAP_DST4" -j RZANS_VPN_MAIN-MAPPING

# общий MASQUERADE для VPN-подсетей
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (POSTROUTE) — пропущен"; continue; }
  add nat POSTROUTING -s "$NET" -o "$INTERFACE" -j MASQUERADE
done < <(all_postroute)

# ── 12. Fail2ban ──────────────────────────────────────────────────────────────
if [[ "$SSH_PROTECTION" == y ]] && command -v fail2ban-client >/dev/null; then
  fail2ban-client reload || systemctl reload fail2ban || true
fi

# явный маркер успешного завершения
echo "up: done"
