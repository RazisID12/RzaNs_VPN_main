#!/bin/bash
# Up-script
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

#Подключаем общий модуль settings и приводим файл к эталону
. /opt/rzans_vpn_main/settings.sh
settings_heal

# ---------------------------------------------------------------------------
# helpers --------------------------------------------------------------------
is_ip_v4()   { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]; }
is_ip_v6()   { [[ $1 =~ ^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(::)|(::ffff:(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$ ]]; }
is_cidr_v4() { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[12]?[0-9])$ ]]; }

# --- константные пути --------------------------------------------------------
# используем одну переменную в обоих ветках (основной и fallback)
mkdir -p /var/lib/ipset
IPSET_STATE=/var/lib/ipset/ipset-bans.rules

# wait_ip <iface> [timeout] [family 4|6] – печатает первый глобальный IP
wait_ip() {
  local ifc=$1 timeout=${2:-30} fam=${3:-4} ip_addr=""
  for ((i=0; i<timeout; i++)); do
    ip_addr=$(ip -o -"$fam" addr show dev "$ifc" scope global 2>/dev/null \
                | awk 'NR==1{split($4,a,"/");print a[1]}')
    [[ -n $ip_addr ]] && { printf '%s' "$ip_addr"; return 0; }
    sleep 1
  done
  return 1
}

read_settings() {
  ADGUARD_HOME="n"
  SSH_PROTECTION="n"
  EXT4_IP_CFG=""; EXT6_IP_CFG=""
  TRUST4_LIST=(); TRUST6_LIST=()
  SVPN_PORT=""
  FVPN_PORT=""
  SVPN_NET4=""
  FVPN_NET4=""
  VPN_MAP_SRC4=""; VPN_MAP_DST4=""
  SNAT_MAP=()
  ROLLBACK_TIMEOUT=180     # default 3 мин на откат

  SETTINGS=/opt/rzans_vpn_main/settings.map

  [[ -r "$SETTINGS" ]] || { echo "ERROR: cannot read $SETTINGS"; exit 1; }

  # ── основной разбор ------------------------------------------------------
  # читаем тег + все значения; «rest» содержит оставшиеся токены
  while IFS=$' \t' read -r tag a b rest; do
    tag=${tag//$'\r'/}; a=${a//$'\r'/}; b=${b//$'\r'/}
    # Комментарии / пустые строки — просто пропускаем
    if [[ "$tag" == \#* || -z "$tag" ]]; then
        continue
    fi
    # Пустота допустима для: EXTIP4/6, TRUST4/6, SNAT
    if [[ -z "$a" ]]; then
        # ROLLBACK_TIMEOUT может быть без значения → берём default
        [[ "$tag" =~ ^(EXTIP[46]|TRUST[46]|SNAT|ROLLBACK_TIMEOUT)$ ]] && continue
        echo "⚠ settings.map: тег «$tag» без значения — пропущен" >&2
        continue
    fi

    case $tag in
      ADGUARD_HOME)         ADGUARD_HOME="$a" ;;
      SSH_PROTECTION)       SSH_PROTECTION="$a" ;;
      EXTIP4)  EXT4_IP_CFG="$a" ;;
      EXTIP6)  EXT6_IP_CFG="$a" ;;
      TRUST4)  # поддержка формата: TRUST4 ip1 ip2 ip3 ...
        for ip in "$a" "$b" $rest; do
          [[ -z "$ip" ]]        && continue   # пропускаем пустые токены
          [[ "$ip" == \#* ]]     && break      # комментарий — выходим из цикла
          if [[ "$ip" == 0.0.0.0 ]]; then
            :                                 # «открыто всем»
          elif is_ip_v4 "$ip"; then
            TRUST4_LIST+=("$ip")
          else
            echo "⚠ settings.map: TRUST4 <$ip> невалиден — пропущен" >&2
          fi
        done ;;

      TRUST6)  # поддержка формата: TRUST6 ip6_1 ip6_2 ...
        for ip in "$a" "$b" $rest; do
          [[ -z "$ip" ]]        && continue
          [[ "$ip" == \#* ]]     && break
          if [[ "$ip" == :: ]]; then
            :                                 # «закрыто всем»
          elif is_ip_v6 "$ip"; then
            TRUST6_LIST+=("$ip")
          else
            echo "⚠ settings.map: TRUST6 <$ip> невалиден — пропущен" >&2
          fi
        done ;;
      SVPN_PORT)           SVPN_PORT="$a" ;;
      FVPN_PORT)           FVPN_PORT="$a" ;;
      SVPN_NET4)           SVPN_NET4="$a" ;;
      FVPN_NET4)           FVPN_NET4="$a" ;;
      VPN_MAP_SRC4)        VPN_MAP_SRC4="$a" ;;
      VPN_MAP_DST4)        VPN_MAP_DST4="$a" ;;
      ROLLBACK_TIMEOUT)
        if [[ $a =~ ^-?[0-9]+$ ]]; then      # допускаем «‑» впереди
          (( a < 0 )) && a=0                 # отрицательные → «отключено»
          ROLLBACK_TIMEOUT="$a"
        else
          echo "⚠ settings.map: ROLLBACK_TIMEOUT <$a> не число — использую 180" >&2
        fi ;;
      SNAT)
        # 0.0.0.0 0.0.0.0 — «заглушка»: считаем, что SNAT не задан
        if [[ "$a" == 0.0.0.0 && "$b" == 0.0.0.0 ]]; then
          :                               # пропускаем такую запись
        elif ! is_ip_v4 "$a" || ! is_ip_v4 "$b"; then
          echo "⚠ settings.map: SNAT <$a,$b> невалиден — пропущен" >&2
        else
          SNAT_MAP+=("$a=$b")
        fi
      ;;
    esac
  done < "$SETTINGS"

# --- удаляем дубликаты в TRUST-массивах ---------------------------
  # удаляем дубликаты, сохраняя исходный порядок появления
  if ((${#TRUST4_LIST[@]})); then
    readarray -t TRUST4_LIST < <(printf '%s\n' "${TRUST4_LIST[@]}" | awk '!seen[$0]++')
  fi
  if ((${#TRUST6_LIST[@]})); then
    readarray -t TRUST6_LIST < <(printf '%s\n' "${TRUST6_LIST[@]}" | awk '!seen[$0]++')
  fi

  # --- SNAT: убираем повторяющиеся SRC=EXT, сохраняя порядок --------
  if ((${#SNAT_MAP[@]})); then
    readarray -t SNAT_MAP < <(printf '%s\n' "${SNAT_MAP[@]}" | awk '!seen[$0]++')
  fi

# --- пост-парсинговая проверка «парных» тегов -------------------
if { [[ -n "$VPN_MAP_SRC4" && -z "$VPN_MAP_DST4" ]] || [[ -z "$VPN_MAP_SRC4" && -n "$VPN_MAP_DST4" ]]; }; then
    echo "⚠ settings.map: VPN_MAP_SRC4 и VPN_MAP_DST4 должны быть заданы одновременно — игнорированы" >&2
    VPN_MAP_SRC4=""; VPN_MAP_DST4=""
fi

  # ── Fallback-значения для «минимального» конфига ─────────────────
  # валидация и fallback портов
  is_port() { [[ $1 =~ ^[0-9]+$ ]] && (( 1 <= $1 && $1 <= 65535 )); }
  is_port "$SVPN_PORT" || SVPN_PORT="500"
  is_port "$FVPN_PORT" || FVPN_PORT="4500"
  [[ -z "$SVPN_NET4" ]] && SVPN_NET4="10.29.8.0/24"
  [[ -z "$FVPN_NET4" ]] && FVPN_NET4="10.28.8.0/24"

  # ―― генераторы списков (IFS=$' \t\n' безопасен) ――――――――――――――――――――――
  all_dns()        { printf '%s\n' "$SVPN_NET4" "$FVPN_NET4"; }
  all_forward()    { printf '%s\n' "$SVPN_NET4" "$FVPN_NET4"; }
  all_postroute()  { printf '%s\n' "$SVPN_NET4" "$FVPN_NET4"; }
  
# ── удобные срезы подсетей + IP‑фронтов ────────────────────────────────
split_nets_v4() { printf '%s\n' "$SVPN_NET4"; }
full_nets_v4()  { printf '%s\n' "$FVPN_NET4"; }

# первый адрес каждой подсети — фронт DNS/AGH
# используем единый helper из settings.sh (корректно обрабатывает /31,/32)
vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" \
  || { echo "Bad SVPN_NET4/FVPN_NET4"; exit 1; }

  # Split-DNS mapping — берём те же диапазоны, если пользователь ничего не задал
  [[ -z "$VPN_MAP_SRC4" ]] && VPN_MAP_SRC4="$SVPN_NET4"
  [[ -z "$VPN_MAP_DST4" ]] && VPN_MAP_DST4="10.30.0.0/15"

  # ---- нормализуем флаги к y|n -------------------------------------------
  ADGUARD_HOME=${ADGUARD_HOME,,}
  [[ "$ADGUARD_HOME" == y ]] || ADGUARD_HOME="n"
  SSH_PROTECTION=${SSH_PROTECTION,,}
  [[ "$SSH_PROTECTION"       == y ]] || SSH_PROTECTION="n"
}

# ── 1. Служебные опции ─────────────────────────────────────────────────────────
set -eEuo pipefail
trap 'echo "ERR on line $LINENO – cmd: $BASH_COMMAND" >&2; exit 1' ERR
shopt -s expand_aliases

# единый алиас для IPv4
if iptables -w -L >/dev/null 2>&1; then
  alias ipt='iptables -w'
else
  echo "⚠ iptables без опции -w; использую блокирующий вызов" >&2
  alias ipt='iptables'
fi

# ── ip6tables: auto-detect + поддержка отсутствия «-w» ─────────────
if command -v ip6tables &>/dev/null; then
  if ip6tables -w -L >/dev/null 2>&1; then
    _ipt6() { ip6tables -w "$@"; }
  else
    echo "⚠ ip6tables без опции -w; использую блокирующий вызов" >&2
    _ipt6() { ip6tables "$@"; }
  fi
  HAS_IP6=y
else
  HAS_IP6=n
fi
ipt6() { [[ $HAS_IP6 == y ]] && _ipt6 "$@" || return 0; }

# ── helper: гарантированно запустить atd перед использованием «at» ----------
ensure_atd() {
  command -v systemctl &>/dev/null || return 1
  systemctl is-active --quiet atd || systemctl start atd 2>/dev/null || true
  sleep 1
  systemctl is-active --quiet atd
}

read_settings

# ── Heal AdGuard Home config early (bind_hosts, upstreams, allowed_clients)
#    чтобы ниже правила iptables/NAT соответствовали реальным слушателям.
if [[ "$ADGUARD_HOME" == y ]]; then
  agh_heal
fi

ins()  { local t=$1 c=$2; shift 2; ipt  -t "$t" -C "$c" "$@" 2>/dev/null || ipt  -t "$t" -I "$c" 1 "$@"; }
ins6() { local t=$1 c=$2; shift 2; ipt6 -t "$t" -C "$c" "$@" 2>/dev/null || ipt6 -t "$t" -I "$c" 1 "$@"; }
add()  { local t=$1 c=$2; shift 2; ipt  -t "$t" -C "$c" "$@" 2>/dev/null || ipt  -t "$t" -A "$c"   "$@"; }
add6() { local t=$1 c=$2; shift 2; ipt6 -t "$t" -C "$c" "$@" 2>/dev/null || ipt6 -t "$t" -A "$c"   "$@"; }

# ── 0. Обработчик быстрых команд «open80/close80» ────────────────
if [[ "${1:-}" == "open80" ]]; then
  ins filter INPUT -p tcp --dport 80 -j ACCEPT
  exit 0
elif [[ "${1:-}" == "close80" ]]; then
  iptables -w -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
  exit 0
fi

# ── 2. Переменные ──────────────────────────────────────────────────────────────
# 0) приоритет — EXT_IF из settings.map (если задан)
INTERFACE=$(settings_get_tag EXT_IF "")

# 1) иначе ждём появления default‑маршрута IPv4 до 30 с
if [[ -z $INTERFACE ]]; then
  for i in {1..30}; do
    INTERFACE=$(ip -4 route | awk '/^default/{print $5;exit}')
    [[ -n $INTERFACE ]] && break
    sleep 1
  done
fi

# 2) если всё ещё пусто — берём первый iface с глобальным IPv4
[[ -z $INTERFACE ]] && \
  INTERFACE=$(ip -o -4 addr show scope global | awk '{print $2;exit}')

# финальная проверка
[[ -z $INTERFACE ]] && { echo "Cannot determine external interface"; exit 1; }

# 1. внешний IP: приоритет EXTIP из settings.map,
if [[ -n "$EXT4_IP_CFG" && "$EXT4_IP_CFG" != "0.0.0.0" ]]; then
  EXT4_IP=$EXT4_IP_CFG                       # явно указан валидный адрес
else
  # ждём появления первого глобального IPv4 не дольше 30 с
  if ! EXT4_IP=$(wait_ip "$INTERFACE" 30 4); then
    echo "No global IPv4 on $INTERFACE after 30 s – aborting" >&2
    exit 1
  fi
fi

export EXT4_IP

# 1-bis. внешний **IPv6**: ждём до 30 с, если EXTIP6 не задан
if [[ -n "$EXT6_IP_CFG" && "$EXT6_IP_CFG" != "::" ]]; then
  EXT6_IP=$EXT6_IP_CFG
else
  EXT6_IP=$(wait_ip "$INTERFACE" 30 6 || true)
fi
export EXT6_IP

# ── 3. Очистка старых правил ───────────────────────────────────────────────────
/opt/rzans_vpn_main/down.sh "$INTERFACE"

# ── 0. Спасаем активный SSH и loopback ────────────────────────────
ipt  -A INPUT  -i lo -j ACCEPT
ipt  -A OUTPUT -o lo -j ACCEPT
ipt  -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ipt6 -A INPUT  -i lo -j ACCEPT
ipt6 -A OUTPUT -o lo -j ACCEPT
ipt6 -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# ── 1. Теперь можно жёстко опустить политики ──────────────────────
ipt  -P INPUT   DROP
ipt  -P FORWARD DROP
ipt6 -P INPUT   DROP
ipt6 -P FORWARD DROP

## ── проверяем наличие at/atd и ставим страховку, если можем ────────────────
if command -v at &>/dev/null && ensure_atd; then
  FALLBACK_OK=y
else
  echo "⚠ 'at' или atd недоступны – аварийный откат не будет запланирован." >&2
  FALLBACK_OK=n
fi

if [[ "$FALLBACK_OK" == y ]]; then
# ── аварийный откат через at (таймер из ROLLBACK_TIMEOUT) ───────────────
  if (( ROLLBACK_TIMEOUT > 0 )); then
    # shellcheck disable=SC2016
    # «at» не понимает единицу *seconds* → переводим секунды в минуты (округление вверх)
    FALLBACK_MIN=$(( (ROLLBACK_TIMEOUT + 59) / 60 ))
    (( FALLBACK_MIN == 0 )) && FALLBACK_MIN=1
    # Ставим задание в отдельную очередь Z и тихо игнорируем вывод
    # Подчищаем очередь Z от старых заданий (если остались)
    at -q Z -l | awk '$1 ~ /^[0-9]+$/ {print $1}' | xargs -r atrm
    # Единица времени для красоты (1 minute vs minutes)
    WORD=$([[ $FALLBACK_MIN -eq 1 ]] && echo minute || echo minutes)
    # Ставим задание в отдельную очередь Z и подавляем вывод
    LC_ALL=C at -q Z now + ${FALLBACK_MIN} ${WORD} >/dev/null 2>&1 <<AT_EOF
# очистка таблиц
iptables -F
iptables -t nat -F

# базовые политики
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# loopback и ESTABLISHED
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# VPN (порт-значения из settings.map)
iptables -A INPUT -p udp --dport ${SVPN_PORT} -j ACCEPT
iptables -A INPUT -p udp --dport ${FVPN_PORT} -j ACCEPT

# --- восстановление ipset‑банов ---------------------------------------
if command -v ipset >/dev/null; then
  if [ -s "$IPSET_STATE" ]; then
    ipset flush ipset-block  2>/dev/null || true
    ipset flush ipset-block6 2>/dev/null || true
    ipset restore -exist < "$IPSET_STATE" || true
    # ── сразу подключаем восстановленные баны ────────────────────────
    iptables -A INPUT -m set --match-set ipset-block src -j DROP
  fi
fi

# --- IPv6: всё закрыть жёстко --------------------------------------
# IPv6: выполняем, если ip6tables вообще доступна
if ip6tables -L >/dev/null 2>&1; then
  ip6tables -F
  ip6tables -t nat -F 2>/dev/null || true
  ip6tables -P INPUT   DROP
  ip6tables -P FORWARD DROP
  ip6tables -P OUTPUT  ACCEPT
  # loopback / ESTABLISHED + восстановленные баны (симметрия с IPv4)
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ip6tables -A INPUT -m set --match-set ipset-block6 src -j DROP
fi

AT_EOF
    # Берём ID последнего job в нашей очереди Z (достаточно для atrm позже)
    AT_JOB_ID=$(at -q Z -l 2>/dev/null | awk 'END{if ($1 ~ /^[0-9]+$/) print $1}')
  else
    AT_JOB_ID=""
  fi
else
  AT_JOB_ID=""
fi

# ── 4. Твики ядра (симметрично через /etc/sysctl.d) ───────────────────────────
# knot-resolver: socat может отсутствовать на минимальных системах
if command -v socat &>/dev/null; then
  echo 'cache.clear()' | socat - /run/knot-resolver/control/1 || true
fi

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

sysctl --system  >/dev/null

# определяем, доступна ли ipset
if command -v ipset &>/dev/null; then
  HAS_IPSET=y
else
  HAS_IPSET=n
fi

# ── 5. ipset-block (только если ipset есть) ───────────────────────────────────
if [[ "$HAS_IPSET" == y ]]; then
  ipset create ipset-block  hash:ip family inet  timeout 0 comment maxelem 200000 -exist
  ipset create ipset-block6 hash:ip family inet6 timeout 0 comment maxelem 200000 -exist
  # ── наборы для авто‑защиты от сканов / micro‑DDoS ─────────────────────────
  ipset create ipset-watch   hash:ip,port              timeout 60  comment -exist
  ipset create ipset-allow   hash:net                             comment -exist
  ipset create ipset-watch6  hash:ip,port family inet6 timeout 60  comment -exist
  ipset create ipset-allow6  hash:net     family inet6            comment -exist

  # 5-bis. Восстановление банов между перезагрузками
  if [ -s "$IPSET_STATE" ]; then
  ipset flush ipset-block  2>/dev/null || true
      ipset flush ipset-block6 2>/dev/null || true
      # ВАЖНО: читаем команды именно из дампа, иначе restore ничего не применит
      ipset restore -exist < "$IPSET_STATE" || true
  fi
fi

# ── 6. Базовая гигиена ─────────────────────────────────────────────────────────
ins filter INPUT   -m conntrack --ctstate INVALID -j DROP
ins filter FORWARD -m conntrack --ctstate INVALID -j DROP
ins filter OUTPUT  -m conntrack --ctstate INVALID -j DROP
ins6 filter INPUT   -m conntrack --ctstate INVALID -j DROP
ins6 filter FORWARD -m conntrack --ctstate INVALID -j DROP
ins6 filter OUTPUT  -m conntrack --ctstate INVALID -j DROP

# ── 7. Сервисные правила ───────────────────────────────────────────────────────
# Loopback / ESTABLISHED
ins filter INPUT  -i lo -j ACCEPT
ins filter OUTPUT -o lo -j ACCEPT
ins filter INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# ── SSH (22/tcp) ─────────────────────────────────────────────

# 1)  IPv4-доступ
if [[ ${#TRUST4_LIST[@]} -eq 0 ]]; then
  ins  filter INPUT -p tcp --dport 22 -j ACCEPT       # всем IPv4
else
  for IP4 in "${TRUST4_LIST[@]}"; do
  is_ip_v4 "$IP4" || { echo "⚠ bad TRUST4 $IP4 — пропущен"; continue; }
    ins  filter INPUT -p tcp --dport 22 -s "$IP4" -j ACCEPT
  done
fi

# 2)  IPv6 – закрыт, пока явно не разрешим
for IP6 in "${TRUST6_LIST[@]}"; do
  is_ip_v6 "$IP6" || { echo "⚠ bad TRUST6 $IP6 — пропущен"; continue; }
  ins6 filter INPUT -p tcp --dport 22 -s "$IP6" -j ACCEPT
done

# ——— SMTP: блокируем, раз не используем локальный MTA ———
ins filter INPUT  -p tcp --dport 25 -j DROP        # входящие
ins6 filter INPUT  -p tcp --dport 25 -j DROP

### --- OUTBOUND anti-abuse filter (v4 + v6) -----------------------
#   Блокирует исходящий SMTP, Telnet, FTP, IRC, SSDP, SMB и др.
for P in 25 465 587 2525 23 21 69 135 137 138 139 445 \
         1900 6666 6667 6668 6669; do
  ins  filter OUTPUT -p tcp --dport "$P" -j REJECT --reject-with tcp-reset
  ins  filter OUTPUT -p udp --dport "$P" -j DROP
  ins6 filter OUTPUT -p tcp --dport "$P" -j REJECT --reject-with tcp-reset
  ins6 filter OUTPUT -p udp --dport "$P" -j DROP
done

# VPN-порты
for P in "$SVPN_PORT" "$FVPN_PORT"; do
  ins  filter INPUT -p udp --dport "$P" -j ACCEPT
  ins6 filter INPUT -p udp --dport "$P" -j ACCEPT
done

# DNS только из VPN-сетей
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (DNS) — пропущен"; continue; }
  # 53: когда AGH включён (AGH слушает :53 на SVPN_IP/FVPN_IP)
  ins filter INPUT -p udp --dport 53   -s "$NET" -j ACCEPT
  ins filter INPUT -p tcp --dport 53   -s "$NET" -j ACCEPT
done < <(all_dns)

# 5353: только для Split‑VPN (AGH OFF → DNAT 53 -> 127.0.0.1:5353, kresd@1)
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (DNS-5353) — пропущен"; continue; }
  ins filter INPUT -p udp --dport 5353 -s "$NET" -j ACCEPT
  ins filter INPUT -p tcp --dport 5353 -s "$NET" -j ACCEPT
done < <(split_nets_v4)

# 5354: только для Full-VPN (AGH OFF → DNAT 53 → 127.0.0.1:5354, kresd@2)
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (DNS-5354) — пропущен"; continue; }
  ins filter INPUT -p udp --dport 5354 -s "$NET" -j ACCEPT
  ins filter INPUT -p tcp --dport 5354 -s "$NET" -j ACCEPT
done < <(full_nets_v4)

# Транзит VPN-подсетей
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (FWD) — пропущен"; continue; }
  ins filter FORWARD -s "$NET" -j ACCEPT
  ins filter FORWARD -d "$NET" -j ACCEPT
done < <(all_forward)

# ── 8. Анти-скан / лимиты (v4) ────────────────────────────────────────────────
## 0) динамическая ipset‑блокировка + приглушение лишних ICMP/RST
if [[ "$HAS_IPSET" == y ]]; then
  ins filter INPUT  -i "$INTERFACE" -p icmp --icmp-type echo-request                 -j DROP
  ins filter INPUT  -i "$INTERFACE" -m set --match-set ipset-allow src               -j ACCEPT
  ins filter INPUT  -m conntrack --ctstate NEW -m set ! --match-set ipset-watch src,dst \
        -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 \
        --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name scan-det \
        -j SET --add-set ipset-block src
  ins filter INPUT  -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-above 10000/hour --hashlimit-burst 10000 \
        --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name ddos-det \
        -j SET --add-set ipset-block src
  ins filter INPUT  -m set --match-set ipset-block src                                -j DROP
  ins filter INPUT  -m conntrack --ctstate NEW -j SET --add-set ipset-watch src,dst
  ins filter OUTPUT -o "$INTERFACE" -p tcp  --tcp-flags RST RST                       -j DROP
  ins filter OUTPUT -o "$INTERFACE" -p icmp --icmp-type destination-unreachable       -j DROP
fi

## 1) SYN-flood
ins filter INPUT -p tcp --syn \
      -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP

## 2) FIN/NULL/XMAS/SYN-RST
ins filter INPUT -p tcp --tcp-flags ALL NONE            -j DROP
ins filter INPUT -p tcp --tcp-flags ALL FIN,URG,PSH     -j DROP
ins filter INPUT -p tcp --tcp-flags SYN,RST SYN,RST     -j DROP

## 3) ICMP-echo limit
for IP4 in "${TRUST4_LIST[@]}"; do
  [[ -z "$IP4" ]] && continue
  ins filter INPUT -p icmp --icmp-type echo-request -s "$IP4" \
       -m limit --limit 4/second --limit-burst 20 -j ACCEPT
done

## 3-bis) служебные ICMP-типы
ins filter INPUT -p icmp --icmp-type 3 \
     -m limit --limit 4/second --limit-burst 20 -j ACCEPT   # Destination-Unreach
ins filter INPUT -p icmp --icmp-type 4 -j DROP             # Source Quench (obsolete)
ins filter INPUT -p icmp --icmp-type 11 \
     -m limit --limit 4/second --limit-burst 20 -j ACCEPT

## 4) Anti-spoofing
ins filter INPUT -i "$INTERFACE" -s 224.0.0.0/3   -j DROP
ins filter INPUT -i "$INTERFACE" -s 169.254.0.0/16 -j DROP
ins filter INPUT -s 127.0.0.0/8 ! -i lo -j DROP

# ── 9. Анти-скан / лимиты (v6) ────────────────────────────────────────────────
## 0) динамическая ipset‑блокировка (IPv6)
if [[ "$HAS_IPSET" == y ]]; then
  ins6 filter INPUT  -i "$INTERFACE" -p icmpv6 --icmpv6-type echo-request             -j DROP
  ins6 filter INPUT  -i "$INTERFACE" -m set --match-set ipset-allow6 src              -j ACCEPT
  ins6 filter INPUT  -m conntrack --ctstate NEW -m set ! --match-set ipset-watch6 src,dst \
        -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 \
        --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name scan6-det \
        -j SET --add-set ipset-block6 src
  ins6 filter INPUT  -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-above 10000/hour --hashlimit-burst 10000 \
        --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name ddos6-det \
        -j SET --add-set ipset-block6 src
  ins6 filter INPUT  -m set --match-set ipset-block6 src                               -j DROP
  ins6 filter INPUT  -m conntrack --ctstate NEW -j SET --add-set ipset-watch6 src,dst
  ins6 filter OUTPUT -o "$INTERFACE" -p tcp  --tcp-flags RST RST                       -j DROP
  ins6 filter OUTPUT -o "$INTERFACE" -p icmpv6 --icmpv6-type destination-unreachable   -j DROP
fi
## 1) SYN-flood
ins6 filter INPUT -p tcp --syn \
      -m connlimit --connlimit-above 20 --connlimit-mask 128 -j DROP

## 2) FIN/NULL/XMAS/SYN-RST
ins6 filter INPUT -p tcp --tcp-flags ALL NONE            -j DROP
ins6 filter INPUT -p tcp --tcp-flags ALL FIN,URG,PSH     -j DROP
ins6 filter INPUT -p tcp --tcp-flags SYN,RST SYN,RST     -j DROP

## 3) ICMPv6-echo limit
for IP6 in "${TRUST6_LIST[@]}"; do
  [[ -z "$IP6" ]] && continue
  ins6 filter INPUT -p icmpv6 --icmpv6-type 128 -s "$IP6" \
        -m limit --limit 4/second --limit-burst 20 -j ACCEPT
done

## 4) Anti-spoofing
ins6 filter INPUT -i "$INTERFACE" -s ff00::/8  -j DROP
ins6 filter INPUT -i "$INTERFACE" -s fe80::/10 -j DROP
ins6 filter INPUT -s ::1/128 ! -i lo -j DROP

# ── 9-bis. Минимально нужное для IPv6 ─────────────────────────────────────────
ins6 filter INPUT  -i lo -j ACCEPT
ins6 filter OUTPUT -o lo -j ACCEPT
ins6 filter INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# ── mangle: Clamp MSS до PMTU (устраняет «не открываются сайты» при низком MTU)
ins mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ins6 mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# обязательные и служебные ICMPv6-типы
for T in 1 2 3 4 133 134 135 136 143 144 145; do
  ins6 filter INPUT -p icmpv6 --icmpv6-type "$T" -j ACCEPT
done

# финальные политики
ipt  -P INPUT   DROP             # политики DROP уже установлены выше
ipt  -P FORWARD DROP
ipt  -P OUTPUT  ACCEPT

ipt6 -P INPUT   DROP      # политики DROP остаются
ipt6 -P FORWARD DROP
ipt6 -P OUTPUT  ACCEPT

# ── 10-bis.  Подключаем дополнительные public-IP, нужные для SNAT ──
declare -A EXT_ADDED
for MAP in "${SNAT_MAP[@]}"; do
    IFS='=' read -r _ EXT <<< "$MAP"
    is_ip_v4 "$EXT" || { echo "⚠ bad IP $EXT — пропущен"; continue; }
    [[ -n ${EXT_ADDED[$EXT]+x} ]] && continue       # уже добавлен
    if ! ip -o -4 addr show dev "$INTERFACE" \
            | awk '{split($4,a,"/"); print a[1]}' | grep -qx "$EXT"; then
        ip addr add "${EXT}/32" dev "$INTERFACE" label "$INTERFACE:snat"
    fi
    EXT_ADDED[$EXT]=1
done

# ── 11. NAT ────────────────────────────────────────────────────────────────────────────────
# ── 11-A. Персональный SNAT ------------------------------------
for MAP in "${SNAT_MAP[@]}"; do
  IFS='=' read -r SRC EXT <<< "$MAP"
  add nat POSTROUTING -s "${SRC}/32" -j SNAT --to-source "$EXT"
done

# ── DNS‑NAT / REDIRECT (всегда через стабильные цепочки) ----------------------
#AGH_START
# Глобальные «якоря» для DNS: весь трафик 53/tcp,udp → RZANS_DNS,
# где разветвляем по адресу назначения (SVPN_IP/FVPN_IP), а далее
# наполняем целевые DNAT в RZANS_DNS_S / RZANS_DNS_F согласно ADGUARD_HOME.

# 1) Создаём/очищаем цепочки
ipt -t nat -N RZANS_DNS   2>/dev/null || true
ipt -t nat -F RZANS_DNS
ipt -t nat -N RZANS_DNS_S 2>/dev/null || true
ipt -t nat -F RZANS_DNS_S
ipt -t nat -N RZANS_DNS_F 2>/dev/null || true
ipt -t nat -F RZANS_DNS_F

# 2) Хуки PREROUTING для DNS
ipt -t nat -C PREROUTING -p udp --dport 53 -j RZANS_DNS 2>/dev/null || \
  ipt -t nat -A PREROUTING -p udp --dport 53 -j RZANS_DNS
ipt -t nat -C PREROUTING -p tcp --dport 53 -j RZANS_DNS 2>/dev/null || \
  ipt -t nat -A PREROUTING -p tcp --dport 53 -j RZANS_DNS

# 3) Разветвление по адресу назначения (SVPN_IP / FVPN_IP)
ipt -t nat -A RZANS_DNS -d "$SVPN_IP" -j RZANS_DNS_S
ipt -t nat -A RZANS_DNS -d "$FVPN_IP" -j RZANS_DNS_F

# 4) Наполняем цели DNAT
if [[ "$ADGUARD_HOME" == y ]]; then
  # AGH ON: клиенты всегда бьют в VPN‑IP:53, AGH там слушает.
  # Оставляем симметричный DNAT на те же адреса/порт (через наши цепочки),
  # чтобы путь оставался единым и предсказуемым.
  ipt -t nat -A RZANS_DNS_S -p udp -j DNAT --to-destination "${SVPN_IP}:53"
  ipt -t nat -A RZANS_DNS_S -p tcp -j DNAT --to-destination "${SVPN_IP}:53"
  ipt -t nat -A RZANS_DNS_F -p udp -j DNAT --to-destination "${FVPN_IP}:53"
  ipt -t nat -A RZANS_DNS_F -p tcp -j DNAT --to-destination "${FVPN_IP}:53"
else
  # AGH OFF:
  #  • Split‑VPN  → kresd@1 на 127.0.0.1:5353
  #  • Full‑VPN   → kresd@2 на 127.0.0.1:5354
  ipt -t nat -A RZANS_DNS_S -p udp -j DNAT --to-destination 127.0.0.1:5353
  ipt -t nat -A RZANS_DNS_S -p tcp -j DNAT --to-destination 127.0.0.1:5353
  ipt -t nat -A RZANS_DNS_F -p udp -j DNAT --to-destination 127.0.0.1:5354
  ipt -t nat -A RZANS_DNS_F -p tcp -j DNAT --to-destination 127.0.0.1:5354
fi
#AGH_END

# RZANS_VPN_MAIN-MAPPING (если задано)
if [[ -n "$VPN_MAP_SRC4" && -n "$VPN_MAP_DST4" ]]; then
  ipt -t nat -C PREROUTING -s "$VPN_MAP_SRC4" -d "$VPN_MAP_DST4" -j RZANS_VPN_MAIN-MAPPING 2>/dev/null || {
    ipt -t nat -N RZANS_VPN_MAIN-MAPPING 2>/dev/null || true
    ipt -t nat -A PREROUTING -s "$VPN_MAP_SRC4" -d "$VPN_MAP_DST4" -j RZANS_VPN_MAIN-MAPPING
  }
fi
# общий MASQUERADE
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (POSTROUTE) — пропущен"; continue; }
  add nat POSTROUTING -s "$NET" -o "$INTERFACE" -j MASQUERADE
done < <(all_postroute)

# ── 12. Fail2ban: при SSH_PROTECTION=y просто перезагружаем ──────────────────
if [[ "$SSH_PROTECTION" == y ]] && command -v fail2ban-client >/dev/null; then
  fail2ban-client reload || systemctl reload fail2ban || true
fi

# скрипт дошёл до конца → страховка больше не нужна
[[ -n "$AT_JOB_ID" ]] && command -v atrm &>/dev/null && atrm "$AT_JOB_ID"