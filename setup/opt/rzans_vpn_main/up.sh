# Up-script
#!/bin/bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 027

#Подключаем общий модуль settings и приводим файл к эталону
. /opt/rzans_vpn_main/settings.sh
settings_heal

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

  SETTINGS=/opt/rzans_vpn_main/settings.map

# --- helpers ---------------------------------------------------------------
is_ip_v4()   { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]; }
is_ip_v6() {
  [[ $1 =~ ^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(::)|(::ffff:(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$ ]]
}
is_cidr_v4() { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[12]?[0-9])$ ]]; }

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
        [[ "$tag" =~ ^(EXTIP[46]|TRUST[46]|SNAT)$ ]] && continue
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
      SNAT)
        if ! is_ip_v4 "$a" || ! is_ip_v4 "$b"; then
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
  all_dnat()       { printf '%s\n' "$SVPN_NET4" "$FVPN_NET4"; }
  all_postroute()  { printf '%s\n' "$SVPN_NET4" "$FVPN_NET4"; }
  all_post_dnat()  { printf '%s\n' "$SVPN_NET4" "$FVPN_NET4"; }

  # Split-DNS mapping — берём те же диапазоны, если пользователь ничего не задал
  [[ -z "$VPN_MAP_SRC4" ]] && VPN_MAP_SRC4="10.29.8.0/24"
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

read_settings

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
INTERFACE=$(ip route | awk '/^default/{print $5;exit}')
[[ -z "$INTERFACE" ]] && { echo 'Default interface not found'; exit 1; }

# 1. внешний IP: приоритет EXTIP из settings.map,
if [[ -n "$EXT4_IP_CFG" && "$EXT4_IP_CFG" != "0.0.0.0" ]]; then
  EXT4_IP=$EXT4_IP_CFG                       # явно указан валидный адрес
else
  # ждём появления первого глобального IPv4 не дольше 30 с
  for _ in {1..30}; do
    EXT4_IP=$(ip -o -4 addr show dev "$INTERFACE" scope global \
             | awk '{print $4; exit}' | cut -d/ -f1)
    [[ -n "$EXT4_IP" ]] && break
    sleep 1
  done
  if [[ -z "$EXT4_IP" ]]; then
    echo "No global IPv4 on $INTERFACE after 30 s – aborting" >&2
    exit 1
  fi
fi

export EXT4_IP

# 1-bis. внешний **IPv6**: ждём до 30 с, если EXTIP6 не задан
if [[ -n "$EXT6_IP_CFG" && "$EXT6_IP_CFG" != "::" ]]; then
  EXT6_IP=$EXT6_IP_CFG
else
  for _ in {1..30}; do
    EXT6_IP=$(ip -o -6 addr show dev "$INTERFACE" scope global \
              | awk '{print $4; exit}' | cut -d/ -f1)
    [[ -n "$EXT6_IP" ]] && break
    sleep 1
  done
fi
export EXT6_IP

# ── 3. Очистка старых правил ───────────────────────────────────────────────────
/opt/rzans_vpn_main/down.sh "$INTERFACE"

# сразу закрываем всё
ipt  -P INPUT   DROP
ipt  -P FORWARD DROP
ipt6 -P INPUT   DROP
ipt6 -P FORWARD DROP

## ── проверяем наличие at/atd и ставим страховку, если можем ────────────────
if command -v at &>/dev/null && command -v systemctl &>/dev/null \
   && systemctl is-active --quiet atd; then
  FALLBACK_OK=y
else
  echo "⚠ 'at' или atd недоступны – аварийный откат не будет запланирован." >&2
  FALLBACK_OK=n
fi

if [[ "$FALLBACK_OK" == y ]]; then
# ── аварийный откат через at: однострочные iptables
#  (IPv6-функция проверяется без builtin `command`)
# shellcheck disable=SC2016
  AT_JOB_ID=$(
    LC_ALL=C at now + 3 minutes 2>&1 <<AT_EOF | awk '/job/{print $2}'
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

# --- IPv6: всё закрыть жёстко --------------------------------------
# IPv6: выполняем, если ip6tables вообще доступна
if ip6tables -L >/dev/null 2>&1; then
  ip6tables -F
  ip6tables -t nat -F 2>/dev/null || true
  ip6tables -P INPUT   DROP
  ip6tables -P FORWARD DROP
  ip6tables -P OUTPUT  ACCEPT
fi

AT_EOF
)
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

  # 5-bis. Восстановление банов между перезагрузками
  mkdir -p /var/lib/ipset
  IPSET_STATE=/var/lib/ipset/ipset-bans.rules
  if [[ -f "$IPSET_STATE" ]]; then
      ipset flush ipset-block  2>/dev/null || true
      ipset flush ipset-block6 2>/dev/null || true
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

# UI-порты AdGuard остаются привязанными к доверенным IP (если заданы)
#AGH_START
if [[ "$ADGUARD_HOME" == y ]]; then
  for IP4 in "${TRUST4_LIST[@]}"; do
  [[ -z "$IP4" ]] && continue
  ins filter INPUT -p tcp --dport 300  -s "$IP4" -j ACCEPT
  ins filter INPUT -p tcp --dport 3000 -s "$IP4" -j ACCEPT
done
fi
#AGH_END

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

# DoH / DoT
#AGH_START
if [[ "$ADGUARD_HOME" == y ]]; then
  for PORT in 443 853; do
    ins filter INPUT -p tcp --dport "$PORT" -j ACCEPT
  done
  ins filter INPUT -p udp --dport 443 -j ACCEPT
  ins filter INPUT -p udp --dport 853 -j ACCEPT
fi
#AGH_END

# VPN-порты
for P in "$SVPN_PORT" "$FVPN_PORT"; do
  ins  filter INPUT -p udp --dport "$P" -j ACCEPT
  ins6 filter INPUT -p udp --dport "$P" -j ACCEPT
done

# DNS только из VPN-сетей
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (DNS) — пропущен"; continue; }
  ins filter INPUT -p udp --dport 53 -s "$NET" -j ACCEPT
  ins filter INPUT -p tcp --dport 53 -s "$NET" -j ACCEPT
done < <(all_dns)

# Транзит VPN-подсетей
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (FWD) — пропущен"; continue; }
  ins filter FORWARD -s "$NET" -j ACCEPT
  ins filter FORWARD -d "$NET" -j ACCEPT
done < <(all_forward)

# ── 8. Анти-скан / лимиты (v4) ────────────────────────────────────────────────
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

# обязательные и служебные ICMPv6-типы
for T in 1 2 3 4 133 134 135 136 143 144 145; do
  ins6 filter INPUT -p icmpv6 --icmpv6-type "$T" -j ACCEPT
done

#AGH_START
if [[ "$ADGUARD_HOME" == y ]]; then
  for PORT in 443 853; do
    ins6 filter INPUT -p tcp --dport "$PORT" -j ACCEPT
  done
  ins6 filter INPUT -p udp --dport 443 -j ACCEPT   # HTTP/3
  ins6 filter INPUT -p udp --dport 853 -j ACCEPT   # DoQ
fi
#AGH_END

# финальные политики
ipt  -P INPUT   DROP             # политики DROP уже установлены выше
ipt  -P FORWARD DROP
ipt  -P OUTPUT  ACCEPT

ipt6 -P INPUT   DROP      # политики DROP остаются
ipt6 -P FORWARD DROP
ipt6 -P OUTPUT  ACCEPT

# ── 10. Fail2Ban и ipset-DROP ────────────────────────────────────────────────
#F2B_START
# 1.  Всегда подключаем ipset-DROP-правила (ручные баны начнут работать сразу)
if [[ "$HAS_IPSET" == y ]]; then
  ins  filter INPUT -m set --match-set ipset-block  src -j DROP
  ins6 filter INPUT -m set --match-set ipset-block6 src -j DROP
fi

# 2.  Цепочки Fail2Ban
if [[ "$SSH_PROTECTION" == y ]]; then
  CHAINS=(f2b-sshd f2b-recidive)
  [[ "$ADGUARD_HOME" == y ]] && CHAINS+=(f2b-adguard-panel)

  for CH in "${CHAINS[@]}"; do
    if ipt  -t filter -nL "$CH" &>/dev/null; then
      ipt  -D INPUT -j "$CH" 2>/dev/null
      ipt  -I INPUT 1 -j "$CH"
    fi
    if ipt6 -t filter -nL "$CH" &>/dev/null; then
      ipt6 -D INPUT -j "$CH" 2>/dev/null
      ipt6 -I INPUT 1 -j "$CH"
    fi
  done
fi
#F2B_END

# ── 10-bis.  Подключаем дополнительные public-IP, нужные для SNAT ──
declare -A EXT_ADDED
for MAP in "${SNAT_MAP[@]}"; do
    IFS='=' read -r _ EXT <<< "$MAP"
    is_ip_v4 "$EXT" || { echo "⚠ bad IP $EXT — пропущен"; continue; }
    [[ -n ${EXT_ADDED[$EXT]+x} ]] && continue       # уже добавлен
    if ! ip -o -4 addr show dev "$INTERFACE" \
            | awk '{print $4}' | cut -d/ -f1 | grep -qx "$EXT"; then
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

# DNAT DNS → AdGuard Home
#AGH_START
if [[ "$ADGUARD_HOME" == y ]]; then
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (DNAT) — пропущен"; continue; }
  add nat PREROUTING -s "$NET" ! -d "$EXT4_IP" -p udp --dport 53 -j DNAT --to-destination "$EXT4_IP"
  add nat PREROUTING -s "$NET" ! -d "$EXT4_IP" -p tcp --dport 53 -j DNAT --to-destination "$EXT4_IP"
done < <(all_dnat)
while IFS= read -r NET; do
  is_cidr_v4 "$NET" || { echo "⚠ bad CIDR $NET (POST_DNAT) — пропущен"; continue; }
  add nat POSTROUTING -s "$NET" -d "${EXT4_IP}/32" -j MASQUERADE
done < <(all_post_dnat)
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

# скрипт дошёл до конца → страховка больше не нужна
[[ -n "$AT_JOB_ID" ]] && command -v atrm &>/dev/null && atrm "$AT_JOB_ID"
