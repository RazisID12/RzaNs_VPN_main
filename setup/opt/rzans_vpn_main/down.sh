#!/bin/bash
# DOWN-script – снимает ровно то, что ставит up.sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

set -eEuo pipefail
trap 'echo "ERR on line $LINENO – cmd: $BASH_COMMAND" >&2; exit 1' ERR
shopt -s expand_aliases

# единые алиасы
# ── auto-detect iptables -w ─────────────────────────────────────────
if iptables -w -L >/dev/null 2>&1; then
  alias ipt='iptables -w'
else
  echo "⚠ iptables без -w; down.sh будет блокировать" >&2
  alias ipt='iptables'
fi

# helpers (такие же, как в up.sh)
is_ip_v4()   { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]; }
is_ip_v6() {
  [[ $1 =~ ^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(::)|(::ffff:(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$ ]]
}
is_port()    { [[ $1 =~ ^[0-9]+$ ]] && (( 1 <= $1 && $1 <= 65535 )); }

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

# ── 1. читаем settings.map (симметрично up.sh) ──────────────────────
read_settings() {
  # ------------------------------------------------------------------------
  # shellcheck disable=SC2034
  # Переменные ниже читаются только для симметрии с up.sh.
  # В рамках down.sh они не используются, поэтому подавляем
  # предупреждение “appears unused” (SC2034).
  # ------------------------------------------------------------------------
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
  [[ -s $SETTINGS ]] || { echo "ERROR: $SETTINGS missing or empty"; exit 1; }

  # разбиваем по пробелу/TAB, но не по \n — как в up.sh
  # «rest» тянет все оставшиеся токены
  while IFS=$' \t' read -r tag a b rest; do
    tag=${tag//$'\r'/}; a=${a//$'\r'/}; b=${b//$'\r'/}
    if [[ "$tag" == \#* || -z "$tag" ]]; then continue; fi
    if [[ -z $a ]]; then
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
          [[ -z "$ip" ]]        && continue          # пропускаем пустые токены
          [[ "$ip" == \#* ]]     && break             # комментарий — конец списка
          if [[ "$ip" == 0.0.0.0 ]]; then
            :                                        # «открыто всем» → не кладём в массив
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
            :                                        # «закрыто всем»
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
        fi ;;
    esac
  done < "$SETTINGS"

  # --- удаляем дубликаты, сохраняя порядок появления -------------
  if ((${#TRUST4_LIST[@]})); then
    readarray -t TRUST4_LIST < <(printf '%s\n' "${TRUST4_LIST[@]}" | awk '!seen[$0]++')
  fi
  if ((${#TRUST6_LIST[@]})); then
    readarray -t TRUST6_LIST < <(printf '%s\n' "${TRUST6_LIST[@]}" | awk '!seen[$0]++')
  fi

  # --- SNAT: удаляем повторяющиеся SRC=EXT-пары, сохраняя первый порядок —
  if ((${#SNAT_MAP[@]})); then
    readarray -t SNAT_MAP < <(printf '%s\n' "${SNAT_MAP[@]}" | awk '!seen[$0]++')
  fi

  if { [[ -n $VPN_MAP_SRC4 && -z $VPN_MAP_DST4 ]] || [[ -z $VPN_MAP_SRC4 && -n $VPN_MAP_DST4 ]]; }; then
    echo "⚠ settings.map: VPN_MAP_SRC4 и VPN_MAP_DST4 должны быть заданы одновременно — игнорированы" >&2
    VPN_MAP_SRC4=""; VPN_MAP_DST4=""
  fi

  is_port "$SVPN_PORT" || SVPN_PORT="500"
  is_port "$FVPN_PORT" || FVPN_PORT="4500"
  [[ -z "$SVPN_NET4" ]] && SVPN_NET4="10.29.8.0/24"
  [[ -z "$FVPN_NET4" ]] && FVPN_NET4="10.28.8.0/24"
  [[ -z $VPN_MAP_SRC4 ]] && VPN_MAP_SRC4="10.29.8.0/24"
  [[ -z $VPN_MAP_DST4 ]] && VPN_MAP_DST4="10.30.0.0/15"

  ADGUARD_HOME=${ADGUARD_HOME,,}
  [[ $ADGUARD_HOME == y ]] || ADGUARD_HOME="n"
  SSH_PROTECTION=${SSH_PROTECTION,,}
  [[ $SSH_PROTECTION == y ]] || SSH_PROTECTION="n"
}

read_settings

# ── 2. базовые переменные ───────────────────────────────────────────
[[ -z "${1:-}" ]] && IFACE=$(ip route | awk '/^default/{print $5;exit}') || IFACE=$1
# IPv4
if [[ -n "$EXT4_IP_CFG" && "$EXT4_IP_CFG" != "0.0.0.0" ]]; then
  EXT4_IP=$EXT4_IP_CFG
else
  EXT4_IP=$(ip -o -4 addr show dev "$IFACE" scope global \
           | awk '{print $4; exit}' | cut -d/ -f1)
fi
# IPv6
if [[ -n "$EXT6_IP_CFG" && "$EXT6_IP_CFG" != "::" ]]; then
  EXT6_IP=$EXT6_IP_CFG
else
  EXT6_IP=$(ip -o -6 addr show dev "$IFACE" scope global \
            | awk '{print $4; exit}' | cut -d/ -f1)
fi

# ── ipset ──────────────────────────
if command -v ipset &>/dev/null; then
  HAS_IPSET=y
else
  HAS_IPSET=n
fi

# ── 3. политики → ACCEPT & flush встроенных цепей ───────────────────
# IPv4 (всегда)
ipt -P INPUT   ACCEPT
ipt -P OUTPUT  ACCEPT
ipt -P FORWARD ACCEPT
# flush-им ВСЮ таблицу filter (встроенные + пользовательские) одним вызовом
ipt -t filter -F
ipt -t filter -X 2>/dev/null || true
# ── NAT: возвращаем «как раньше» — полный flush ────────────────────
#    (пользовательские DNS-цепочки и Mapping удаляем после flush’а)
# flush
ipt -t nat -F
# удалить ВСЕ пользовательские цепочки (если остались)
ipt -t nat -X 2>/dev/null || true
# плюс явная зачистка наших стабильных DNS‑цепочек (на случай старых версий)
ipt -t nat -X RZANS_DNS_S 2>/dev/null || true
ipt -t nat -X RZANS_DNS_F 2>/dev/null || true
ipt -t nat -X RZANS_DNS   2>/dev/null || true

# SNAT-правила из SNAT_MAP — дублировать не вредно, но оставляем на случай,
# если кто-то добавил их вручную и flush по каким-то причинам не прошёл.
for MAP in "${SNAT_MAP[@]}"; do
  IFS='=' read -r SRC EXT <<<"$MAP"
  ipt -t nat -D POSTROUTING -s "${SRC}/32" -j SNAT --to-source "$EXT" 2>/dev/null || true
done

# удаляем цепочку Mapping (после flush она пустая)
ipt -t nat -X RZANS_VPN_MAIN-MAPPING 2>/dev/null || true

# IPv6 — только если ip6tables доступна; порядок как у IPv4: политики → flush
if [[ "$HAS_IP6" == y ]]; then
  ipt6 -P INPUT   ACCEPT
  ipt6 -P OUTPUT  ACCEPT
  ipt6 -P FORWARD ACCEPT
  ipt6 -t filter -F
  ipt6 -t filter -X 2>/dev/null || true
  ipt6 -t nat -F 2>/dev/null || true
  # удалить все пользовательские цепочки
  ipt6 -t nat -X 2>/dev/null || true
  # дальше точечно чистим наши, вдруг остались
  ipt6 -t nat -X RZANS_DNS_S 2>/dev/null || true
  ipt6 -t nat -X RZANS_DNS_F 2>/dev/null || true
  ipt6 -t nat -X RZANS_DNS   2>/dev/null || true
  ipt6 -t nat -X RZANS_VPN_MAIN-MAPPING 2>/dev/null || true
fi

# полная зачистка mangle и raw ──────────────────────────────
ipt  -t mangle -F
ipt  -t mangle -X 2>/dev/null || true
ipt  -t raw    -F
ipt  -t raw    -X 2>/dev/null || true
ipt6 -t mangle -F 2>/dev/null || true
ipt6 -t mangle -X 2>/dev/null || true
ipt6 -t raw    -F 2>/dev/null || true
ipt6 -t raw    -X 2>/dev/null || true

# ── 4. снимаем /32-адреса, добавленные для SNAT ─────────────────────
declare -A EXT_DONE
for MAP in "${SNAT_MAP[@]}"; do
  IFS='=' read -r _ ext <<< "$MAP"
    is_ip_v4 "$ext" || { echo "⚠ bad IP $ext — пропущен"; continue; }
    [[ -n ${EXT_DONE[$ext]+x} ]] && continue
  if ip -4 addr show dev "$IFACE" to "$ext"/32 &>/dev/null; then
      # shellcheck disable=SC2086
      ip addr del "$ext/32" dev "$IFACE" 2>/dev/null || true
  fi
  EXT_DONE[$ext]=1
done

# ── 5. сохраняем ipset-баны (сами сеты не удаляем — up.sh их переиспользует) ─
if [[ "$HAS_IPSET" == y ]]; then
  # ── удалить временные наборы, созданные up.sh ─────────────────────────────
  #    • ipset-watch       / ipset-watch6   – отслеживание «новых» соединений
  #    • ipset-allow       / ipset-allow6   – белые сети/хосты
  #    Они нужны только во время работы сервиса, поэтому при остановке
  #    полностью уничтожаем, чтобы:
  #      1) не сохранялись в ipset-bans.rules;
  #      2) не занимали память.
  for S in ipset-watch ipset-watch6 ipset-allow ipset-allow6; do
      ipset flush   "$S" 2>/dev/null || true   # на случай, если set ещё живой
      ipset destroy "$S" 2>/dev/null || true   # игнорируем «does not exist»
  done

  mkdir -p /var/lib/ipset
  ipset save -f /var/lib/ipset/ipset-bans.rules
fi

# ── 6. симметричный откат sysctl ───────────────────────────────────
SYSCTL_FILE="/etc/sysctl.d/99-rzans_vpn_main.conf"
if [[ -f "$SYSCTL_FILE" ]]; then
  rm -f "$SYSCTL_FILE"
  sysctl --system >/dev/null
  # Если ключи не заданы в других sysctl-конфигах, вернуть к безопасным дефолтам
  _has_key() {
    grep -Rqs "^[[:space:]]*$1[[:space:]]*=" /etc/sysctl.conf /etc/sysctl.d 2>/dev/null
  }
  _has_key "net.ipv4.ip_forward" || sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
  _has_key "net.ipv4.conf.all.route_localnet" || sysctl -w net.ipv4.conf.all.route_localnet=0 >/dev/null 2>&1 || true
fi
