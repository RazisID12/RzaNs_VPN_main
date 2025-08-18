#!/bin/bash
# DOWN-script – снимает ровно то, что ставит up.sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

set -eEuo pipefail
trap 'echo "ERR on line $LINENO – cmd: $BASH_COMMAND" >&2; exit 1' ERR
# подключаем общий модуль (yaml_get / _yaml_merged и т.п.)
. /opt/rzans_vpn_main/settings/settings.sh
_ensure_settings_yaml                  # гарантируем наличие settings.yaml
shopt -s expand_aliases
YQ_BIN=${YQ_BIN:-yq}

mkdir -p /var/lib/ipset
IPSET_BAN_STATE=/var/lib/ipset/ipset-bans.rules
IPSET_ALLOW_STATE=/var/lib/ipset/ipset-allow.rules

# Снять возможные отложенные fallback-джобы (ставит up.sh в очередь Z)
if command -v at >/dev/null 2>&1 && command -v atrm >/dev/null 2>&1; then
  at -q Z -l 2>/dev/null \
    | awk '$1 ~ /^[0-9]+$/ {print $1}' \
    | xargs -r atrm || true
fi

# --- choose iptables backend consistently (nft pinned) ---
IPT_BIN=$(command -v iptables-nft || echo iptables)
IP6T_BIN=$(command -v ip6tables-nft || echo ip6tables)
echo "Using iptables backend: $("$IPT_BIN" -V)" >&2
alias ipt="$IPT_BIN -w"
HAS_IP6=y; command -v "$IP6T_BIN" >/dev/null || HAS_IP6=n
ipt6() { if [[ $HAS_IP6 == y ]]; then "$IP6T_BIN" -w "$@"; else return 0; fi; }

# helpers (такие же, как в up.sh)
is_ip_v4()   { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]; }
# mini-helper, нужен для проверки наличия yq
_have(){ command -v "$1" >/dev/null 2>&1; }

## ── 0a. Аккуратный демонтаж DNS egress-якорей в filter/OUTPUT ───────────────
# v4: снять переходы OUTPUT → RZANS_DNS_EGRESS и удалить цепь
ipt -t filter -S OUTPUT \
  | awk -v ch="RZANS_DNS_EGRESS" \
      '$0 ~ (" -A OUTPUT ") && $0 ~ (" -j " ch "($| )") {sub(/^-A OUTPUT /,""); print}' \
  | while read -r spec; do ipt -t filter -D OUTPUT $spec 2>/dev/null || true; done
ipt -t filter -F RZANS_DNS_EGRESS 2>/dev/null || true
ipt -t filter -X RZANS_DNS_EGRESS 2>/dev/null || true

# v6: аналогично, если доступен ip6tables
if [[ "$HAS_IP6" == y ]]; then
  ipt6 -t filter -S OUTPUT \
    | awk -v ch="RZANS_DNS6_EGRESS" \
        '$0 ~ (" -A OUTPUT ") && $0 ~ (" -j " ch "($| )") {sub(/^-A OUTPUT /,""); print}' \
    | while read -r spec; do ipt6 -t filter -D OUTPUT $spec 2>/dev/null || true; done
  ipt6 -t filter -F RZANS_DNS6_EGRESS 2>/dev/null || true
  ipt6 -t filter -X RZANS_DNS6_EGRESS 2>/dev/null || true
fi

## ── 0-bis. Аккуратный демонтаж наших NAT-хуков/цепочек ─────────────
# Снимаем PREROUTING-правила, ведущие в наши цепочки, и удаляем сами цепочки.
# Делается ДО общего flush, чтобы не зависеть от «глухого» режима.
for CH in RZANS_VPN_MAIN-MAPPING RZANS_DNS_S RZANS_DNS_F; do
  ipt -t nat -S PREROUTING \
    | awk -v ch="$CH" \
        '$0 ~ (" -A PREROUTING ") && $0 ~ (" -j " ch "($| )") {sub(/^-A PREROUTING /,""); print}' \
    | while read -r spec; do ipt -t nat -D PREROUTING $spec 2>/dev/null || true; done
  ipt -t nat -F "$CH" 2>/dev/null || true
  ipt -t nat -X "$CH" 2>/dev/null || true
done

## 1) читаем settings.yaml (симметрично up.sh)
read_settings() {
  # Значения по умолчанию используем те же, что в up.sh
  # --- SNAT-карты -----------------------------------------------------
  if _have yq; then
    readarray -t SNAT_MAP < <(
      _yaml_merged \
      | "$YQ_BIN" e -r '
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

# ── 3. политики → ACCEPT & flush встроенных цепей ───────────────────
# IPv4 (всегда)
ipt -P INPUT   ACCEPT
ipt -P OUTPUT  ACCEPT
ipt -P FORWARD ACCEPT
# flush-им ВСЮ таблицу filter (встроенные + пользовательские) одним вызовом
ipt -t filter -F
ipt -t filter -X 2>/dev/null || true
# ── NAT: возвращаем «как раньше» — полный flush ────────────────────
#    (пользовательские цепочки удаляем после flush’а)
ipt -t nat -F

# удалить ВСЕ пользовательские цепочки (если остались)
ipt -t nat -X 2>/dev/null || true

# SNAT-правила из SNAT_MAP — на случай, если кто-то добавил их вручную
# и общий flush не прошёл.
for MAP in "${SNAT_MAP[@]}"; do
  IFS='=' read -r SRC EXT <<<"$MAP"
  # если EXT == 0.0.0.0 (MASQUERADE в up.sh), отдельного SNAT-правила нет — пропускаем
  [[ "$EXT" == "0.0.0.0" ]] && continue
  ipt -t nat -D POSTROUTING -s "${SRC}/32" -o "$INTERFACE" -j SNAT --to-source "$EXT" 2>/dev/null || true
done

# IPv6 — только если ip6tables доступна; порядок как у IPv4: политики → flush
if [[ "$HAS_IP6" == y ]]; then
  ipt6 -P INPUT   ACCEPT
  ipt6 -P OUTPUT  ACCEPT
  ipt6 -P FORWARD ACCEPT
  ipt6 -t filter -F
  ipt6 -t filter -X 2>/dev/null || true
  ipt6 -t nat -F 2>/dev/null || true
  # удалить все пользовательские цепочки (одним вызовом)
  ipt6 -t nat -X 2>/dev/null || true
fi

# полная зачистка mangle ──────────────────────────────
ipt  -t mangle -F
ipt  -t mangle -X 2>/dev/null || true
ipt6 -t mangle -F 2>/dev/null || true
ipt6 -t mangle -X 2>/dev/null || true

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

# — fallback: если SNAT_MAP пуст (нет yq), снимем все адреса с label $IFACE:snat
while read -r ip4; do
  ip addr del "$ip4/32" dev "$INTERFACE" 2>/dev/null || true
done < <(ip -o -4 addr show dev "$INTERFACE" label "${INTERFACE}:snat" \
         | awk '{split($4,a,"/"); print a[1]}')

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
SYSCTL_FILE="/etc/sysctl.d/99-rzans_vpn_main.conf"
if [[ -f "$SYSCTL_FILE" ]]; then
  rm -f "$SYSCTL_FILE"
  sysctl --system >/dev/null || true
  # Если ключи не заданы в других sysctl-конфигах, вернуть к безопасным дефолтам
  _has_key() {
    grep -Rqs "^[[:space:]]*$1[[:space:]]*=" /etc/sysctl.conf /etc/sysctl.d 2>/dev/null
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
  _has_key "net.ipv4.tcp_syncookies" || sysctl -w net.ipv4.tcp_syncookies=0 >/dev/null 2>&1 || true

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
rm -f /run/rzans_vpn_main/cache_hash 2>/dev/null || true

# явный маркер успешного завершения
echo "down: done"
