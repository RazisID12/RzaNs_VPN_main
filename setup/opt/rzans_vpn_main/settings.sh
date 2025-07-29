#!/usr/bin/env bash
# shellcheck shell=bash

# фиксируем POSIX-локаль, чтобы регэкспы/пробелы в awk/sed вели себя одинаково
export LC_ALL=C

# чтобы strict-mode (set -u) не ругался,
# объявим служебные переменные заранее
tmp=""; old=""

# Точка правды для пути к settings.map (можно переопределить до source)
: "${SETTINGS:=/opt/rzans_vpn_main/settings.map}"

# ──────────────────────────────────────────────────────────────────────────────
# Публичные функции:
#   settings_heal     — создать/восстановить settings.map целиком по шаблону,
#                            сохранив пользовательские значения и дополнительные
#                            TRUST/SNAT строки.
#   settings_pretty        — выровнять файл по колонкам.
#   settings_get_tag TAG DEFAULT
#   agh_heal               — создать/восстановить /opt/AdGuardHome/AdGuardHome.yaml
#                            по шаблону, заполнив динамические поля из settings.map
#                            (bind_hosts, upstream_dns, bootstrap/fallback, allowed_clients).
#                         — вернуть значение тега или DEFAULT.
#   ipv4_host CIDR        — вернуть первый IPv4‑хост из сети
#                           (пример: 10.29.8.0/24 → 10.29.8.1).
#                           Для /31 и /32 функция вернёт ip+1; обычно такие
#                           маски не используются в наших конфигурациях.
#   vpn_addrs_from_cidrs SVPN_NET4 FVPN_NET4
#                         — установить: SVPN_IP, FVPN_IP, SVPN_ADDR, FVPN_ADDR,
#                           SVPN_DNS_IP, FVPN_DNS_IP.
# ──────────────────────────────────────────────────────────────────────────────

settings_heal() {
  _settings__ensure_placeholder
  _settings__restore_full_from_template
  _settings__annotate_upstream
  settings_pretty
}

settings_pretty() {
  [[ -f "$SETTINGS" ]] || return 0

  # вычисляем ширину колонки (минимум 22, +1 пробел)
  local pad
  pad=$(awk '
    /^[[:space:]]*#/ || NF==0 {next}
    { if (length($1) > m) m = length($1) }
    END {
      w = (m < 22 ? 22 : m + 1);
      if (w > 64) w = 64;
      print w
    }' "$SETTINGS")

  local tmp; tmp=$(mktemp)
  awk -v pad="$pad" '
    /^#/ || NF==0 {print; next}
    {
      key=$1; $1="";
      sub(/^ +/,"");
      printf "%-*s %s\n", pad, key, $0
    }' "$SETTINGS" >"$tmp" && mv "$tmp" "$SETTINGS"
  chmod 600 "$SETTINGS"
}

# ── Upstream DNS helpers (комментарий к активному набору) ────────────────────
_upstream_comment() {          # $1 = 1|2|3
  case "$1" in
    1) echo "Cloudflare  v4: 1.1.1.1 1.0.0.1   v6: 2606:4700:4700::1111 2606:4700:4700::1001" ;;
    2) echo "Quad9       v4: 9.9.9.10 149.112.112.10   v6: 2620:fe::10 2620:fe::fe:10" ;;
    3) echo "Google      v4: 8.8.8.8 8.8.4.4   v6: 2001:4860:4860::8888 2001:4860:4860::8844" ;;
    *) _upstream_comment 1 ;;
  esac
}

# ── Helper: динамический зазор, чтобы первый «#» оказался на ~40‑й колонке
#    • $1 — строка «TAG  value» без хвоста
#    • если ключ+значение длиннее цели — добавляем всего 1 пробел
_gap40() {
  local tgt=40 len=${#1}
  (( len >= tgt )) && { printf ' '; return; }
  printf '%*s' $((tgt - len)) ''
}

# вставить / обновить комментарий к ADGUARD_HOME
settings_set_agh_comment() {
  local ver="$1" dat="$2"
  [[ -f "$SETTINGS" ]] || return 0
  # оставляем значение (y|n) как есть, полностью переписываем хвост комментария
  local head gap
  head=$(grep -Eo '^(ADGUARD_HOME[[:space:]]+[ynYN])' "$SETTINGS")
  gap=$(_gap40 "$head")
  sed -i -r \
    "s|^(ADGUARD_HOME[[:space:]]+[ynYN])[[:space:]]*(#.*)?$|\\1${gap}# v${ver}   updated: ${dat}|" \
    "$SETTINGS"
}

# вставить / обновить комментарий к SSH_PROTECTION (вызывает update.sh)
settings_set_ssh_comment() {
  local ver="$1" dat="$2"
  [[ -f "$SETTINGS" ]] || return 0
  local head gap
  head=$(grep -Eo '^(SSH_PROTECTION[[:space:]]+[ynYN])' "$SETTINGS")
  gap=$(_gap40 "$head")
  sed -i -r \
    "s|^(SSH_PROTECTION[[:space:]]+[ynYN])[[:space:]]*(#.*)?$|\\1${gap}# v${ver}   updated: ${dat}|" \
    "$SETTINGS"
}

# ── Полные пары апстримов (v4a v4b v6a v6b) ────────────────────────────────
# upstream_pair_full — IPv4+IPv6;  upstream_pair_v4 — только IPv4
upstream_pair_full() {        # 1|2|3 → "v4a v4b v6a v6b"
  case "$1" in
    1) echo "1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001" ;; # Cloudflare
    2) echo "9.9.9.10 149.112.112.10 2620:fe::10 2620:fe::fe:10"       ;;  # Quad9
    3) echo "8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844" ;; # Google
    *) upstream_pair_full 1 ;;
  esac
}

# только IPv4 (для kresd/proxy etc.)
upstream_pair_v4() {          # 1|2|3 → "v4a v4b"
  local a b c d; read -r a b c d <<<"$(upstream_pair_full "$1")"
  printf '%s %s\n' "$a" "$b"
}

# ── Унифицированное обновление systemd‑resolved и /etc/network/interfaces ──
_update_system_dns() {
  local sel; sel="$(_normalize_upstream_sel "$(settings_get_tag UPSTREAM_DNS 1)")"
  local DNS4_1 DNS4_2 DNS6_1 DNS6_2
  read -r DNS4_1 DNS4_2 DNS6_1 DNS6_2 <<<"$(upstream_pair_full "$sel")"

  # IPv6 есть?
  local IPV6_AVAIL=n
  [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" == 0 ]] \
    && ip -6 route show default 2>/dev/null | grep -q . && IPV6_AVAIL=y

  # ── systemd‑resolved ────────────────────────────────────────────────
  local RESCONF=/etc/systemd/resolved.conf
  grep -q '^\[Resolve\]' "$RESCONF" 2>/dev/null || echo '[Resolve]' >>"$RESCONF"
  sed -i -r '/^[[:space:]]*DNS=/d' "$RESCONF"
  local DNS_LINE="DNS=${DNS4_1} ${DNS4_2}"
  [[ $IPV6_AVAIL == y ]] && DNS_LINE+=" ${DNS6_1} ${DNS6_2}"
  sed -i "/^\[Resolve\]/a ${DNS_LINE}" "$RESCONF"
  systemctl restart systemd-resolved 2>/dev/null || true

  # ── /etc/network/interfaces (если существует) ───────────────────────
  if [[ -f /etc/network/interfaces ]]; then
    if [[ $IPV6_AVAIL == y ]]; then
      local TMP_IF; TMP_IF=$(mktemp /etc/network/interfaces.XXXXXX)
      awk -v v4="dns-nameservers ${DNS4_1} ${DNS4_2}" \
          -v v6="dns-nameservers ${DNS6_1} ${DNS6_2}" '
        function flush(){if(sec=="v4"&&!dns)print "    "v4; if(sec=="v6"&&!dns)print "    "v6; sec=""; dns=0}
        /^[[:space:]]*iface .* inet6 static/{flush();sec="v6";dns=0;print;next}
        /^[[:space:]]*iface .* inet static/{flush();sec="v4";dns=0;print;next}
        # первая строка dns‑nameservers → заменяем; остальные в том же iface пропускаем
        sec && /^[[:space:]]*dns-nameservers/{
          if(!dns){
            dns=1
            if(sec=="v4") print "    " v4; else print "    " v6
          }
          next     # пропускаем исходную строку в любом случае
        }
        {print}
        END{flush()}' /etc/network/interfaces >"$TMP_IF" \
      && mv -f "$TMP_IF" /etc/network/interfaces \
      || { rm -f "$TMP_IF"; return 1; }
    else
      local TMP_IF; TMP_IF=$(mktemp /etc/network/interfaces.XXXXXX)
      awk -v v4="dns-nameservers ${DNS4_1} ${DNS4_2}" '
        function flush(){if(sec=="v4"&&!dns)print "    "v4; sec=""; dns=0}
        /^[[:space:]]*iface .* inet static/{flush();sec="v4";dns=0;print;next}
        # первая строка dns‑nameservers → заменяем; остальные в том же iface пропускаем
        sec && /^[[:space:]]*dns-nameservers/{
          if(!dns){
            dns=1
            print "    " v4
          }
          next
        }
        {print}
        END{flush()}' /etc/network/interfaces >"$TMP_IF" \
      && mv -f "$TMP_IF" /etc/network/interfaces \
      || { rm -f "$TMP_IF"; return 1; }
    fi
  fi
}

# Проставить комментарий к `UPSTREAM_DNS` в settings.map
_settings__annotate_upstream() {
  local raw val sel comment
  # Считываем фактическое значение тега, не подставляя дефолт
  raw="$(_settings__get_raw_val UPSTREAM_DNS)"
  val="$(printf '%s' "$raw" | _settings__strip_comment)"

  # Если тег присутствует и имеет нетипичное значение — предупреждаем и НЕ правим файл
  if [[ -n "$val" && ! "$val" =~ ^[1-3]$ ]]; then
    echo "WARNING: UPSTREAM_DNS has unexpected value '${val}'. Expected: 1=Cloudflare, 2=Quad9, 3=Google. Leaving line unchanged." >&2
    return 0
  fi

  # Нормализуем выбор для формирования подписи (если тега нет — считаем 1)
  sel="$(_normalize_upstream_sel "$(settings_get_tag UPSTREAM_DNS 1)")"
  comment="$(_upstream_comment "$sel")"

  # динамический зазор, как для AGH/F2B
  local head gap
  head=$(grep -Eo '^(UPSTREAM_DNS[[:space:]]+[^[:space:]]+)' "$SETTINGS")
  gap=$(_gap40 "$head")
  sed -i -r "s|^(UPSTREAM_DNS[[:space:]]+[^[:space:]]+).*|\\1${gap}# ${comment}|" "$SETTINGS"
}

settings_get_tag() {          # settings_get_tag TAG DEFAULT
  local tag="$1" def="$2" line
  # POSIX-класс вместо \s, stderr → /dev/null (убираем warning’и awk)
  line=$(awk -v t="^[[:space:]]*${tag}[[:space:]]+" \
             '$0~t && $0!~/^[[:space:]]*#/{ $1=""; sub(/^[[:space:]]+/,""); print; exit }' \
             "$SETTINGS" 2>/dev/null \
        | sed -r 's/[[:space:]]*#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')
  [[ -n $line ]] && printf '%s' "$line" || printf '%s' "$def"
}
# ── Общий helper: первый хост IPv4 в CIDR (корректно для любых масок) ────────
# Пример: ipv4_host "10.29.8.0/24"   → "10.29.8.1"
#         ipv4_host "10.29.8.128/25" → "10.29.8.129"

ipv4_host() {
  local cidr="$1" ip mask a b c d ip_i mask_i net first
  ip=${cidr%/*}; mask=${cidr#*/}
  IFS='.' read -r a b c d <<<"$ip" || return 1
  (( mask >= 0 && mask <= 32 )) || return 1
  ip_i=$(( (a<<24) | (b<<16) | (c<<8) | d ))
  mask_i=$(( mask==0 ? 0 : ((0xFFFFFFFF << (32-mask)) & 0xFFFFFFFF) ))
  net=$(( ip_i & mask_i ))
  first=$(( net + 1 ))
  printf '%d.%d.%d.%d' \
    $(((first>>24)&255)) $(((first>>16)&255)) $(((first>>8)&255)) $((first&255))
}

# ── Derived VPN helpers (stateless) ───────────────────────────────────────────
# Usage: vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4"
# Sets:  SVPN_IP, FVPN_IP, SVPN_ADDR, FVPN_ADDR, SVPN_DNS_IP, FVPN_DNS_IP
#
# Примечание: для масок /31 и /32 адрес интерфейса берётся как сам IP сети
# (без +1), т.к. инкремент не имеет смысла.
vpn_addrs_from_cidrs() {
  local svpn="$1" fvpn="$2"
  local m1="${svpn#*/}" m2="${fvpn#*/}"
  if [[ "$m1" =~ ^[0-9]+$ ]] && (( m1 >= 31 )); then
    SVPN_IP="${svpn%/*}"
  else
    SVPN_IP="$(ipv4_host "$svpn")" || return 1
  fi
  if [[ "$m2" =~ ^[0-9]+$ ]] && (( m2 >= 31 )); then
    FVPN_IP="${fvpn%/*}"
  else
    FVPN_IP="$(ipv4_host "$fvpn")" || return 1
  fi
  SVPN_ADDR="$SVPN_IP/${svpn##*/}"
  FVPN_ADDR="$FVPN_IP/${fvpn##*/}"
  SVPN_DNS_IP="$SVPN_IP"
  FVPN_DNS_IP="$FVPN_IP"
}

# ──────────────────────────────────────────────────────────────────────────────
# Внутренние (служебные) функции
# ──────────────────────────────────────────────────────────────────────────────

_settings__ensure_placeholder() {
  if [[ ! -e "$SETTINGS" || ! -s "$SETTINGS" ]]; then
    local dir
    dir=$(dirname -- "$SETTINGS")
    mkdir -p "$dir"
    printf '# placeholder\n' >"$SETTINGS"
    chmod 600 "$SETTINGS"
  fi
}

_settings__template() {
  cat <<'EOF'
# ========================================================================================
# settings.map (минимальный автосозданный шаблон)
# ========================================================================================
# ─── Базовые параметры ──────────────────────────────────────────────────────────────────
# Внешние IP:
EXTIP4                        0.0.0.0                       # 0.0.0.0 ⇒ авто
EXTIP6                        ::                            # ::      ⇒ авто
# Вышестоящий DNS: 1 = Cloudflare | 2 = Quad9 | 3 = Google
UPSTREAM_DNS                  1                             # IPv4: 1.1.1.1 1.0.0.1   IPv6: 2606:4700:4700::1111 2606:4700:4700::1001
# ─── Параметры безопасности ─────────────────────────────────────────────────────────────
# Доверенные IPv4/IPv6 для SSH/Fail2ban/AdGuard Home:
TRUST4                        0.0.0.0                       # 0.0.0.0 ⇒ по IPv4 открыт для всех
TRUST6                        ::                            # ::      ⇒ по IPv6 закрыт для всех
# ─── Параметры VPN ──────────────────────────────────────────────────────────────────────
# Домен:
WIREGUARD_HOST                ""
# Порты:
SVPN_PORT                     500                           # Для Split VPN
FVPN_PORT                     4500                          # Для Full  VPN
# Подсети IPv4:
SVPN_NET4                     10.29.8.0/24                  # Для Split VPN
FVPN_NET4                     10.28.8.0/24                  # Для Full  VPN
# Fake-IP диапазон для proxy.py
VPN_MAP_SRC4                  10.29.8.0/24
VPN_MAP_DST4                  10.30.0.0/15
# SNAT <internal IP> <external IP>
SNAT                          0.0.0.0 0.0.0.0               # User 1
SNAT                          0.0.0.0 0.0.0.0               # User 2
# ─── Сервисы ────────────────────────────────────────────────────────────────────────────
# Fail2ban:
SSH_PROTECTION                n                             # version   updated: dd.mm.year
# AdGuard Home:
ADGUARD_HOME                  n                             # version   updated: dd.mm.year
# ─── Маршрутизация (doall.sh) ───────────────────────────────────────────────────────────
ROUTE_ALL                     n
DISCORD_INCLUDE               y
CLOUDFLARE_INCLUDE            y
AMAZON_INCLUDE                n
HETZNER_INCLUDE               n
DIGITALOCEAN_INCLUDE          n
OVH_INCLUDE                   n
TELEGRAM_INCLUDE              y
GOOGLE_INCLUDE                n
AKAMAI_INCLUDE                n
# ========================================================================================
EOF
}

_settings__get_raw_val() {          # $1 = TAG → "value [# comment...]" без ключа
  awk -v t="^[[:space:]]*$1[[:space:]]+" '
      $0~t && $0!~/^[[:space:]]*#/ { $1=""; sub(/^[[:space:]]+/,""); print; exit }' \
      "$SETTINGS" 2>/dev/null \
  | sed -r 's/[[:space:]]+$//'
}

_settings__strip_comment() {  # stdin -> stdout (без хвостового #...)
  sed -r 's/[[:space:]]*#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//'
}

_settings__restore_full_from_template() {
  # временные файлы создаём здесь, удаляем вручную в конце функции
  local old tmp pad
  tmp=$(mktemp)
  old=$(mktemp)

  cp -f "$SETTINGS" "$old" 2>/dev/null || :

  # динамический pad: длина самого длинного тега, минимум 22 (+1 пробел)
  pad=$(
    _settings__template | awk '
      /^[[:space:]]*#/ || NF==0 {next}
      { if (length($1) > m) m = length($1) }
      END { w=(m<22?22:m+1); if (w>64) w=64; print w }' )

  while IFS= read -r line; do
    # Пустые и комментарии: копируем 1:1
    if [[ -z "$line" || "$line" == \#* ]]; then
      printf '%s\n' "$line" >>"$tmp"
      continue
    fi

    # Тег + «дефолт» (значение +, возможно, комментарий)
    local tag def raw val comment
    tag=${line%%[[:space:]]*}
    def=${line#"$tag"}                 # всё, что после тега в шаблоне
    raw=$(_settings__get_raw_val "$tag")

    # user-value без комментария
    val=$(printf '%s' "$raw" | _settings__strip_comment)

    # комментарий: берём существующий "# v…" если он есть, иначе — шаблонный
    # переносим **весь** хвост «# v… updated: …» (до конца строки)
    comment=$(printf '%s' "$raw" | grep -oE '#[[:space:]]*v[^#]*$' || true)
    if [[ -z "$comment" ]]; then
      comment=$(printf '%s' "$def" | grep -oE '#.*$' || true)
    fi

    if [[ -n "$val" ]]; then
      # значение есть у пользователя — печатаем его и добавляем шаблонный комментарий
      if [[ -n "$comment" ]]; then
        printf "%-*s %s  %s\n" "$pad" "$tag" "$val" "$comment" >>"$tmp"
      else
        printf "%-*s %s\n" "$pad" "$tag" "$val" >>"$tmp"
      fi
    else
      # значения нет / пусто — печатаем дефолтную строку
      local def_trimmed
      def_trimmed=$(printf '%s' "$def" | sed -r 's/^[[:space:]]+//')
      printf "%-*s%s\n" "$pad" "$tag" "$def_trimmed" >>"$tmp"
    fi
  done < <(_settings__template)

  # --- дополнительные TRUST4/6 и SNAT с дедупликацией
  # добавляем все TRUST4/6, кроме первой строки каждого тега
  awk '
    BEGIN { IGNORECASE=1 }
    /^[[:space:]]*TRUST[46][[:space:]]+/ {
      line=$0
      gsub(/^[[:space:]]+/, "", line)
      split(line, a, /[[:space:]]+/)
      key=a[1]
      cnt[key]++
      if (cnt[key] > 1) print $0
    }' "$old" \
  | sed -r 's/[[:space:]]*#.*$//' \
  | sed -r 's/[[:space:]]+/ /g; s/[[:space:]]+$//' \
  | awk '!seen[$0]++' >>"$tmp" || true

  grep -E "^[[:space:]]*SNAT[[:space:]]+" "$old" \
  | sed -r 's/[[:space:]]*#.*$//' \
  | sed -r 's/[[:space:]]+/ /g; s/[[:space:]]+$//' \
  | awk '!seen[$0]++' >>"$tmp" || true

  mv "$tmp" "$SETTINGS" && chmod 600 "$SETTINGS"
  # удаляем временные файлы вручную
  rm -f "$tmp" "$old"
}

# ──────────────────────────────────────────────────────────────────────────────
# AdGuard Home: шаблон и самолечение (полный YAML + заполнение ключей)
# ──────────────────────────────────────────────────────────────────────────────

# Полный дефолтный шаблон, как вы прислали. Значимые поля ниже будут
# перезаписаны программно: http.address (оставляем как в шаблоне),
# dns.bind_hosts, dns.upstream_dns, dns.bootstrap_dns, dns.fallback_dns,
# dns.allowed_clients.
agh_template() {
  cat <<'YAML'
http:
  pprof:
    port: 0
    enabled: false
  address: 127.0.0.1:80
  session_ttl: 720h
users:
  - name:
    password:
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: ""
theme: auto
dns:
  bind_hosts:
    - 
  port: 53
  anonymize_client_ip: false
  ratelimit: 20
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  ratelimit_whitelist: []
  refuse_any: true
  upstream_dns:
    - 
  upstream_dns_file: ""
  bootstrap_dns:
    - 
  fallback_dns: []
  upstream_mode: load_balance
  fastest_timeout: 1s
  allowed_clients:
    - 
  disallowed_clients: []
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
  trusted_proxies:
    - 127.0.0.0/8
    - ::1/128
  cache_size: 4194304
  cache_ttl_min: 0
  cache_ttl_max: 0
  cache_optimistic: false
  bogus_nxdomain: []
  aaaa_disabled: false
  enable_dnssec: false
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  ipset: []
  ipset_file: ""
  bootstrap_prefer_ipv6: false
  upstream_timeout: 10s
  private_networks: []
  use_private_ptr_resolvers: true
  local_ptr_upstreams: []
  use_dns64: false
  dns64_prefixes: []
  serve_http3: false
  use_http3_upstreams: false
  serve_plain_dns: true
  hostsfile_enabled: true
  pending_requests:
    enabled: true
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 0
  port_dns_over_tls: 0
  port_dns_over_quic: 0
  port_dnscrypt: 0
  dnscrypt_config_file: ""
  allow_unencrypted_doh: false
  certificate_chain: ""
  private_key: ""
  certificate_path: ""
  private_key_path: ""
  strict_sni_check: false
querylog:
  dir_path: ""
  ignored: []
  interval: 2160h
  size_memory: 1000
  enabled: true
  file_enabled: true
statistics:
  dir_path: ""
  ignored: []
  interval: 24h
  enabled: true
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt
    name: AdAway Default Blocklist
    id: 2
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
  interface_name: ""
  local_domain_name: lan
  dhcpv4:
    gateway_ip: ""
    subnet_mask: ""
    range_start: ""
    range_end: ""
    lease_duration: 86400
    icmp_timeout_msec: 1000
    options: []
  dhcpv6:
    range_start: ""
    lease_duration: 86400
    ra_slaac_only: false
    ra_allow_slaac: false
filtering:
  blocking_ipv4: ""
  blocking_ipv6: ""
  blocked_services:
    schedule:
      time_zone: Local
    ids: []
  protection_disabled_until: null
  safe_search:
    enabled: false
    bing: true
    duckduckgo: true
    ecosia: true
    google: true
    pixabay: true
    yandex: true
    youtube: true
  blocking_mode: default
  parental_block_host: family-block.dns.adguard.com
  safebrowsing_block_host: standard-block.dns.adguard.com
  rewrites: []
  safe_fs_patterns:
    - /opt/AdGuardHome/userfilters/*
  safebrowsing_cache_size: 1048576
  safesearch_cache_size: 1048576
  parental_cache_size: 1048576
  cache_time: 30
  filters_update_interval: 24
  blocked_response_ttl: 10
  filtering_enabled: true
  parental_enabled: false
  safebrowsing_enabled: false
  protection_enabled: true
clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: true
    hosts: true
  persistent: []
      name: ""
      ids:
        - 
      upstreams:
        - 
      uid: 
log:
  enabled: true
  file: "/var/log/adguardhome/access.log"
  max_backups: 0
  max_size: 100
  max_age: 3
  compress: false
  local_time: false
  verbose: false
os:
  group: ""
  user: ""
  rlimit_nofile: 0
schema_version: 29
YAML
}

# приводим любое постороннее значение к 1..3
_normalize_upstream_sel() {
  case "$1" in 1|2|3) echo "$1" ;; *) echo 1 ;; esac
}

# Собрать все TRUST4/6 из settings.map (включая «нижние»), игнорируя 0.0.0.0/::.
_settings__collect_trust() { # $1 = 4|6
  local v="$1"
  grep -E "^[[:space:]]*TRUST${v}[[:space:]]+" "$SETTINGS" 2>/dev/null \
    | awk '{for(i=2;i<=NF;i++){ if($i ~ /^#/) break; print $i }}' \
    | sed -r 's/[[:space:]]+$//' \
    | awk '($0!="0.0.0.0" && $0!="::") && !seen[$0]++'
}

# ── Fail2Ban helper: подтягиваем TRUST4/6 → ignoreip ────────────────────────
_update_f2b_ignoreip() {
  local jail=/etc/fail2ban/jail.local

  # адреса одной строкой
  local t4 t6 line
  t4="$(_settings__collect_trust 4 | tr '\n' ' ')"
  t6="$(_settings__collect_trust 6 | tr '\n' ' ')"
  line="ignoreip = 127.0.0.1/8 ::1 $t4 $t6"

  # если файла нет — создадим
  [[ -f "$jail" ]] || : >"$jail"

  if ! grep -q '^\[DEFAULT\]' "$jail" 2>/dev/null; then
    # нет секции — добавляем в конец
    printf '\n[DEFAULT]\n%s\n' "$line" >>"$jail"
    return 0
  fi

  # есть секция DEFAULT: проверим, есть ли в ней ignoreip
  if awk '
      /^\[DEFAULT\]/{in=1; next}
      /^$$/{in=0}
      in && /^[[:space:]]*ignoreip[[:space:]]*=/ {found=1}
      END{ exit(found?0:1) }
    ' "$jail"; then
    # заменить только внутри DEFAULT
    awk -v LINE="$line" '
      /^\[DEFAULT\]/{print; in=1; next}
      /^$$/{if(in){in=0} }
      { if(in && $0 ~ /^[[:space:]]*ignoreip[[:space:]]*=/) {print LINE; next}
        print }
    ' "$jail" >"$jail.tmp" && mv "$jail.tmp" "$jail"
  else
    # вставить сразу после заголовка DEFAULT
    awk -v LINE="$line" '
      /^\[DEFAULT\]/{print; print LINE; inserted=1; next}
      {print}
      END{ if(!inserted) print "[DEFAULT]\n" LINE }
    ' "$jail" >"$jail.tmp" && mv "$jail.tmp" "$jail"
  fi
}

agh_heal() {
  local AGH_YAML="/opt/AdGuardHome/AdGuardHome.yaml"
  local TMP OLD
  mkdir -p /opt/AdGuardHome
  TMP=$(mktemp); OLD=$(mktemp)
  cp -f "$AGH_YAML" "$OLD" 2>/dev/null || :

  # Читаем значения из settings.map (без зависимости от read_settings)
  local SVPN_NET4 FVPN_NET4 USEL v4a v4b v6a v6b
  SVPN_NET4="$(settings_get_tag SVPN_NET4 "10.29.8.0/24")"
  FVPN_NET4="$(settings_get_tag FVPN_NET4 "10.28.8.0/24")"
  USEL="$(_normalize_upstream_sel "$(settings_get_tag UPSTREAM_DNS 1)")"
  read -r v4a v4b v6a v6b <<<"$(upstream_pair_full "$USEL")"

  # Вычисляем IP‑адреса интерфейсов VPN
  vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" || { rm -f "$TMP" "$OLD"; return 1; }

  # TRUST‑списки (в строку, разделитель — пробел)
  local TRUST4 TRUST6
  TRUST4="$(_settings__collect_trust 4 | tr '\n' ' ')"
  TRUST6="$(_settings__collect_trust 6 | tr '\n' ' ')"

  local BOOTS="$v4a $v4b $v6a $v6b"       # v4 + v6

  # Строим YAML на базе шаблона, заполняя нужные секции.
  awk \
    -v b1="$SVPN_IP" -v b2="$FVPN_IP" \
    -v boots="$BOOTS" \
    -v s_net="$SVPN_NET4" -v f_net="$FVPN_NET4" \
    -v t4="$TRUST4" -v t6="$TRUST6" '
    BEGIN {
      split(boots, BOOT, /[[:space:]]+/);
      n_boot=0;
      for (i=1; i in BOOT; i++) {
        if (BOOT[i]!="") { n_boot++; BOOT_U[n_boot]=BOOT[i]; }
      }
      split(t4, T4, /[[:space:]]+/);
      split(t6, T6, /[[:space:]]+/);
      # переносимо считаем количество элементов (mawk/BusyBox awk совместимость)
      n4=0; for(i=1; i in T4; i++) n4++;
      n6=0; for(i=1; i in T6; i++) n6++;
      skip_list=0
    }
    # ключевые секции
    /^  bind_hosts:/      { print; printf("    - %s\n", b1); printf("    - %s\n", b2); skip_list=1; next }
    # AGH всегда проксирует в оба kresd-инстанса: 5353 (=kresd@1), 5354 (=kresd@2)
    /^  upstream_dns:/    { print; print "    - 127.0.0.1:5353"; print "    - 127.0.0.1:5354"; skip_list=1; next }
    /^  bootstrap_dns:/   { print; for(i=1;i<=n_boot;i++) printf("    - %s\n", BOOT_U[i]); skip_list=1; next }
    /^  fallback_dns:/    { print "  fallback_dns:"; for(i=1;i<=n_boot;i++) printf("    - %s\n", BOOT_U[i]); next }
    /^  allowed_clients:/ {
                             print;
                             printf("    - %s\n", s_net);
                             printf("    - %s\n", f_net);
                             for(i=1;i<=n4;i++) if(T4[i]!="") printf("    - %s\n", T4[i]);
                             for(i=1;i<=n6;i++) if(T6[i]!="") printf("    - %s\n", T6[i]);
                             skip_list=1; next
                           }
    # Пропускаем пустые элементы списков из шаблона (строки вида "    -")
    skip_list && /^[[:space:]]*-[[:space:]]*$/ { next }
    # Сброс режима пропуска при новом разделe того же уровня
    /^[^[:space:]]/ || /^[[:space:]]{2}[a-z]/ { skip_list=0 }
    { print }
  ' < <(agh_template) >"$TMP"

  # Если установлен yq — мерджим: СТАРЫЙ * НОВЫЙ → новые значения для управляемых ключей,
  # при этом сохраняем пользовательские секции из старого файла.
  if command -v yq &>/dev/null && [[ -s "$OLD" ]]; then
    yq eval-all 'select(fi==0) * select(fi==1)' "$OLD" "$TMP" >"$AGH_YAML"
  else
    cp "$TMP" "$AGH_YAML"
   fi

  # гарантируем наличие каталога и файла логов, с корректными правами
  install -d -m 755 /var/log/adguardhome
  : > /var/log/adguardhome/access.log
  chown adguardhome:adguardhome /var/log/adguardhome /var/log/adguardhome/access.log 2>/dev/null || true
  chmod 600 "$AGH_YAML"
  rm -f "$TMP" "$OLD"
}

# ──────────────────────────────────────────────────────────────────────────────
# Kresd: upstream лист для обоих инстансов (одинаковая пара публичных DNS)
#  - kresd@1 — со списками (RPZ/deny)
#  - kresd@2 — без списков
kresd_upstream_heal() {
  local USEL u1 u2
  USEL="$(_normalize_upstream_sel "$(settings_get_tag UPSTREAM_DNS 1)")"
  # берём только IPv4‑адреса провайдера
  read -r u1 u2 <<<"$(upstream_pair_v4 "$USEL")"
  # экранируем одинарные кавычки на случай форматов вида 1.1.1.1#853
  local u1_esc=${u1//\'/\'\\\'\'}
  local u2_esc=${u2//\'/\'\\\'\'}
  install -d -o knot-resolver -g knot-resolver /etc/knot-resolver
  cat >/etc/knot-resolver/upstream_dns.lua <<EOF
return { up = {'${u1_esc}','${u2_esc}'} }
EOF
  chown knot-resolver:knot-resolver /etc/knot-resolver/upstream_dns.lua 2>/dev/null || true
  chmod 644 /etc/knot-resolver/upstream_dns.lua
}

# ──────────────────────────────────────────────────────────────────────────────
# Что писать в DNS клиентов (для генератора client.sh):
#  - при AGH=y: оба стека указывают на IP сервера (AGH:53), по своей VPN‑сети
#  - при AGH=n:  оба профиля указывают на kresd@1:
#                SVPN_DNS = SVPN_IP,  FVPN_DNS = FVPN_IP
dns_targets_for_clients() {
  local agh SVPN_NET4 FVPN_NET4
  SVPN_NET4="$(settings_get_tag SVPN_NET4 "10.29.8.0/24")"
  FVPN_NET4="$(settings_get_tag FVPN_NET4 "10.28.8.0/24")"
  vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" || return 1
  agh="$(settings_get_tag ADGUARD_HOME n)"
  if [[ "$agh" == "y" ]]; then
    echo "SVPN_DNS=${SVPN_IP}"
    echo "FVPN_DNS=${FVPN_IP}"
  else
    echo "SVPN_DNS=${SVPN_IP}"
    echo "FVPN_DNS=${FVPN_IP}"
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Применение настроек
# ──────────────────────────────────────────────────────────────────────────────

_settings__svc() { systemctl "$@"; }

apply_settings_services() {
  local agh sshp
  agh="$(settings_get_tag ADGUARD_HOME n)"
  sshp="$(settings_get_tag SSH_PROTECTION n)"

  # AGH: пересобираем YAML и включаем/выключаем юнит
  agh_heal || true
  if [[ "$agh" == "y" ]]; then
    _settings__svc enable --now AdGuardHome 2>/dev/null || true
    _settings__svc restart       AdGuardHome 2>/dev/null || true
  else
    _settings__svc disable --now AdGuardHome 2>/dev/null || true
  fi

  # Fail2Ban: включение по флагу (комментарий версия правит update.sh)
  if [[ "$sshp" == "y" ]]; then
    _update_f2b_ignoreip
    _settings__svc enable --now fail2ban 2>/dev/null || true
    _settings__svc restart       fail2ban 2>/dev/null || true
  else
    _settings__svc disable --now fail2ban 2>/dev/null || true
  fi
}

apply_settings_dns() {
  # upstream для kresd
  kresd_upstream_heal
  # systemd-resolved + /etc/network/interfaces
  _update_system_dns
  # перезапуск инстансов
  _settings__svc restart kresd@1 2>/dev/null || true
  _settings__svc restart kresd@2 2>/dev/null || true
}

apply_settings_vpn() {
  # ── iptables / WireGuard / SNAT / PORTы ──────────────────────────────
  /opt/rzans_vpn_main/up.sh 2>/dev/null || true
  _settings__svc restart wg-quick@rzans_svpn_main 2>/dev/null || true
  _settings__svc restart wg-quick@rzans_fvpn_main 2>/dev/null || true

  # ── AmneziaWG: (re)создаём server‑конфиги и все клиентские профили ──
  /opt/rzans_vpn_main/client.sh 4 >/dev/null 2>&1 || true

  # ── proxy.py (rzans_vpn_main.service) ───────────────────────────────
_settings__svc restart core 2>/dev/null || true
}

apply_settings_all() {
  # защита от гонок
  exec 9> /run/rzans_settings.lock
  flock -w 30 9 || { echo "apply_settings_all: lock timeout"; return 1; }

  local STATE=/run/rzans_settings.state tmp; tmp=$(mktemp)

  # 1) считаем «старые» значения (если файл‑state уже есть)
  declare -A OLD
  if [[ -f $STATE ]]; then
    while IFS='=' read -r k v; do OLD[$k]=$v; done <"$STATE"
  fi

  # 2) helper: changed TAG ?
  _changed() {
    local cur old; cur=$(settings_get_tag "$1" ""); old=${OLD[$1]-""}
    [[ "$cur" != "$old" ]]
  }

  local need_dns=n need_vpn=n need_srv=n

  _changed UPSTREAM_DNS && need_dns=y

  for t in EXTIP4 EXTIP6 TRUST4 TRUST6 SVPN_PORT FVPN_PORT \
           SVPN_NET4 FVPN_NET4 VPN_MAP_SRC4 VPN_MAP_DST4 SNAT; do
    _changed "$t" && need_vpn=y
  done

  for t in SSH_PROTECTION ADGUARD_HOME; do
    _changed "$t" && need_srv=y
  done

  # 3) всегда оздоровливаем файл (healer может дописать комментарии)
  settings_heal

  [[ $need_dns == y ]] && apply_settings_dns
  [[ $need_vpn == y ]] && apply_settings_vpn
  [[ $need_srv == y ]] && apply_settings_services

  # 4) обновляем state‑файл (все интересующие теги)
  for t in UPSTREAM_DNS EXTIP4 EXTIP6 TRUST4 TRUST6 SVPN_PORT FVPN_PORT \
           SVPN_NET4 FVPN_NET4 VPN_MAP_SRC4 VPN_MAP_DST4 SNAT \
           SSH_PROTECTION ADGUARD_HOME; do
    printf '%s=%s\n' "$t" "$(settings_get_tag "$t" "")"
  done >"$tmp" && mv "$tmp" "$STATE"
}

# ── CLI‑интерфейс ───────────────────────────────────────────────
case "${1:-}" in
  --apply)         shift; apply_settings_all "$@";           exit $? ;;
  --apply-changed) shift; apply_settings_all "$@";           exit $? ;;  # точечное → тот же код
  *)               echo "Usage: $0 [--apply|--apply-changed]"; exit 1  ;;
esac
