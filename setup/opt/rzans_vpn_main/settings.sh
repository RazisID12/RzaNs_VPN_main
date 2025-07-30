#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
IFS=$'\n\t'

# фиксируем POSIX-локаль, чтобы регэкспы/пробелы в awk/sed вели себя одинаково
export LC_ALL=C

# чтобы strict-mode (set -u) не ругался,
# объявим служебные переменные заранее
tmp=""; old=""

# Точка правды для пути к settings.map (можно переопределить до source)
# путь к settings.map
: "${SETTINGS:=/opt/rzans_vpn_main/settings.map}"

# директория и файлы шаблонов AdGuard Home
TEMPLATE_DIR=/opt/rzans_vpn_main/config/templates
AGH_TMPL_BASE=${TEMPLATE_DIR}/AdGuardHome.yaml
AGH_TMPL_PATCH=${TEMPLATE_DIR}/agh_dynamic_patch.yaml

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

# ——— helpers ————————————————————————————————————————————————————————————————
_have() { command -v "$1" >/dev/null 2>&1; }

# Унифицированный рендер шаблонов: предпочитаем функцию/утилиту render,
# иначе — envsubst. Возвращает результат в stdout.
_render() {
  local src="$1"
  if declare -F render >/dev/null 2>&1; then
    render "$src"
  elif _have render; then
    command render "$src"
  elif _have envsubst; then
    envsubst < "$src"
  else
    echo "ERROR: no renderer (need 'render' or 'envsubst')" >&2
    return 1
  fi
}

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
  local AGH_YAML=/opt/AdGuardHome/AdGuardHome.yaml
  mkdir -p /opt/AdGuardHome
  # инструменты, без которых merge невозможен
  _have yq || { echo "ERROR: yq not found"; return 1; }

  # ── 1. собираем переменные из settings.map ──────────────────────
  local SVPN_NET4 FVPN_NET4 USEL v4a v4b v6a v6b
  SVPN_NET4=$(settings_get_tag SVPN_NET4 "10.29.8.0/24")
  FVPN_NET4=$(settings_get_tag FVPN_NET4 "10.28.8.0/24")
  USEL=$(_normalize_upstream_sel "$(settings_get_tag UPSTREAM_DNS 1)")
  read -r v4a v4b v6a v6b <<<"$(upstream_pair_full "$USEL")"
  vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" || return 1

  # bootstrap (v4+v6) — одной строкой; TRUST_BLOCK — с реальными \n и отступами
  local BOOTSTRAP="${v4a} ${v4b} ${v6a} ${v6b}"
  local TRUST_BLOCK="" _trust_list=""
  _trust_list="$( { _settings__collect_trust 4; _settings__collect_trust 6; } || true )"
  if [[ -n "${_trust_list}" ]]; then
    while IFS= read -r _t; do
      [[ -n "${_t}" ]] && TRUST_BLOCK+=$'    - '"${_t}"$'\n'
    done <<< "${_trust_list}"
    # убрать последний перевод строки
    TRUST_BLOCK="${TRUST_BLOCK%$'\n'}"
  fi

  # ── 2. рендерим динамический патч ───────────────────────────────
  local PTMP; PTMP=$(mktemp)
  {
    export SVPN_IP FVPN_IP SVPN_NET4 FVPN_NET4
    export BOOTSTRAP TRUST_BLOCK
    _render "$AGH_TMPL_PATCH"
  } >"$PTMP"

  # ── 3. merge: base * patch * (optional)old ──────────────────────
  if [[ -s $AGH_YAML ]]; then
    # есть непустой старый файл → трёхсторонний merge
    if _have sponge; then
      yq ea '
      select(fi==0) *          # базовый шаблон
      select(fi==1) *          # динамический патч
      select(fi==2)            # существующий YAML (кастом)
      '  "$AGH_TMPL_BASE" "$PTMP" "$AGH_YAML" | sponge "$AGH_YAML"
    else
      local _tmp; _tmp=$(mktemp)
      yq ea '
      select(fi==0) * select(fi==1) * select(fi==2)
      ' "$AGH_TMPL_BASE" "$PTMP" "$AGH_YAML" >"$_tmp" && mv -f "$_tmp" "$AGH_YAML"
    fi
  else
    # старого файла нет или он пустой → двусторонний merge (base * patch)
    if _have sponge; then
      yq ea 'select(fi==0) * select(fi==1)' \
            "$AGH_TMPL_BASE" "$PTMP" | sponge "$AGH_YAML"
    else
      local _tmp; _tmp=$(mktemp)
      yq ea 'select(fi==0) * select(fi==1)' \
            "$AGH_TMPL_BASE" "$PTMP" >"$_tmp" && mv -f "$_tmp" "$AGH_YAML"
    fi
  fi
  rm -f "$PTMP"

  chmod 600 "$AGH_YAML"
  install -d -m 755 /var/log/adguardhome
  : > /var/log/adguardhome/access.log
  chown adguardhome:adguardhome /var/log/adguardhome /var/log/adguardhome/access.log 2>/dev/null || true
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
# если файл подключён через «source», а не запущен напрямую —
#    загружаем функции и выходим без CLI‑логики
[[ "${BASH_SOURCE[0]}" != "${0}" ]] && return 0

case "${1:-}" in
  --apply)         shift; apply_settings_all "$@";           exit $? ;;
  --apply-changed) shift; apply_settings_all "$@";           exit $? ;;  # точечное → тот же код
  *)               echo "Usage: $0 [--apply|--apply-changed]"; exit 1  ;;
esac
