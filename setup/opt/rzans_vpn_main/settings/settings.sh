#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
IFS=$'\n\t'

# фиксируем POSIX-локаль, чтобы регэкспы/пробелы в awk/sed вели себя одинаково
export LC_ALL=C

# ── base paths (для единообразия путей) ───────────────────────────
: "${BASE_DIR:=/opt/rzans_vpn_main}"
: "${SETTINGS_DIR:=${BASE_DIR}/settings}"
: "${FIREWALL_DIR:=${BASE_DIR}/firewall}"

# ── pin go-yq v4 ────────────────────────────────────────────────────────────
#  • Bash иногда кеширует первый найденный yq; после PATH-изменений это приводит
#    к запуску «чужого» бинаря.  Переопределяем команду локальной функцией,
#    указывая явный путь /usr/bin/yq (его ставит setup.sh).
#  • Если вдруг нет v4 — прекращаем работу сразу.
# ---------------------------------------------------------------------------
YQ_BIN=/usr/bin/yq
hash -r                                 # сбрасываем возможный кеш Bash
if ! "$YQ_BIN" --version 2>/dev/null | grep -Eq '\bv?4(\.|$)'; then
  echo "ERROR: need go-yq v4+, but $YQ_BIN is missing or outdated" >&2
  exit 90
fi
yq() { command "$YQ_BIN" "$@"; }

# DRY-run:    1 — показывать diff’ы, но ничего не писать/рестартовать
# BOOTSTRAP:  1 — «тихий» режим инсталлятора: генерим файлы, но
#               *не* вызываем systemctl и не ломаем resolv.conf
DRY_RUN="${DRY_RUN:-0}"
BOOTSTRAP="${BOOTSTRAP:-0}"

# ── DNS addresses (как в up.sh) ───────────────────────────────────
# IP’ы локальных сервисов и общий DNS-порт (новая схема)

# --- iptables backend selection (как в up/down) --------------------
# Можно переопределить из окружения перед запуском, если нужно.
: "${IPT_BIN:=$(command -v iptables-nft || command -v iptables || echo iptables)}"
: "${IP6T_BIN:=$(command -v ip6tables-nft || command -v ip6tables || echo ip6tables)}"
_has_ipt()  { command -v "$IPT_BIN"  >/dev/null 2>&1; }
_has_ip6t() { command -v "$IP6T_BIN" >/dev/null 2>&1; }
# Локальные обёртки только для внутреннего использования в settings.sh,
# чтобы не конфликтовать с alias/функциями в up.sh
_ipt()  { "$IPT_BIN"  -w "$@"; }
_ipt6() {
  if _has_ip6t; then "$IP6T_BIN" -w "$@"; else return 127; fi
}

KRESD1_IP="${KRESD1_IP:-127.0.0.1}"  # kresd@1 (DoT hub)
KRESD2_IP="${KRESD2_IP:-127.0.0.2}"  # kresd@2 (SYSTEM DNS, validating → @1)
KRESD3_IP="${KRESD3_IP:-127.0.0.3}"  # kresd@3 (SPLIT, IPv4-only, lists)
KRESD4_IP="${KRESD4_IP:-127.0.0.4}"  # kresd@4 (FULL, IPv4-only)
PROXY_IP="${PROXY_IP:-127.0.0.5}"    # proxy (RPZ helper for @3 / SPLIT)
AGH_IP="${AGH_IP:-127.0.0.6}"        # AdGuard Home (client front / DNAT)
DNS_PORT="${DNS_PORT:-53}"

# ── единый lock для ВСЕХ конфиг-операций (делим с update.sh) ─────────────
_ensure_settings_lock() {
  if ! _have flock; then
    echo "[WARN] flock not found; proceeding without interprocess lock" >&2
    return 0
  fi
  # Ре-входимый лок: используем «именованный» FD и экспортируем его номер,
  # чтобы подпроцессы видели уже взятый лок и не пытались блокироваться повторно.
  if [[ -n "${_SETTINGS_LOCK_FD:-}" ]]; then
    return 0
  fi
  local _fd
  exec {_fd}>/run/rzans_settings.lock || { echo "open lock failed: /run/rzans_settings.lock" >&2; return 1; }
  # Сначала неблокирующая попытка (избегаем висящих конкурентов),
  # потом — ожидание до 30 с.
  if ! flock -n "$_fd"; then
    flock -w 30 "$_fd" || { echo "lock timeout: /run/rzans_settings.lock" >&2; eval "exec ${_fd}>&-"; return 1; }
  fi
  _SETTINGS_LOCK_FD="$_fd"
  export _SETTINGS_LOCK_FD
}

# Явно отпускаем блокировку (закрываем дескриптор, сохранённый
# в переменной $_SETTINGS_LOCK_FD), когда она больше не нужна.
_release_settings_lock() {
  if [[ -n "${_SETTINGS_LOCK_FD:-}" ]]; then
    eval "exec ${_SETTINGS_LOCK_FD}>&-"
    unset _SETTINGS_LOCK_FD
  fi
}

# ── атомичная запись «только при изменении» (+валидация) ──────────────────
# _write_if_changed <dst> <tmp> [yaml]
_write_if_changed() {
  local dst="$1" tmp="$2" v="${3-}"
  if [[ "$v" == yaml ]]; then
    if ! _have yq || ! yq e '.' "$tmp" >/dev/null 2>&1; then
      echo "YAML validation failed for $dst" >&2
      rm -f "$tmp"; return 2
    fi
  fi
  # Определяем, отличается ли содержимое безопасно (без падений при отсутствии diff/cmp)
  local need_update=1
  if [[ -f "$dst" ]]; then
    need_update=0
    if _have cmp; then
      cmp -s "$tmp" "$dst" || need_update=1
    elif _have diff; then
      diff -q "$dst" "$tmp" >/dev/null 2>&1 || need_update=1
    else
      need_update=1   # нет инструментов сравнения → считаем, что отличается
    fi
  fi
  if (( need_update )); then
    if [[ "$DRY_RUN" == 1 ]]; then
      if [[ -f "$dst" ]]; then
        echo "[DRY] would update $dst (showing unified diff, capped)"
        if _have diff; then
          local DOUT; DOUT="$(mktemp)"
          # diff возвращает 1 при различиях — это не ошибка для нас
          diff -u --label "${dst} (old)" --label "${dst} (new)" "$dst" "$tmp" >"$DOUT" || true
          # печатаем до 200 строк, затем помета о срезе
          head -n 200 "$DOUT"
          local total; total="$(wc -l <"$DOUT" | tr -d ' ')"
          [[ "$total" -gt 200 ]] && echo "[...] diff truncated (${total} lines total)"
          rm -f "$DOUT"
        else
          echo "(no 'diff' available)"
        fi
      else
        echo "[DRY] would create $dst (showing first 60 lines)"
        head -n 60 "$tmp" || true
      fi
      rm -f "$tmp"; return 0
    fi
    mv -f "$tmp" "$dst"; return 0
  fi
  rm -f "$tmp"; return 1
}

# ── YAML-конфиги (defaults * settings) ───────────────────────────────────────
: "${DEFAULTS_YAML:=${BASE_DIR}/config/templates/defaults.yaml}"
: "${SETTINGS_YAML:=${BASE_DIR}/settings.yaml}"

# директория и файлы шаблонов AdGuard Home
TEMPLATE_DIR="${BASE_DIR}/config/templates"
AGH_TMPL_BASE=${TEMPLATE_DIR}/AdGuardHome.yaml
AGH_TMPL_PATCH=${TEMPLATE_DIR}/agh_dynamic_patch.yaml
: "${AGH_DIR:=/opt/AdGuardHome}"

# ──────────────────────────────────────────────────────────────────────────────
# Публичные функции:
#   agh_heal               — создать/восстановить /opt/AdGuardHome/AdGuardHome.yaml
#                            из шаблонов; bind_hosts и GUI — всегда локальные (127.0.0.6).
#   server_iface           — определить внешний интерфейс (server.ext_if или авто)
#   server_domain          — вернуть домен ('' если auto/пусто)
#   agh_control_post PATH  — локальный POST к /control/<PATH> на 127.0.0.6:80 (IPv6-скобки поддержаны)
#   server_ip4 [wait]      — внешний IPv4: явный из settings или автоопределение (wait сек)
#   server_ip6 [wait]      — внешний IPv6: явный из settings или автоопределение (wait сек)
#   ipv4_host CIDR        — вернуть первый IPv4‑хост из сети
#                           (пример: 10.29.8.0/24 → 10.29.8.1).
#                           Функция просто возвращает первый адрес сети (ip+1). 
#                           Для /31-/32 такие маски обычно не используются здесь;
#                           в боевом коде эти случаи перехватываются в vpn_addrs_from_cidrs.
#   vpn_addrs_from_cidrs SVPN_NET4 FVPN_NET4
#                         — установить: SVPN_IP, FVPN_IP, SVPN_ADDR, FVPN_ADDR,
#                           SVPN_DNS_IP, FVPN_DNS_IP.
# ──────────────────────────────────────────────────────────────────────────────

# ——— helpers ————————————————————————————————————————————————————————————————
_have() { command -v "$1" >/dev/null 2>&1; }

# Сброс кэша всех экземпляров kresd (идемпотентно, best-effort)
kresd_flush_all() {
  command -v socat >/dev/null 2>&1 || return 0
  for i in 1 2 3 4; do
    s="/run/knot-resolver/control/$i"
    [[ -S "$s" ]] && echo 'cache.clear()' | socat - "$s" >/dev/null 2>&1 || true
  done
}

# DoT ipset: единая точка правды для адресов апстрима (v4/v6)
dot_ipset_sync() {
  command -v ipset >/dev/null 2>&1 || { echo "[INFO] ipset missing; skip dot sync"; return 0; }
  # Межпроцессный лок только на время работы с наборами DoT
  local _lock=/run/rzans_ipset_dot.lock
  exec 9>"$_lock" || true
  local _locked=0
  if command -v flock >/dev/null 2>&1; then
    # Если не удалось взять за 10с — лучше «мирно» пропустить синк,
    # чтобы не устраивать гонку без лока
    flock -w 10 9 || { echo "[INFO] dot_ipset_sync: busy, skip"; exec 9>&-; return 0; }
    _locked=1
  fi

  # Читаем «квадру» (v4a v4b v6a v6b)
  readarray -t Q < <(yaml_upstream_quad | tr -d '\r')

  # Уникальные имена временных наборов (чтобы параллельные запуски не пересекались)
  local SUF; SUF=".$$-$RANDOM"
  local S4N="ipset-dot${SUF}" S6N="ipset-dot6${SUF}"

  # Создаём боевые (на случай первого запуска) и временные наборы
  ipset -! create ipset-dot  hash:ip  family inet  comment 2>/dev/null || true
  ipset -! create ipset-dot6 hash:ip  family inet6 comment 2>/dev/null || true
  ipset -! create "$S4N"     hash:ip  family inet  comment 2>/dev/null || true
  ipset -! create "$S6N"     hash:ip  family inet6 comment 2>/dev/null || true

  [[ -n "${Q[0]:-}" ]] && ipset -! add "$S4N" "${Q[0]}"
  [[ -n "${Q[1]:-}" ]] && ipset -! add "$S4N" "${Q[1]}"
  [[ -n "${Q[2]:-}" ]] && ipset -! add "$S6N" "${Q[2]}"
  [[ -n "${Q[3]:-}" ]] && ipset -! add "$S6N" "${Q[3]}"

  # Атомарная подмена: если боевой отсутствует (гонка) — переименуем
  ipset swap ipset-dot  "$S4N" 2>/dev/null || ipset rename "$S4N" ipset-dot  2>/dev/null || true
  ipset swap ipset-dot6 "$S6N" 2>/dev/null || ipset rename "$S6N" ipset-dot6 2>/dev/null || true

  # Уборка возможных «хвостов» (если swap прошёл — временных уже нет)
  ipset destroy "$S4N" 2>/dev/null || true
  ipset destroy "$S6N" 2>/dev/null || true

  # аккуратно отпускаем лок
  if (( _locked )); then flock -u 9 || true; fi
  exec 9>&-  # закрыть FD
}

# IPv6 доступен? → 'y' если включён и есть default route, иначе 'n'
_ipv6_available() {
  if _have sysctl && _have ip; then
    if [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" == 0 ]] \
       && ip -6 route show default 2>/dev/null | grep -q .; then
      echo y; return 0
    fi
  fi
  echo n
}

###############################################################################
# AdGuard Home: единый helper прав на YAML
###############################################################################
# Определить пользователя, под которым запускается юнит AdGuardHome.
_agh_unit_user() {
  local u=""
  if command -v systemctl >/dev/null 2>&1; then
    u="$(systemctl show -p User --value AdGuardHome 2>/dev/null || true)"
    [[ -z "$u" ]] && u="$(
      ( systemctl cat AdGuardHome 2>/dev/null || true ) | awk -F= '/^[[:space:]]*User=/{print $2; exit}'
    )"
  fi
  [[ -n "$u" ]] || u="adguardhome"
  printf '%s' "$u"
}

# ===== AdGuard Home API helpers ===========================================
agh_gui_host_port() {
  # Панель/Control доступны только локально на loopback AGH
  printf '%s\t%s\n' "${AGH_IP:-127.0.0.6}" 80
}

# POST к /control/<path> по http; поддержка IPv6 [host]
# usage: agh_control_post "cache/flush"
agh_control_post() {
  local path="$1"
  [[ -z "$path" ]] && return 1
  local host port; read -r host port < <(agh_gui_host_port)
  [[ "$host" == *:* && "$host" != \[*\] ]] && host="[$host]"   # обернуть IPv6
  # percent-encode zone id in IPv6 scope (e.g. fe80::1%eth0)
  [[ "$host" == *%* ]] && host="${host//%/%25}"
  local urls=("http://${host}:${port}/control/${path}")
  if command -v curl >/dev/null 2>&1; then
    for u in "${urls[@]}"; do curl -ksS -X POST "$u" >/dev/null && return 0; done
  elif command -v wget >/dev/null 2>&1; then
    for u in "${urls[@]}"; do wget --no-check-certificate -qO- --post-data="" "$u" >/dev/null && return 0; done
  fi
  return 1
}
# ========================================================================

# Привести владельца/права конфигурации AdGuardHome (идемпотентно).
# Использование: agh_fix_perms [/opt/AdGuardHome/AdGuardHome.yaml]
agh_fix_perms() {
  local f="${1:-${AGH_DIR}/AdGuardHome.yaml}"
  [[ -f "$f" ]] || return 0
  local u; u="$(_agh_unit_user)"
  chown "$u:$u" "$f" 2>/dev/null || true
  chmod 0640 "$f" 2>/dev/null || true
}

# определить главный интерфейс
#  • ждём default-route до $1 секунд (по умолчанию 30);
#  • иначе первый iface с глобальным IPv4;
#  • иначе первый UP (кроме lo);
#  • в самом крайнем случае «ens3».
_primary_iface() {
  local timeout=${1:-30} ifc=""
  # ① default-route dev (ожидание до timeout)
  for ((i=0; i<timeout; i++)); do
    ifc="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}')"
    [[ -n "$ifc" ]] && break
    sleep 1
  done
  # ② первый iface с глобальным IPv4
  [[ -z $ifc ]] && \
    ifc="$(ip -o -4 addr show scope global | awk '{print $2; exit}')"
  # ③ любой UP (кроме lo)
  [[ -z $ifc ]] && \
    ifc="$(ip -o link show up | awk -F': ' '$2 != "lo" {print $2; exit}')"
  # ④ крайний fallback
  [[ -z $ifc ]] && ifc="ens3"
  printf '%s' "$ifc"
}

# дождаться глобального адреса на интерфейсе
# wait_ip <iface> [timeout] [family 4|6] → печатает IP или возвращает 1
wait_ip() {
  local ifc=$1 timeout=${2:-30} fam=${3:-4} ip_addr=""
  for ((i=0; i<timeout; i++)); do
    ip_addr=$({ ip -o -"$fam" addr show dev "$ifc" scope global 2>/dev/null || true; } \
              | awk 'NR==1{split($4,a,"/");print a[1]}')
    [[ -n $ip_addr ]] && { printf '%s' "$ip_addr"; return 0; }
    sleep 1
  done
  return 1
}

# гарантируем наличие settings.yaml (если нет — копируем defaults)
_ensure_settings_yaml() {
  [[ -s "$SETTINGS_YAML" ]] && return 0
  if [[ "$DRY_RUN" == 1 ]]; then
    echo "[DRY] would create $SETTINGS_YAML from defaults"
  else
    install -D -m600 "$DEFAULTS_YAML" "$SETTINGS_YAML"
  fi
}

# дата для updated
_today() {
  if command -v date >/dev/null 2>&1; then
    date +%d.%m.%Y
  else
    busybox date +%d.%m.%Y
  fi
}

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

# ── Одноразовый переход системы на локальный DNS (для init.service) ─
switch_system_resolve() {
  # 1) Идемпотентно выключаем и маскируем systemd-resolved
  _release_settings_lock
  systemctl disable --now systemd-resolved 2>/dev/null || true
  systemctl mask systemd-resolved 2>/dev/null || true
  # IPv6-доступность и итоговая строка DNS (v4 + опционально v6)
  local IPV6_AVAIL; IPV6_AVAIL="$(_ipv6_available)"
  local _dns_line
  if [[ "$IPV6_AVAIL" == y ]]; then
    _dns_line="${KRESD2_IP:-127.0.0.2} ::2"
  else
    _dns_line="${KRESD2_IP:-127.0.0.2}"
  fi
  # 2) Аккуратно правим /etc/systemd/resolved.conf:
  #    - меняем ТОЛЬКО активную (не закомментированную) строку DNS= внутри [Resolve]
  #    - #DNS= не трогаем
  #    - если активной DNS= нет — ничего не добавляем
  if [[ -f /etc/systemd/resolved.conf ]]; then
    local _rcf=/etc/systemd/resolved.conf _tmp
    _tmp="$(mktemp)"
    awk -v NEWDNS="${_dns_line}" '
      BEGIN { inres=0; done=0 }

      # ── вход/выход из секции [Resolve] ─────────────────────────────
      /^[[:space:]]*\[Resolve\][[:space:]]*(#.*)?$/      { print; inres=1; done=0; next }
      /^[[:space:]]*\[[^][]+\][[:space:]]*(#.*)?$/       { inres=0; print; next }

      # ── обработка активных строк DNS= внутри [Resolve] ────────────
      inres && $0 ~ /^[[:space:]]*DNS[[:space:]]*=/ && $0 !~ /^[[:space:]]*#/ {
          if (!done) {                                   # первую меняем…
              # m[1] – отступ, m[3] – «хвост» (пробелы + комментарий, если был)
              match($0, /^([[:space:]]*)DNS[[:space:]]*=[[:space:]]*([^#]*)([[:space:]]*(#.*))?$/, m)
              print m[1] "DNS=" NEWDNS (m[3] ? m[3] : "")
              done = 1
          }                                              # остальные отбрасываем
          next
      }

      { print }                                          # всё прочее без изменений
    ' "$_rcf" >"$_tmp"
    _write_if_changed "$_rcf" "$_tmp"
  fi
  # 3) /etc/resolv.conf → ${KRESD2_IP} (перезаписываем, с уважением DRY_RUN)
  if [[ "$DRY_RUN" == 1 ]]; then
    echo "[DRY] would replace /etc/resolv.conf with local stub (${_dns_line})"
  else
    rm -f /etc/resolv.conf
    if [[ "$IPV6_AVAIL" == y ]]; then
      printf 'nameserver %s\nnameserver ::2\noptions edns0 trust-ad\n' "${KRESD2_IP:-127.0.0.2}" >/etc/resolv.conf
    else
      printf 'nameserver %s\noptions edns0 trust-ad\n' "${KRESD2_IP:-127.0.0.2}" >/etc/resolv.conf
    fi
    chmod 644 /etc/resolv.conf 2>/dev/null || true
    chown root:root /etc/resolv.conf 2>/dev/null || true
  fi
  # 4) приведение косметики системных файлов
  _update_system_upstream
}

# ── YAML helpers (defaults * settings) ───────────────────────────
_yaml_merged() {
  _have yq || { echo "ERROR: yq not found" >&2; return 1; }
  local files=()
  [[ -s "$DEFAULTS_YAML"  ]] && files+=("$DEFAULTS_YAML")
  [[ -s "$SETTINGS_YAML"  ]] && files+=("$SETTINGS_YAML")
  [[ ${#files[@]} -eq 0 ]] && { echo "{}"; return 0; }
  # глубокий мердж двух документов: правее имеет приоритет
  if [[ ${#files[@]} -eq 1 ]]; then
    cat "${files[0]}"
  else
    yq ea -P 'select(fi==0) * select(fi==1)' "${files[@]}"
  fi
}
# yaml_get <key> [default]
#  – читает ключ из merge(defaults, settings); если нет — берёт default
#  – сохраняет тип (число, bool, null) через from_yaml
yaml_get() {
  local key="$1" def="${2-}" expr="." seg
  local -a _parts
  IFS='.' read -r -a _parts <<<"$key"
  for seg in "${_parts[@]}"; do
    seg=${seg//\"/\\\"}
    expr+='["'"$seg"'"]'
  done
  # Возвращаем JSON-представление значения или строку-сентинел, чтобы
  # различать: отсутствие пути, null, пустую строку, числа, bool.
  local raw
  raw="$(_yaml_merged | yq e -r "(${expr} // \"__absent__\") | @json" - 2>/dev/null || echo '\"__absent__\"')"
  case "$raw" in
    '"__absent__"'|null)
      printf '%s' "$def"
      ;;
    '""')
      # Совместимо с прежней логикой: пустая строка = возьми default.
      printf '%s' "$def"
      ;;
    *)
      # Строки приходят в кавычках, числа/bool — без.
      if [[ "$raw" =~ ^\".*\"$ ]]; then
        # снимаем кавычки и проверяем, не остались ли одни пробелы
        local _val _trim
        _val="${raw:1:${#raw}-2}"
        _trim="$(printf '%s' "$_val" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
        if [[ -z "$_trim" ]]; then
          printf '%s' "$def"
        else
          printf '%s' "$_val"
        fi
      else
        printf '%s' "$raw"
      fi
      ;;
  esac
}

# Специальный getter для IP-полей: 'auto' → sentinel по умолчанию
yaml_get_ip() {
  local key="$1" def="${2-}"
  local v; v="$(yaml_get "$key" "$def")"
  [[ ${v,,} == auto ]] && { printf '%s' "$def"; } || printf '%s' "$v"
}

# yaml_bool <key> [default_if_absent]
# Возвращает 'y' или 'n'. Значение берётся из merge(defaults, settings).
# Если ключ отсутствует и там, и тут — используется второй аргумент (по умолчанию: n).
yaml_bool() {
  local key="$1" def="${2:-n}" raw expr="." seg
  # строим безопасный .["a"]["b"] для любых ключей с точками
  local -a _parts
  IFS='.' read -r -a _parts <<<"$key"
  for seg in "${_parts[@]}"; do
    seg=${seg//\"/\\\"}
    expr+='["'"$seg"'"]'
  done
  # Универсально для любых версий v4: берём значение или «__absent__», даже если путь отсутствует
  raw="$(_yaml_merged | yq e -r "${expr} // \"__absent__\"" - 2>/dev/null || echo "__absent__")"
  case "${raw,,}" in
    true|yes|y|1)  echo y ;;
    false|no|n|0)  echo n ;;
    "__absent__")  echo "$def" ;;
    *)             echo "$def" ;;
  esac
}

yaml_allow_all() {
  # null→[], скаляр→[скаляр], массив «как есть»
  _yaml_merged | yq e -r '
    [.allowip.ipv4, .allowip.ipv6]
    | flatten
    | .[]
    | select(. != null and . != "auto")
  ' - | awk '!seen[$0]++' || true
}

# ── Allow-лист: перенесено из sync.sh (единая реализация) ──────────────────
_yaml_adopt_one() { # $1=allowip.ipv4|allowip.ipv6  $2=cidr
  local key="$1" cidr="$2" TMP; TMP="$(mktemp)"
  KEY="$key" CIDR="$cidr" \
  yq e -P 'setpath( env(KEY)|split("."); ((. // []) + [env(CIDR)]) | unique )' \
     "$SETTINGS_YAML" >"$TMP" || { rm -f "$TMP"; return 0; }
  _write_if_changed "$SETTINGS_YAML" "$TMP" yaml || true
}

allow_sync_ipsets() {
  ipset create ipset-allow  hash:net              comment -exist 2>/dev/null || true
  ipset create ipset-allow6 hash:net family inet6 comment -exist 2>/dev/null || true

  declare -A CUR4 CUR6
  while read -r _a _set _cidr _rest; do
    [[ -n "${_cidr:-}" ]] || continue
    local cmt; cmt="$(sed -n 's/.*comment[[:space:]]\+"\([^"]*\)".*/\1/p' <<<"$_rest")"
    CUR4["$_cidr"]="${cmt:-}"
  done < <(ipset save ipset-allow  2>/dev/null | awk '$1=="add"')
  while read -r _a _set _cidr _rest; do
    [[ -n "${_cidr:-}" ]] || continue
    local cmt; cmt="$(sed -n 's/.*comment[[:space:]]\+"\([^"]*\)".*/\1/p' <<<"$_rest")"
    CUR6["$_cidr"]="${cmt:-}"
  done < <(ipset save ipset-allow6 2>/dev/null | awk '$1=="add"')

  _ensure_settings_lock || true
  for k in "${!CUR4[@]}"; do
    [[ "${CUR4[$k]}" == "src=settings" ]] && continue
    _yaml_adopt_one 'allowip.ipv4' "$k" || true
    ipset del ipset-allow "$k" 2>/dev/null || true
    ipset add ipset-allow "$k" comment "src=settings" -exist
  done
  for k in "${!CUR6[@]}"; do
    [[ "${CUR6[$k]}" == "src=settings" ]] && continue
    _yaml_adopt_one 'allowip.ipv6' "$k" || true
    ipset del ipset-allow6 "$k" 2>/dev/null || true
    ipset add ipset-allow6 "$k" comment "src=settings" -exist
  done
  _release_settings_lock || true

  readarray -t A4 < <(yaml_allow_all | grep -E '^[0-9.]+(/[0-9]+)?$' || true)
  readarray -t A6 < <(yaml_allow_all | grep -F ':' || true)
  declare -A SEEN4 SEEN6
  for x in "${A4[@]}"; do
    SEEN4["$x"]=1
    [[ "${CUR4[$x]:-}" == "src=settings" ]] || {
      ipset del ipset-allow "$x" 2>/dev/null || true
      ipset add ipset-allow "$x" comment "src=settings" -exist
    }
  done
  for x in "${A6[@]}"; do
    SEEN6["$x"]=1
    [[ "${CUR6[$x]:-}" == "src=settings" ]] || {
      ipset del ipset-allow6 "$x" 2>/dev/null || true
      ipset add ipset-allow6 "$x" comment "src=settings" -exist
    }
  done
  for k in "${!CUR4[@]}"; do
    [[ "${CUR4[$k]}" == "src=settings" && -z "${SEEN4[$k]:-}" ]] && ipset del ipset-allow "$k" 2>/dev/null || true
  done
  for k in "${!CUR6[@]}"; do
    [[ "${CUR6[$k]}" == "src=settings" && -z "${SEEN6[$k]:-}" ]] && ipset del ipset-allow6 "$k" 2>/dev/null || true
  done
}

# -------- Внешний интерфейс и IP-адреса (централизовано) --------------------
# Кэшируем, чтобы не ждать повторно при многократных вызовах
SERVER_IP4=""; SERVER_IP6=""

# Вернуть внешний интерфейс: server.ext_if или автоопределение
server_iface() {
  local ifc; ifc="$(yaml_get 'server.ext_if' '')"
  # поддержим 'auto' как явный сигнал автодетекта
  [[ ${ifc,,} == auto || -z "$ifc" ]] && ifc="$(_primary_iface 30)"
  printf '%s' "$ifc"
}

# Внешний IPv4: явный из settings.server.ipv4, иначе — ждём появления на iface.
# Аргумент: timeout ожидания (сек), по умолчанию 30. Возвращает '0.0.0.0' при неудаче.
server_ip4() {
  local wait=${1:-30}
  [[ -n "$SERVER_IP4" && "$SERVER_IP4" != "0.0.0.0" ]] && { echo "$SERVER_IP4"; return 0; }
  local cfg; cfg="$(yaml_get_ip 'server.ipv4' '0.0.0.0')"
  if [[ "$cfg" != "0.0.0.0" ]]; then
    SERVER_IP4="$cfg"
  else
    local ifc; ifc="$(server_iface)"
    if (( wait > 0 )); then
      SERVER_IP4="$(wait_ip "$ifc" "$wait" 4 || echo '')"
    fi
    [[ -z "$SERVER_IP4" ]] && SERVER_IP4="0.0.0.0"
  fi
  echo "$SERVER_IP4"
}

# Внешний IPv6: аналогично IPv4. Возвращает '::' при неудаче.
server_ip6() {
  local wait=${1:-30}
  [[ -n "$SERVER_IP6" && "$SERVER_IP6" != "::" ]] && { echo "$SERVER_IP6"; return 0; }
  local cfg; cfg="$(yaml_get_ip 'server.ipv6' '::')"
  if [[ "$cfg" != "::" ]]; then
    SERVER_IP6="$cfg"
  else
    local ifc; ifc="$(server_iface)"
    if (( wait > 0 )); then
      SERVER_IP6="$(wait_ip "$ifc" "$wait" 6 || echo '')"
    fi
    [[ -z "$SERVER_IP6" ]] && SERVER_IP6="::"
  fi
  echo "$SERVER_IP6"
}

# Домен сервера: 'auto' → пусто; убираем кавычки (и " и ') и пробелы по краям.
# Реализация без extglob, чтобы не полагаться на shopt.
server_domain() {
  local d
  d="$(yaml_get 'server.domain' '')"
  [[ ${d,,} == auto ]] && d=""
  # убрать все двойные и одинарные кавычки
  d="${d//\"/}"; d="${d//\'/}"
  # трим пробелов по краям (POSIX-совместимо)
  d="$(printf '%s' "$d" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  printf '%s' "$d"
}

# ── yaml_set <key> <value> ────────────────────────────────────────────────
# Записывает (или обновляет) скаляр в settings.yaml.
# • Поддерживает DRY-режим (показывает diff, но не пишет).
# • Ключ — в dot-нотации (пример: filters.discord).
# • Значение передаётся как есть: true/false/строка/число.
yaml_set() {
  local key="$1" val="${2-}"
  [[ -z "$key" ]] && { echo "yaml_set: key is empty" >&2; return 1; }
  if [[ -z "${val}" ]]; then
    echo "yaml_set: value for '$key' is empty – skip" >&2
    return 0
  fi

  _ensure_settings_lock || return 1
  _ensure_settings_yaml

  local TMP; TMP="$(mktemp)"
  KEY="$key" VAL="$val" \
  yq e -P 'setpath( env(KEY)|split("."); (env(VAL)|from_yaml) )' \
    "$SETTINGS_YAML" >"$TMP"
  _write_if_changed "$SETTINGS_YAML" "$TMP" yaml || true
  # Сразу отпускаем lock, чтобы другие процессы (в т.ч. systemd-юниты) не ждали
  _release_settings_lock
  return 0            # всегда 0, даже если файл не менялся
}

yaml_upstream_quad() {
  case "$(yaml_get 'dns.upstream' cloudflare | tr '[:upper:]' '[:lower:]')" in
    quad9)
      printf '%s\n' 9.9.9.10 149.112.112.10 \
                     2620:fe::10 2620:fe::fe:10 | tr -d '\r' ;;
    google)
      printf '%s\n' 8.8.8.8 8.8.4.4 \
                     2001:4860:4860::8888 2001:4860:4860::8844 | tr -d '\r' ;;
    *)
      printf '%s\n' 1.1.1.1 1.0.0.1 \
                     2606:4700:4700::1111 2606:4700:4700::1001 | tr -d '\r' ;;
  esac
}

# Вернуть DoT URL (tls://…) и порт_tls: prefer явные dns.dot/dns.port_tls, иначе — по upstream.
yaml_upstream_dot() {
  local up dot_url port
  up="$(yaml_get 'dns.upstream' cloudflare | tr '[:upper:]' '[:lower:]')"
  # Новые ключи без fallback’ов
  local dot_cfg; dot_cfg="$(yaml_get 'dns.dot' '')"
  local prt_cfg; prt_cfg="$(yaml_get 'dns.port_tls' 853)"
  if [[ -n "$dot_cfg" && "${dot_cfg,,}" != "auto" ]]; then
    # Нормализуем префикс tls://
    if [[ "$dot_cfg" == tls://* ]]; then
      dot_url="$dot_cfg"
    else
      dot_url="tls://$dot_cfg"
    fi
    port="$prt_cfg"
  else
    case "$up" in
      quad9)  dot_url="tls://dns10.quad9.net" ;;
      google) dot_url="tls://dns.google" ;;
      *)      dot_url="tls://one.one.one.one" ;;   # cloudflare (default)
    esac
    port="$prt_cfg"
  fi
  printf '%s\t%s\n' "$dot_url" "$port"
}

#──────────────────────────────────────────────────────────────────────────────
# SNAT helpers — создание / удаление правил при добавлении / удалении клиента
#──────────────────────────────────────────────────────────────────────────────
# add_snat <ip> <name>
add_snat() {
  local ip="$1" name="$2"
  [[ -z "$ip" || -z "$name" ]] && return 0
  _have yq || return 0
  _ensure_settings_lock || return 1
  _ensure_settings_yaml
  local TMP; TMP="$(mktemp)"
  SNAT_IP="$ip" SNAT_NAME="$name" \
  yq e -P '
    .snat = (.snat // []) |
    .snat |= (
      map(select(.internal != env(SNAT_IP) and .name != env(SNAT_NAME)))
      + [{                                             # добавить/обновить
          "name":     env(SNAT_NAME),
          "internal": env(SNAT_IP),
          "external": "0.0.0.0"
        }]
    )
  ' "$SETTINGS_YAML" >"$TMP"
  _write_if_changed "$SETTINGS_YAML" "$TMP" yaml || true
  _release_settings_lock
}

#──────────────────────────────────────────────────────────────────────────────
# AdGuard Home: helpers для clients.persistent (перенесены из client.sh)
#   add_agh_client  <ip> <mode: split|full> <nick>
#   remove_agh_client <nick>
#──────────────────────────────────────────────────────────────────────────────
add_agh_client() {
  local ip="$1" mode="$2" nick="$3" agh="${AGH_DIR}/AdGuardHome.yaml"
  # Тихо выходим, если нет AGH или неполные аргументы
  [[ -f "$agh" && -n "$ip" && -n "$mode" && -n "$nick" ]] || return 0
  _have yq || { echo "[WARN] yq not found, skip AdGuardHome client registration"; return 0; }
  _ensure_settings_lock || return 1
 
  local UPSTREAM_HOST AGH_UUID EXIST_UID
  if [[ "$mode" == split ]]; then
    UPSTREAM_HOST="${KRESD3_IP:-127.0.0.3}:${DNS_PORT:-53}"   # SPLIT → @3
  else
    UPSTREAM_HOST="${KRESD4_IP:-127.0.0.4}:${DNS_PORT:-53}"   # FULL  → @4
  fi
  # 1) Пытаемся переиспользовать существующий uid по имени клиента
  EXIST_UID="$(
    AGH_NICK="$nick" yq e -r '
      (.clients.persistent // [])[]
      | select(.name == env(AGH_NICK))
      | .uid // ""
    ' "$agh" 2>/dev/null | head -n1 || true
  )"
  # 2) Если по имени не нашли — пробуем по IP (на случай переименований)
  if [[ -z "$EXIST_UID" || "$EXIST_UID" == "null" ]]; then
    EXIST_UID="$(
      CLIENT_IP="$ip" yq e -r '
        (.clients.persistent // [])[]
        | select(((.ids // []) | contains([env(CLIENT_IP)])))
        | .uid // ""
      ' "$agh" 2>/dev/null | head -n1 || true
    )"
  fi
  # 3) Берём найденный uid, либо генерируем новый
  if [[ -n "$EXIST_UID" && "$EXIST_UID" != "null" ]]; then
    AGH_UUID="$EXIST_UID"
  elif _have uuidgen; then
    AGH_UUID="$(uuidgen)"
  else
    AGH_UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || date +%s%N)"
  fi

  # Идемпотентный upsert в один проход с tmp-файлом
  local TMP; TMP="$(mktemp)"
  CLIENT_IP="$ip" AGH_NICK="$nick" UPSTREAM_HOST="$UPSTREAM_HOST" AGH_UUID="$AGH_UUID" \
  yq e -P '
    .clients.persistent = (.clients.persistent // []) |
    .clients.persistent =
      (
        # выбрасываем любые старые записи того же клиента:
        #  - по uid (стабильный идентификатор)
        #  - или по имени
        #  - или по IP (на случай переименований/смены режима)
        (.clients.persistent
          | map(
              select(
                (
                  ((.uid // "") == env(AGH_UUID)) or
                  (.name == env(AGH_NICK)) or
                  ((.ids // []) | contains([env(CLIENT_IP)]))
                ) | not
              )
            )
        )
        +
        # добавляем актуальную запись
        [
          {
            "name": env(AGH_NICK),
            "ids": [env(CLIENT_IP)],
            "upstreams": [env(UPSTREAM_HOST)],
            "uid": env(AGH_UUID),
            "use_global_settings": false
          }
        ]
      )
  ' "$agh" >"$TMP"
  local _changed=0
  if _write_if_changed "$agh" "$TMP" yaml; then
    _changed=1
  fi
  if [[ $_changed -eq 1 ]]; then
    # важно: сначала права, потом рестарт
    if [[ "$DRY_RUN" != 1 ]]; then
      agh_fix_perms "$agh"
    fi
    # Перед systemctl — отпускаем lock, чтобы не дедлочиться с юнит-хуками
    _release_settings_lock
    # Позволяем отложить рестарт (пачечные операции)
    if [[ "${ADD_NO_RESTART:-0}" != 1 ]]; then
      _settings__svc try-reload-or-restart AdGuardHome >/dev/null 2>&1 || true
    fi
    # Фиксация версии — короткая операция; сама возьмёт/отпустит свой lock
    bump_service_ver adguard_home "$(_detect_ver_agh)"
  fi
  # На случай, если мы не попали в ветку изменений — делаем отпускание идемпотентно
  _release_settings_lock
}

remove_agh_client() {
  local nick="$1" agh="${AGH_DIR}/AdGuardHome.yaml"
  [[ -f "$agh" && -n "$nick" ]] || return 0
  _have yq || { echo "[WARN] yq not found, skip AdGuardHome client removal"; return 0; }
  _ensure_settings_lock || return 1

  local TMP; TMP="$(mktemp)"
  if ! AGH_NICK="$nick" yq e -P '
    .clients.persistent = (
      (.clients.persistent // []) | map(select(.name != env(AGH_NICK)))
    )
  ' "$agh" >"$TMP"; then
    echo "[WARN] yq failed, skip AdGuardHome client removal" >&2
    rm -f "$TMP"
    _release_settings_lock
    return 0
  fi

  if _write_if_changed "$agh" "$TMP" yaml; then
    if [[ "$DRY_RUN" != 1 ]]; then
      agh_fix_perms "$agh"
    fi
    # Отпускаем lock и рестартуем (если не отложено)
    _release_settings_lock
    if [[ "${ADD_NO_RESTART:-0}" != 1 ]]; then
      _settings__svc try-reload-or-restart AdGuardHome >/dev/null 2>&1 || true
    fi
  fi
  _release_settings_lock
}

# remove_snat <name>
remove_snat() {
  local name="$1"
  [[ -z "$name" ]] && return 0
  _have yq || return 0
  _ensure_settings_lock || return 1
  _ensure_settings_yaml
  local TMP; TMP="$(mktemp)"
  NAME="$name" \
  yq e -P '
    .snat = (
      (.snat // []) | map(select(.name != env(NAME)))
    )
  ' "$SETTINGS_YAML" >"$TMP"
  _write_if_changed "$SETTINGS_YAML" "$TMP" yaml || true
  _release_settings_lock
}

###############################################################################
# АВТО-ЗАПОЛНЕНИЕ settings.yaml
###############################################################################

# Обновить «косметические» поля в settings.yaml по dns.upstream:
#   • .dns.ipv4 / .dns.ipv6   — человекочитаемые строки вида "up://A | B"
#   • .dns.dot / .dns.port_tls — URL DoT (tls://…) и порт TLS для @1
update_dns_ips() {
  _ensure_settings_lock || return 1
  _ensure_settings_yaml
  local ips=(); mapfile -t ips < <(yaml_upstream_quad)   # 0-3: v4a v4b v6a v6b
  local v4a=${ips[0]} v4b=${ips[1]} v6a=${ips[2]} v6b=${ips[3]}
  local DOT_URL DOT_PORT
  read -r DOT_URL DOT_PORT < <(yaml_upstream_dot)

  # Собираем косметические строки: "up://A | B" (второй может отсутствовать)
  local IPV4_STR=""; local IPV6_STR=""
  [[ -n "$v4a" ]] && IPV4_STR="up://$v4a"
  [[ -n "$v4b" ]] && IPV4_STR="${IPV4_STR} | $v4b"
  [[ -n "$v6a" ]] && IPV6_STR="up://$v6a"
  [[ -n "$v6b" ]] && IPV6_STR="${IPV6_STR} | $v6b"

  local TMP; TMP="$(mktemp)"
  IPV4_STR="$IPV4_STR" IPV6_STR="$IPV6_STR" DOT_URL="$DOT_URL" DOT_PORT="$DOT_PORT" \
  yq e -P '
      .dns.ipv4 = env(IPV4_STR) |
      .dns.ipv6 = env(IPV6_STR) |
      .dns.dot      = env(DOT_URL) |
      .dns.port_tls = (env(DOT_PORT)|tonumber)
  ' "$SETTINGS_YAML" >"$TMP"
  _write_if_changed "$SETTINGS_YAML" "$TMP" yaml || true
  _release_settings_lock
}

# Детекторы текущих версий сервисов (best-effort). Возвращают ПУСТО, если не нашли.
_detect_ver_fail2ban() {
  local v=""
  if _have fail2ban-server; then
    v=$(fail2ban-server -V 2>/dev/null | head -n1 | grep -Eo 'v?[0-9]+([.-][0-9A-Za-z]+)*') || true
  fi
  # apt-версия вида 1.0.2-1~deb11u1 → берём только «1.0.2»
  if [[ -z "$v" ]] && _have dpkg-query; then
    v=$(dpkg-query -W -f='${Version}' fail2ban 2>/dev/null \
         | sed -E 's/^([^+-]+).*/\1/' || true)
  fi
  printf '%s' "$v"
}
_detect_ver_agh() {
  local bin out ver
  for bin in "${AGH_DIR}/AdGuardHome" AdGuardHome; do
    [[ -x "$bin" ]] || continue
    # ① Нормальный вызов (пробуем --version, затем -v), не дольше 3 секунд
    if _have timeout; then
      out=$(timeout 3 "$bin" --version 2>/dev/null | head -n1) || true
    else
      out=$("$bin" --version 2>/dev/null | head -n1) || true
    fi
    if [[ -n "$out" ]]; then
      ver="$(printf '%s' "$out" | grep -Eo 'v?[0-9]+\.[0-9]+(\.[0-9A-Za-z.-]+)?' || true)"
      [[ -n "$ver" ]] && { printf '%s' "$ver"; return; }
    fi
    if _have timeout; then
      out=$(timeout 3 "$bin" -v 2>/dev/null | head -n1) || true
    else
      out=$("$bin" -v 2>/dev/null | head -n1) || true
    fi
    if [[ -n "$out" ]]; then
      # Не роняем set -e -o pipefail, если паттерн не совпал
      ver="$(printf '%s' "$out" | grep -Eo 'v?[0-9]+\.[0-9]+(\.[0-9A-Za-z.-]+)?' || true)"
      [[ -n "$ver" ]] && { printf '%s' "$ver"; return; }
    fi
    # ② Fallback: достаём версию из строк бинаря (если доступен strings)
    if command -v strings >/dev/null 2>&1; then
      if out=$(strings -n3 "$bin" | grep -Eom1 'v?[0-9]+\.[0-9]+(\.[0-9A-Za-z.-]+)?'); then
        printf '%s' "$out"
        return
      fi
    fi
  done
  # «Последний шанс»: если что-то осталось в $out — вернём только токен версии
  [[ -n "${out:-}" ]] && printf '%s' "$(printf '%s' "$out" | grep -Eo 'v?[0-9]+\.[0-9]+(\.[0-9A-Za-z.-]+)?' || true)"
}

# Обновить .<svc>.version / .<svc>.updated ТОЛЬКО если версия действительно изменилась.
# Использует формат с префиксом "v", но принимает как "1.2.3", так и "v1.2.3".
bump_service_ver() { # $1=fail2ban|adguard_home  $2=new_version
  local svc="$1" new="$2" cur today _had_lock=0
  [[ -n "${_SETTINGS_LOCK_FD:-}" ]] && _had_lock=1
  _ensure_settings_lock || return 1
  [[ $_had_lock -eq 0 ]] && trap '_release_settings_lock' RETURN
  _ensure_settings_yaml
  [[ -z "$new" ]] && return 0
  [[ "$new" =~ ^v ]] || new="v${new}"
  cur=$(yq e -r ".${svc}.version // \"\"" "$SETTINGS_YAML")
  [[ "$cur" == "$new" ]] && return 0
  today="$(_today)"
  local TMP; TMP="$(mktemp)"
  SVC="$svc" VER="$new" UPD="$today" \
  yq e -P '
    .[env(SVC)].version = env(VER) |
    .[env(SVC)].updated = env(UPD)
  ' "$SETTINGS_YAML" >"$TMP"
  _write_if_changed "$SETTINGS_YAML" "$TMP" yaml || true
}

# Единая точка автозаполнения (можно дергать вручную ключом --autofill)
autofill_settings() {
  # DNS IPs — можно пересчитывать всегда (идемпотентно).
  update_dns_ips
  # Версии — только при реальной смене.
  bump_service_ver fail2ban    "$(_detect_ver_fail2ban)"
  bump_service_ver adguard_home "$(_detect_ver_agh)"
}

# ── ЕДИНЫЙ рендер системных DNS-файлов (без `resolv.conf`, без рестартов) ──
# Делает только косметику в `/etc/network/interfaces`:
#   • всегда держит строки `dns-nameservers` закомментированными;
#   • подставляет актуальные upstream-адреса (видно в файле, но не активно).
_update_system_upstream() {
  # читаем 4 адреса (2×IPv4 + 2×IPv6) построчно
  local _dns=() DNS4_1 DNS4_2 DNS6_1 DNS6_2
  readarray -t _dns < <(yaml_upstream_quad)
  DNS4_1="${_dns[0]}"; DNS4_2="${_dns[1]}"
  DNS6_1="${_dns[2]}"; DNS6_2="${_dns[3]}"

  # IPv6 есть?
  local IPV6_AVAIL; IPV6_AVAIL="$(_ipv6_available)"

  # ── /etc/network/interfaces: косметическая правка dns-nameservers ───
  if [[ -f /etc/network/interfaces ]]; then
    local IF=/etc/network/interfaces TMP_IF
    TMP_IF="$(mktemp)"
    local PRIMARY_IF PRIMARY_IF_ESC
    PRIMARY_IF="$(_primary_iface 5)"
    PRIMARY_IF_ESC="$(printf '%s' "$PRIMARY_IF" | sed -E 's/[][\.^$*+?(){}|\\]/\\&/g')"

    awk -v v4a="$DNS4_1" -v v4b="$DNS4_2" \
        -v v6a="$DNS6_1" -v v6b="$DNS6_2" -v has6="$IPV6_AVAIL" \
        -v ifname="$PRIMARY_IF_ESC" '
      # Меняем ТОЛЬКО строки dns-nameservers под:
      #   - iface <ifname> inet  static
      #   - iface <ifname> inet6 static
      # Ничего не добавляем и не удаляем; позиция строки сохраняется.
      function join2(a,b){ return (b=="" ? a : a" "b) }

      # <ifname> / IPv4
      $0 ~ "^iface[[:space:]]+" ifname "[[:space:]]+inet[[:space:]]+static([[:space:]]*(#.*)*)?$"{
          print; in4=1; next
      }
      in4 && /^[[:space:]]*#?[[:space:]]*dns-nameservers[[:space:]]*/{
          print "    # dns-nameservers " join2(v4a,v4b)
          in4=0; next
      }
      in4 && (/^iface[[:space:]]/ || /^$/) { in4=0 }   # выход из стэнзы

      # <ifname> / IPv6
      $0 ~ "^iface[[:space:]]+" ifname "[[:space:]]+inet6[[:space:]]+static([[:space:]]*(#.*)*)?$"{
          print; in6=1; next
      }
      in6 && /^[[:space:]]*#?[[:space:]]*dns-nameservers[[:space:]]*/{
          if(has6=="y"){
              print "    # dns-nameservers " join2(v6a,v6b)
          } else print
          in6=0; next
      }
      in6 && (/^iface[[:space:]]/ || /^$/) { in6=0 }   # выход из стэнзы

      { print }
    ' "$IF" >"$TMP_IF"
    _write_if_changed "$IF" "$TMP_IF" || true                # «без-изменений» ≠ ошибка
  fi
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
# AdGuard Home: шаблон и самолечение (полный YAML + заполнение ключей)
# ──────────────────────────────────────────────────────────────────────────────
# ── Fail2Ban helper: подтягиваем TRUST4/6 → ignoreip ────────────────────────
_update_f2b_ignoreip() {
  local jail=/etc/fail2ban/jail.local
  # DRY-режим: ничего не правим, только сообщаем
  if [[ "$DRY_RUN" == 1 ]]; then
    if [[ -f "$jail" ]]; then
      echo "[DRY] would update ignoreip in $jail ([DEFAULT])"
    else
      echo "[DRY] would skip: $jail missing (expected from repo)"
    fi
    return 0
  fi

  # адреса одной строкой
  local line
  line="ignoreip = 127.0.0.1/8 ::1 $(yaml_allow_all | tr '\n' ' ')"

  # если файла/каталога нет — создадим
  install -d -m 755 /etc/fail2ban 2>/dev/null || true
  if [[ ! -f "$jail" ]]; then
    echo "[WARN] $jail not found; skip updating (setup must place it from repo)" >&2
    return 0
  fi

  if ! grep -q '^\[DEFAULT\]' "$jail" 2>/dev/null; then
    # нет секции — добавляем в конец
    local tmp; tmp="$(mktemp)"
    { cat "$jail"; printf '\n[DEFAULT]\n%s\n' "$line"; } >"$tmp"
    mv -f -- "$tmp" "$jail"
    chmod 0644 "$jail" 2>/dev/null || true
    chown root:root "$jail" 2>/dev/null || true
    return 0
  fi

  # есть секция DEFAULT: проверим, есть ли в ней ignoreip
  if awk '
      /^\[DEFAULT\]/{inblk=1; next}           # начали секцию
      /^\[/{inblk=0}                          # любой новый заголовок — выходим
      inblk && /^[[:space:]]*ignoreip[[:space:]]*=/ {found=1}
      END{ exit(found?0:1) }
    ' "$jail"; then
    # заменить только внутри DEFAULT
    local tmp; tmp="$(mktemp)"
    awk -v LINE="$line" '
      /^\[DEFAULT\]/{print; inblk=1; next}
      /^[[:space:]]*\[[^][]+\][[:space:]]*(#.*)?$/ { if (inblk){ inblk=0 } }
      /^$/{if(inblk){inblk=0}}
      { if(inblk && $0 ~ /^[[:space:]]*ignoreip[[:space:]]*=/) {print LINE; next}
        print }
    ' "$jail" >"$tmp" && mv -f -- "$tmp" "$jail"
    chmod 0644 "$jail" 2>/dev/null || true
    chown root:root "$jail" 2>/dev/null || true
  else
    # вставить сразу после заголовка DEFAULT
    local tmp; tmp="$(mktemp)"
    awk -v LINE="$line" '
      /^\[DEFAULT\]/{print; print LINE; inserted=1; next}
      { print }
      END{
        if(!inserted){
          print "[DEFAULT]"
          print LINE
        }
      }
    ' "$jail" >"$tmp" && mv -f -- "$tmp" "$jail"
    chmod 0644 "$jail" 2>/dev/null || true
    chown root:root "$jail" 2>/dev/null || true
  fi
}

agh_heal() {
  local AGH_YAML="${AGH_DIR}/AdGuardHome.yaml"
  if [[ "$DRY_RUN" == 1 ]]; then
    [[ -d "${AGH_DIR}" ]] || echo "[DRY] would create dir ${AGH_DIR}"
  else
    mkdir -p "${AGH_DIR}"
  fi
  # инструменты, без которых merge невозможен
  _have yq || { echo "ERROR: yq not found"; return 1; }
  # Если lock не был взят ранее, берём его здесь и отпускаем при выходе
  local _had_lock=0
  [[ -n "${_SETTINGS_LOCK_FD:-}" ]] && _had_lock=1
  _ensure_settings_lock || return 1
  [[ $_had_lock -eq 0 ]] && trap '_release_settings_lock' RETURN

  # ── 1. собираем переменные из settings.yaml ─────────────────────
  local SVPN_NET4 FVPN_NET4 v4a v4b v6a v6b _quad=()
  SVPN_NET4=$(yaml_get 'vpn.nets.split' 10.29.8.0/24)
  FVPN_NET4=$(yaml_get 'vpn.nets.full'  10.28.8.0/24)
  # читаем 4 адреса построчно (read читает только одну строку; нужен readarray)
  readarray -t _quad < <(yaml_upstream_quad)
  v4a="${_quad[0]}"; v4b="${_quad[1]}"; v6a="${_quad[2]}"; v6b="${_quad[3]}"
  vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" || return 1

  # bootstrap (v4+v6) — одной строкой; TRUST_BLOCK — с реальными \n и отступами
  # BOOTSTRAP одной строкой без «хвостовых» пробелов
  local ALLOW_BLOCK="" _allow_list=""
  _allow_list="$(yaml_allow_all || true)"
  if [[ -n "${_allow_list}" ]]; then
    while IFS= read -r _t; do
      [[ -n "${_t}" ]] && ALLOW_BLOCK+=$'    - '"${_t}"$'\n'
    done <<< "${_allow_list}"
    ALLOW_BLOCK="${ALLOW_BLOCK%$'\n'}"
  fi

  # ── адрес GUI и bind_hosts — всегда локально ─
  local GUI_ADDR BIND_BLOCK="" BIND_LIST=()
  GUI_ADDR="${AGH_IP:-127.0.0.6}:80"
  BIND_LIST=( "${AGH_IP:-127.0.0.6}" )
  for ip in "${BIND_LIST[@]}"; do
    [[ -n "$ip" ]] && BIND_BLOCK+=$'    - '"$ip"$'\n'
  done
  BIND_BLOCK="${BIND_BLOCK%$'\n'}"

  # ── 2. рендерим динамический патч ───────────────────────────────
  local PTMP; PTMP=$(mktemp)
  {
    # переменные, которые подставляются в agh_dynamic_patch.yaml
    export SVPN_IP FVPN_IP SVPN_NET4 FVPN_NET4
    export v4a v4b v6a v6b
    export ALLOW_BLOCK="$ALLOW_BLOCK"
    export GUI_ADDR BIND_BLOCK
    export KRESD1_IP KRESD2_IP KRESD3_IP KRESD4_IP PROXY_IP AGH_IP DNS_PORT
    _render "$AGH_TMPL_PATCH"
  } >"$PTMP"

  # ── 3. merge → GEN_TMP, запись только при изменении ─────────────────
  local GEN_TMP; GEN_TMP="$(mktemp)"
  if [[ -s $AGH_YAML ]]; then
    yq ea -P '
      select(fi==0) *          # базовый шаблон
      select(fi==1) *          # динамический патч
      select(fi==2)            # существующий YAML (кастом)
    '  "$AGH_TMPL_BASE" "$PTMP" "$AGH_YAML" >"$GEN_TMP"
  else
    yq ea -P 'select(fi==0) * select(fi==1)' "$AGH_TMPL_BASE" "$PTMP" >"$GEN_TMP"
  fi
  rm -f "$PTMP"

  # убрать пустые элементы из списков DNS (на случай неполных подстановок)
  yq e -i '
    .dns.bootstrap_dns = ((.dns.bootstrap_dns // []) | map(select(. != null and . != ""))) |
    .dns.fallback_dns  = ((.dns.fallback_dns  // []) | map(select(. != null and . != "")))
  ' "$GEN_TMP"

  local _agh_changed=0
  if _write_if_changed "$AGH_YAML" "$GEN_TMP" yaml; then
    _agh_changed=1
  fi
  # ВНЕ зависимости от того, менялся ли файл — выставляем владельца/права
  if [[ "$DRY_RUN" != 1 && -f "$AGH_YAML" ]]; then
    agh_fix_perms "$AGH_YAML"
    if [[ $_agh_changed -eq 1 && "${ADD_NO_RESTART:-0}" != 1 && "${BOOTSTRAP:-0}" != 1 ]]; then
      # рестарт действительно нужен → перед systemctl отпускаем лок
      _release_settings_lock
      _settings__svc try-reload-or-restart AdGuardHome 2>/dev/null || true
    fi
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    [[ -d /var/log/adguardhome ]] || echo "[DRY] would create dir /var/log/adguardhome"
    [[ -f /var/log/adguardhome/access.log ]] || echo "[DRY] would create /var/log/adguardhome/access.log"
  else
    install -d -m 755 /var/log/adguardhome
    touch /var/log/adguardhome/access.log
    chmod 640 /var/log/adguardhome/access.log 2>/dev/null || true
    chown "$(_agh_unit_user)":"$(_agh_unit_user)" /var/log/adguardhome /var/log/adguardhome/access.log 2>/dev/null || true
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Kresd: автогенерация upstream_dns.lua
#   ipv4/ipv6   — IP-адреса апстримов
#   dot/port_tls — DoT URL и порт TLS (использует kresd@1)
# Роли:
#   @1 — DoT hub (FORWARD TLS to provider, v4+v6)
#   @2 — System validating → @1
#   @3 — SPLIT (IPv4-only, lists) → @1
#   @4 — FULL  (IPv4-only) → @1
kresd_upstream() {
  # Читаем «квадру» апстримов: v4a v4b v6a v6b
  local _had_lock=0
  [[ -n "${_SETTINGS_LOCK_FD:-}" ]] && _had_lock=1
  _ensure_settings_lock || return 1
  [[ $_had_lock -eq 0 ]] && trap '_release_settings_lock' RETURN
  local ips=()
  readarray -t ips < <(yaml_upstream_quad)   # 0-3
  local v4a="${ips[0]}" v4b="${ips[1]}" v6a="${ips[2]}" v6b="${ips[3]}"
  local DOT_URL DOT_PORT
  read -r DOT_URL DOT_PORT < <(yaml_upstream_dot)

  # Экранируем одинарные кавычки на случай форматов вида 1.1.1.1#853
  local v4a_e=${v4a//\'/\\\'}
  local v4b_e=${v4b//\'/\\\'}
  local v6a_e=${v6a//\'/\\\'}
  local v6b_e=${v6b//\'/\\\'}

  # Раздельные списки для v4/v6
  local -a UP4_LIST=() UP6_LIST=()
  [[ -n $v4a ]] && UP4_LIST+=("'${v4a_e}'")
  [[ -n $v4b ]] && UP4_LIST+=("'${v4b_e}'")
  [[ -n $v6a ]] && UP6_LIST+=("'${v6a_e}'")
  [[ -n $v6b ]] && UP6_LIST+=("'${v6b_e}'")

  # Sanity check: если апстримов нет — не трогаем файл и не перезапускаем kresd
  if ((${#UP4_LIST[@]} + ${#UP6_LIST[@]} == 0)); then
    echo "[WARN] kresd_upstream: upstream list is empty; skip updating /etc/knot-resolver/upstream_dns.lua" >&2
    return 0
  fi
  local TMP; TMP="$(mktemp)"
  if [[ "$DRY_RUN" != 1 ]]; then
    install -d -m 755 /etc/knot-resolver 2>/dev/null || true
  fi
  # Пишем ipv4/ipv6 + DoT параметры (dot/port_tls)
  {
    printf "return {\n"
    { local IFS=,; printf "  ipv4 = {%s},\n" "${UP4_LIST[*]}"; }
    { local IFS=,; printf "  ipv6 = {%s},\n" "${UP6_LIST[*]}"; }
    printf "  dot = '%s',\n" "${DOT_URL//\'/\\\'}"
    printf "  port_tls = %s\n" "${DOT_PORT}"
    printf "}\n"
  } >"$TMP"
  if [[ "$DRY_RUN" != 1 ]]; then
      chown knot-resolver:knot-resolver "$TMP" 2>/dev/null || true
      chmod 644 "$TMP"
  fi
  if _write_if_changed /etc/knot-resolver/upstream_dns.lua "$TMP"; then
    # при bootstrap перезапуски DNS-сервисов не делаем
    if [[ "$BOOTSTRAP" != 1 ]]; then
      # Перед перезапусками отпускаем lock (он не нужен для systemctl)
      _release_settings_lock
      _settings__svc try-reload-or-restart kresd@1 || true
      _settings__svc try-reload-or-restart kresd@2 || true
      _settings__svc try-reload-or-restart kresd@3 || true
      _settings__svc try-reload-or-restart kresd@4 || true
    fi
  elif [[ "$DRY_RUN" != 1 ]]; then
    # файл не менялся — всё равно нормализуем права
    chown knot-resolver:knot-resolver /etc/knot-resolver/upstream_dns.lua 2>/dev/null || true
    chmod 644 /etc/knot-resolver/upstream_dns.lua 2>/dev/null || true
  fi
}

# ── Точечные синхронизаторы правил (без полного up.sh) ──────────────────────
_fw_del_by_comment() {
  local chain=OUTPUT pat="$1"
  if _has_ipt; then
    local out4; out4="$(_ipt -S "$chain" 2>/dev/null || true)"
    printf '%s\n' "$out4" | awk -v p="$pat" '$0 ~ p && $0 ~ "^-A " {print}' \
      | sed -E 's/^-A /-D /' | while read -r L; do _ipt $L || true; done
  fi
  if _has_ip6t; then
    local out6; out6="$(_ipt6 -S "$chain" 2>/dev/null || true)"
    printf '%s\n' "$out6" | awk -v p="$pat" '$0 ~ p && $0 ~ "^-A " {print}' \
      | sed -E 's/^-A /-D /' | while read -r L; do _ipt6 $L || true; done
  fi
}

_fw_del_in_by_comment() {
  local chain4="$1" chain6="$2" pat="$3"
  if _has_ipt; then
    local out4; out4="$(_ipt -S "$chain4" 2>/dev/null || true)"
    printf '%s\n' "$out4" | awk -v p="$pat" '$0 ~ p && $0 ~ "^-A " {print}' \
      | sed -E 's/^-A /-D /' | while read -r L; do _ipt $L || true; done
  fi
  if _has_ip6t; then
    local out6; out6="$(_ipt6 -S "$chain6" 2>/dev/null || true)"
    printf '%s\n' "$out6" | awk -v p="$pat" '$0 ~ p && $0 ~ "^-A " {print}' \
      | sed -E 's/^-A /-D /' | while read -r L; do _ipt6 $L || true; done
  fi
}

fw_sync_dot_port() {
  read -r _ DOT_PORT < <(yaml_upstream_dot); DOT_PORT="${DOT_PORT:-853}"
  local KRESD_UID; KRESD_UID="$(id -u knot-resolver 2>/dev/null || id -u kresd 2>/dev/null || echo '')"

  # Сносим старые правила по комментариям (v4 и v6) — на случай смены порта
  _fw_del_by_comment 'RZANS_DOT_ALLOW'
  _fw_del_by_comment 'RZANS_DOT_REJECT'
  _fw_del_by_comment 'RZANS_DOT_ALLOW6'
  _fw_del_by_comment 'RZANS_DOT_REJECT6'

  # v4
  if _has_ipt; then
    if [[ -n "$KRESD_UID" ]] && "$IPT_BIN" -m owner -h >/dev/null 2>&1; then
      _ipt -C OUTPUT -p tcp --dport "$DOT_PORT" -m owner --uid-owner "$KRESD_UID" \
           -m set --match-set ipset-dot dst -m comment --comment RZANS_DOT_ALLOW -j ACCEPT 2>/dev/null \
        || _ipt -I OUTPUT 1 -p tcp --dport "$DOT_PORT" -m owner --uid-owner "$KRESD_UID" \
           -m set --match-set ipset-dot dst -m comment --comment RZANS_DOT_ALLOW -j ACCEPT
    else
      _ipt -C OUTPUT -p tcp --dport "$DOT_PORT" -m set --match-set ipset-dot dst \
           -m comment --comment RZANS_DOT_ALLOW -j ACCEPT 2>/dev/null \
        || _ipt -I OUTPUT 1 -p tcp --dport "$DOT_PORT" -m set --match-set ipset-dot dst \
           -m comment --comment RZANS_DOT_ALLOW -j ACCEPT
    fi
    if [[ "$DOT_PORT" != "443" ]]; then
      _ipt -C OUTPUT -p tcp --dport "$DOT_PORT" -m comment --comment RZANS_DOT_REJECT \
           -j REJECT --reject-with tcp-reset 2>/dev/null \
        || _ipt -A OUTPUT    -p tcp --dport "$DOT_PORT" -m comment --comment RZANS_DOT_REJECT \
           -j REJECT --reject-with tcp-reset
    fi
  else
    echo "[WARN] iptables backend not found; skip DoT v4 rules" >&2
  fi

  # v6
  if _has_ip6t; then
    if [[ -n "$KRESD_UID" ]] && "$IP6T_BIN" -m owner -h >/dev/null 2>&1; then
      _ipt6 -C OUTPUT -p tcp --dport "$DOT_PORT" -m owner --uid-owner "$KRESD_UID" \
            -m set --match-set ipset-dot6 dst -m comment --comment RZANS_DOT_ALLOW6 -j ACCEPT 2>/dev/null \
        ||  _ipt6 -I OUTPUT 1 -p tcp --dport "$DOT_PORT" -m owner --uid-owner "$KRESD_UID" \
            -m set --match-set ipset-dot6 dst -m comment --comment RZANS_DOT_ALLOW6 -j ACCEPT
    else
      _ipt6 -C OUTPUT -p tcp --dport "$DOT_PORT" -m set --match-set ipset-dot6 dst \
            -m comment --comment RZANS_DOT_ALLOW6 -j ACCEPT 2>/dev/null \
        ||  _ipt6 -I OUTPUT 1 -p tcp --dport "$DOT_PORT" -m set --match-set ipset-dot6 dst \
            -m comment --comment RZANS_DOT_ALLOW6 -j ACCEPT
    fi
    if [[ "$DOT_PORT" != "443" ]]; then
      _ipt6 -C OUTPUT -p tcp --dport "$DOT_PORT" -m comment --comment RZANS_DOT_REJECT6 \
            -j REJECT --reject-with tcp-reset 2>/dev/null \
        ||  _ipt6 -A OUTPUT    -p tcp --dport "$DOT_PORT" -m comment --comment RZANS_DOT_REJECT6 \
            -j REJECT --reject-with tcp-reset
    fi
  else
    echo "[WARN] ip6tables backend not found; skip DoT v6 rules" >&2
  fi
}

# Агрегированный «мини-синк» правил — без «apply all»
# ВАЖНО: сначала обновим ipset'ы DoT, потом правила.
sync_fw_all() { dot_ipset_sync; fw_sync_dot_port; fw_sync_ssh_port; fw_sync_vpn_ports; }

fw_sync_ssh_port() {
  local SSH_PORT; SSH_PORT="$(yaml_get 'server.port_ssh' 22)"
  # цепи должны существовать (их создаёт up.sh)
  if _has_ipt; then
    _ipt -S RZANS_INPUT >/dev/null 2>&1 || { echo "[WARN] RZANS_INPUT missing; run up.sh first"; return 0; }
  else
    echo "[WARN] iptables backend not found; run up.sh first" >&2; return 0
  fi
  if _has_ip6t; then _ipt6 -S RZANS_INPUT6 >/dev/null 2>&1 || true; fi
  # гарантируем, что ipset'ы существуют (на случай раннего вызова)
  if command -v ipset >/dev/null 2>&1; then
    ipset create ipset-allow  hash:net              comment -exist 2>/dev/null || true
    ipset create ipset-allow6 hash:net family inet6 comment -exist 2>/dev/null || true
  fi
  _fw_del_in_by_comment RZANS_INPUT RZANS_INPUT6 'RZANS_SSH_ALLOW'
  _ipt -C RZANS_INPUT  -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow  src -m comment --comment RZANS_SSH_ALLOW  -j ACCEPT 2>/dev/null \
    || _ipt -I RZANS_INPUT 1 -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow  src -m comment --comment RZANS_SSH_ALLOW  -j ACCEPT
  if _has_ip6t; then
    _ipt6 -C RZANS_INPUT6 -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow6 src -m comment --comment RZANS_SSH_ALLOW6 -j ACCEPT 2>/dev/null \
      || _ipt6 -I RZANS_INPUT6 1 -p tcp --dport "$SSH_PORT" -m set --match-set ipset-allow6 src -m comment --comment RZANS_SSH_ALLOW6 -j ACCEPT
  fi
}

fw_sync_vpn_ports() {
  local SVPN_PORT FVPN_PORT
  SVPN_PORT="$(yaml_get 'vpn.ports.split' 500)"
  FVPN_PORT="$(yaml_get 'vpn.ports.full'  4500)"
  # цепи должны существовать (их создаёт up.sh)
  if _has_ipt; then
    _ipt -S RZANS_INPUT >/dev/null 2>&1 || { echo "[WARN] RZANS_INPUT missing; run up.sh first"; return 0; }
  else
    echo "[WARN] iptables backend not found; run up.sh first" >&2; return 0
  fi
  if _has_ip6t; then _ipt6 -S RZANS_INPUT6 >/dev/null 2>&1 || true; fi
  _fw_del_in_by_comment RZANS_INPUT RZANS_INPUT6 'RZANS_VPN_SPORT|RZANS_VPN_FPORT'
  if [[ "$SVPN_PORT" == "$FVPN_PORT" ]]; then
    _ipt  -C RZANS_INPUT  -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT  -j ACCEPT 2>/dev/null \
      || _ipt  -I RZANS_INPUT 1 -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT  -j ACCEPT
    if _has_ip6t; then
      _ipt6 -C RZANS_INPUT6 -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT6 -j ACCEPT 2>/dev/null \
        || _ipt6 -I RZANS_INPUT6 1 -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT6 -j ACCEPT
    fi
    return 0
  fi
  _ipt  -C RZANS_INPUT  -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT  -j ACCEPT 2>/dev/null \
    || _ipt  -I RZANS_INPUT 1 -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT  -j ACCEPT
  if _has_ip6t; then
    _ipt6 -C RZANS_INPUT6 -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT6 -j ACCEPT 2>/dev/null \
      || _ipt6 -I RZANS_INPUT6 1 -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_VPN_SPORT6 -j ACCEPT
  fi
  _ipt  -C RZANS_INPUT  -p udp --dport "$FVPN_PORT" -m comment --comment RZANS_VPN_FPORT  -j ACCEPT 2>/dev/null \
    || _ipt  -I RZANS_INPUT 1 -p udp --dport "$FVPN_PORT" -m comment --comment RZANS_VPN_FPORT  -j ACCEPT
  if _has_ip6t; then
    _ipt6 -C RZANS_INPUT6 -p udp --dport "$FVPN_PORT" -m comment --comment RZANS_VPN_FPORT6 -j ACCEPT 2>/dev/null \
      || _ipt6 -I RZANS_INPUT6 1 -p udp --dport "$FVPN_PORT" -m comment --comment RZANS_VPN_FPORT6 -j ACCEPT
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Что писать в DNS клиентов (для генератора client.sh) — УНИФИЦИРОВАНО:
#  Всегда:
#    SVPN_DNS = SVPN_IP
#    FVPN_DNS = FVPN_IP
#  Это гарантирует стабильность профилей при любых настройках — схема всегда одинаковая.
dns_targets_for_clients() {
  local SVPN_NET4 FVPN_NET4
  SVPN_NET4="$(yaml_get 'vpn.nets.split' 10.29.8.0/24)"
  FVPN_NET4="$(yaml_get 'vpn.nets.full'  10.28.8.0/24)"
  vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" || return 1
  echo "SVPN_DNS=${SVPN_IP}"
  echo "FVPN_DNS=${FVPN_IP}"
}

###############################################################################
# Inlined apply layer: systemctl wrapper + apply_* entrypoints
# (apply.sh больше не нужен)
###############################################################################
_settings__svc() {
  if [[ "${DRY_RUN:-0}" == 1 || "${BOOTSTRAP:-0}" == 1 ]]; then
    echo "[NOOP] systemctl $*"
  else
    [[ -z "${1-}" ]] && return 0
    local verb="$1"; shift || true
    case "$verb" in
      reload|try-reload-or-restart|restart|try-restart)
        if command -v timeout >/dev/null 2>&1; then
          timeout 20s systemctl --no-block "$verb" "$@" || true
        else
          systemctl --no-block "$verb" "$@" || true
        fi
        ;;
      *)
        systemctl "$verb" "$@"
        ;;
    esac
  fi
}

apply_settings_services() {
  local agh sshp
  agh="$(yaml_bool 'adguard_home.enable')"
  sshp="$(yaml_bool 'fail2ban.enable')"

  agh_heal || true
  _release_settings_lock

  if [[ "$agh" == "y" ]]; then
    _settings__svc enable --now AdGuardHome || true
  else
    _settings__svc disable --now AdGuardHome 2>/dev/null || true
  fi

  if [[ "$sshp" == "y" ]]; then
    local BEFORE AFTER
    if [[ -f /etc/fail2ban/jail.local ]] && _have md5sum; then
      BEFORE=$(md5sum /etc/fail2ban/jail.local | awk '{print $1}')
    else
      BEFORE=""
    fi
    _update_f2b_ignoreip
    if [[ -f /etc/fail2ban/jail.local ]] && _have md5sum; then
      AFTER=$(md5sum /etc/fail2ban/jail.local | awk '{print $1}')
    else
      AFTER=""
    fi
    _settings__svc enable --now fail2ban || true
    if [[ "$BEFORE" != "$AFTER" ]]; then
      _settings__svc restart fail2ban || true
    fi
  else
    _settings__svc disable --now fail2ban 2>/dev/null || true
  fi
}

apply_settings_bootstrap() {
  BOOTSTRAP=1
  kresd_upstream
  agh_heal || true
  _update_system_upstream
}

apply_settings_upstream() {
  update_dns_ips
  kresd_upstream
  agh_heal || true
  _update_system_upstream
  dot_ipset_sync
  agh_control_post "cache/flush" || true
  kresd_flush_all || true
  fw_sync_dot_port || true
}

apply_settings_vpn() {
  if [[ "${DRY_RUN:-0}" == 1 ]]; then
    echo "[DRY] would run ${FIREWALL_DIR}/up.sh"
  else
    "${FIREWALL_DIR}/up.sh" 2>/dev/null || true
  fi
  if [[ -f /run/rzans_wg_changed ]]; then
    _release_settings_lock
    _settings__svc restart wg-quick@rzans_svpn_main || true
    _settings__svc restart wg-quick@rzans_fvpn_main || true
    [[ "${DRY_RUN:-0}" == 1 ]] || rm -f /run/rzans_wg_changed
  fi

  if [[ "${DRY_RUN:-0}" == 1 ]]; then
    echo "[DRY] would run ${BASE_DIR}/client.sh 4"
  else
    "${BASE_DIR}/client.sh" 4 >/dev/null 2>&1 || true
  fi

  if [[ -f /run/rzans_core_changed ]]; then
      _release_settings_lock
      _settings__svc restart core || true
      [[ "${DRY_RUN:-0}" == 1 ]] || rm -f /run/rzans_core_changed
  fi
}

apply_settings_allow() {
  allow_sync_ipsets
  _update_f2b_ignoreip || true
  _settings__svc try-reload-or-restart fail2ban || true
  # Если allow непустой — убираем временный SSH-boot доступ
  if ipset list ipset-allow  2>/dev/null | grep -q 'Number of entries: [1-9]'; then
    _fw_del_in_by_comment RZANS_INPUT RZANS_INPUT6 'RZANS_SSH_BOOT'
  fi
}

apply_settings_all() {
  _ensure_settings_lock || return 1
  _ensure_settings_yaml

  local _tmp; _tmp="$(mktemp)"
  if [[ -s "$DEFAULTS_YAML" && -s "$SETTINGS_YAML" ]]; then
    yq ea -P 'select(fi==0) * select(fi==1)' "$DEFAULTS_YAML" "$SETTINGS_YAML" >"$_tmp"
  elif [[ -s "$DEFAULTS_YAML" ]]; then
    cp "$DEFAULTS_YAML" "$_tmp"
  elif [[ -s "$SETTINGS_YAML" ]]; then
    cp "$SETTINGS_YAML" "$_tmp"
  else
    printf '{}\n' >"$_tmp"
  fi
  _write_if_changed "$SETTINGS_YAML" "$_tmp" yaml || true
  unset _tmp

  autofill_settings

  _release_settings_lock
  apply_settings_services
  apply_settings_vpn
  apply_settings_upstream
}

# ── CLI-интерфейс ───────────────────────────────────────────────
# если файл подключён через «source», а не запущен напрямую — выходим без CLI-логики
[[ "${BASH_SOURCE[0]}" != "${0}" ]] && return 0

 # Обёртка для CLI-входов: взять lock и гарантированно отпустить при выходе
 _with_lock() { _ensure_settings_lock || return 1; trap '_release_settings_lock' RETURN; "$@"; }

case "${1:-}" in
  --apply)            shift; _with_lock apply_settings_all           "$@"; exit $? ;;
  --apply-changed)    shift; _with_lock apply_settings_all           "$@"; exit $? ;;
  --apply-upstream)   shift; _with_lock apply_settings_upstream      "$@"; exit $? ;;
  --bootstrap)        shift; BOOTSTRAP=1 _with_lock apply_settings_bootstrap "$@"; exit $? ;;
  --apply-vpn)        shift; _with_lock apply_settings_vpn           "$@"; exit $? ;;
  --apply-services)   shift; _with_lock apply_settings_services      "$@"; exit $? ;;
  --apply-allow)      shift; _with_lock apply_settings_allow         "$@"; exit $? ;;
  --sync-fw-ssh)      shift; _with_lock fw_sync_ssh_port             "$@"; exit $? ;;
  --sync-fw-vpn-ports) shift; _with_lock fw_sync_vpn_ports           "$@"; exit $? ;;
  --sync-fw)          shift; _with_lock sync_fw_all                  "$@"; exit $? ;;
  --switch-system-resolve) shift; _with_lock switch_system_resolve   "$@"; exit $? ;;
  --dry-run)          shift; DRY_RUN=1 _with_lock apply_settings_all "$@"; exit $? ;;
  --autofill)         shift; _with_lock autofill_settings            "$@"; exit $? ;;
  *)
    echo "Usage: $0 [--apply|--apply-changed|--apply-upstream|--bootstrap|--apply-vpn|--apply-services|--apply-allow|--sync-fw|--sync-fw-ssh|--sync-fw-vpn-ports|--switch-system-resolve|--dry-run|--autofill]"
    exit 1 ;;
esac
