#!/usr/bin/env bash
# shellcheck shell=bash
# Включаем строгий режим ТОЛЬКО при прямом запуске (а не при source).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
  set -E -o errtrace
fi
IFS=$'\n\t'
umask 022

# фиксируем POSIX-локаль, чтобы регэкспы/пробелы в awk/sed вели себя одинаково
export LC_ALL=C

# -----------------------------------------------------------------------------
# yq v4 helper:
# mikefarah/yq не поддерживает --argjson (это jq-флаг).
# Чтобы аккуратно проставлять любые значения (числа, строки, map/array),
# теперь пишем значение во временный файл и подставляем через load(env(...)).
# Это устойчиво к многострочным YAML/JSON и не ловит «Error: EOF».
# Пример: _yq_apply file '.server.port_ssh = $V' '22'
#         _yq_apply file '.dns = $V' '{"upstream":"quad9","ipv4":"up://9.9.9.10 | 149.112.112.10"}'
_yq_apply() {
  local _file="$1"
  local _expr="$2"     # выражение вида '.path = $V'
  local _val="$3"      # значение в YAML/JSON (число/строка/объект/массив)
  # Подставляем $V через временный файл: load(env(YV_FILE)) — безопасно для многострочных значений.
  local _tmp
  _tmp="$(mktemp)" || { echo "tmp create failed for _yq_apply" >&2; return 1; }
  printf '%s' "$_val" >"$_tmp"
  local _expr_resolved="${_expr//\$V/(load(env(YV_FILE)))}"
  YV_FILE="$_tmp" yq e -i "$_expr_resolved" "$_file"
  local rc=$?
  rm -f -- "$_tmp"
  return $rc
}
# -----------------------------------------------------------------------------

# ── base paths (для единообразия путей) ───────────────────────────
: "${BASE_DIR:=/opt/rzans_vpn_main}"
: "${SETTINGS_DIR:=${BASE_DIR}/settings}"
: "${FIREWALL_DIR:=${BASE_DIR}/firewall}"
# Директория состояния для снапшота авто-применения
: "${STATE_DIR:=/var/lib/rzans_vpn_main}"

# ── pin go-yq v4 ────────────────────────────────────────────────────────────
#  • Bash иногда кеширует первый найденный yq; после PATH-изменений это приводит
#    к запуску «чужого» бинаря.  Переопределяем команду локальной функцией,
#    указывая явный путь /usr/bin/yq (его ставит setup.sh).
#  • Если вдруг нет v4 — прекращаем работу сразу.
# ---------------------------------------------------------------------------
: "${YQ_BIN:=/usr/bin/yq}"
hash -r                                 # сбрасываем возможный кеш Bash
if ! "$YQ_BIN" --version 2>/dev/null | grep -Eq '\bv?4(\.|$)'; then
  echo "ERROR: need go-yq v4+, but $YQ_BIN is missing or outdated" >&2
  exit 90
fi
yq() { command "$YQ_BIN" "$@"; }

# ── pin jq 1.6+ ──────────────────────────────────────────────────────────────
: "${JQ_BIN:=/usr/bin/jq}"
if ! "$JQ_BIN" --version 2>/dev/null | grep -Eq 'jq-1\.(6|[7-9])'; then
  echo "ERROR: need jq 1.6+ (for path enumeration)" >&2
  exit 91
fi
jq() { command "$JQ_BIN" "$@"; }

# ── DNS addresses (как в up.sh) ───────────────────────────────────
# IP’ы локальных сервисов и общий DNS-порт (новая схема)

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
    local _lockdir="/run"; [[ ! -d "$_lockdir" || ! -w "$_lockdir" ]] && _lockdir="/tmp"
    local _mdir="${_lockdir}/rzans_settings.lock.d"
    # Реентерабельность через переменную окружения
    [[ -n "${_SETTINGS_LOCK_MDIR:-}" ]] && return 0
    for (( _i=0; _i<30; _i++ )); do
      if mkdir "$_mdir" 2>/dev/null; then
        _SETTINGS_LOCK_MDIR="$_mdir"; export _SETTINGS_LOCK_MDIR
        return 0
      fi
      sleep 1
    done
    echo "lock timeout: $_mdir" >&2
    return 1
  fi
  # Каталог для лок-файла: /run если доступен, иначе /tmp
  local _lockdir="/run"
  if [[ ! -d "$_lockdir" || ! -w "$_lockdir" ]]; then
    _lockdir="/tmp"
  fi
  # Ре-входимый лок: используем «именованный» FD и экспортируем его номер,
  # чтобы подпроцессы видели уже взятый лок и не пытались блокироваться повторно.
  if [[ -n "${_SETTINGS_LOCK_FD:-}" ]]; then
    return 0
  fi
  local _fd _lockfile="${_lockdir}/rzans_settings.lock"
  exec {_fd}>"$_lockfile" || { echo "open lock failed: $_lockfile" >&2; return 1; }
  # Сначала неблокирующая попытка (избегаем висящих конкурентов),
  # потом — ожидание до 30 с.
  if ! flock -n "$_fd"; then
    flock -w 30 "$_fd" || { echo "lock timeout: $_lockfile" >&2; [[ "$_fd" =~ ^[0-9]+$ ]] && eval "exec ${_fd}>&-" || true; return 1; }
  fi
  _SETTINGS_LOCK_FD="$_fd"
  export _SETTINGS_LOCK_FD
}

# Явно отпускаем блокировку (закрываем дескриптор, сохранённый
# в переменной $_SETTINGS_LOCK_FD), когда она больше не нужна.
_release_settings_lock() {
  if [[ -n "${_SETTINGS_LOCK_FD:-}" ]]; then
    if [[ "${_SETTINGS_LOCK_FD}" =~ ^[0-9]+$ ]]; then
      eval "exec ${_SETTINGS_LOCK_FD}>&-"
    fi
    unset _SETTINGS_LOCK_FD
  elif [[ -n "${_SETTINGS_LOCK_MDIR:-}" ]]; then
    rmdir -- "${_SETTINGS_LOCK_MDIR}" 2>/dev/null || true
    unset _SETTINGS_LOCK_MDIR
  fi
}
# Ловушку на EXIT/INT/TERM включаем только когда файл запущен как самостоятельный скрипт,
# чтобы не трогать окружение вызывающей оболочки при `source`.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  trap '_release_settings_lock 2>/dev/null || true' EXIT INT TERM
fi

# ── требования / проверки ─────────────────────────────────────────
_require_root() {
  [[ $EUID -eq 0 ]] || { echo "ERROR: need root" >&2; exit 100; }
}

_require_prepared() {
  [[ -s "$SETTINGS_YAML" ]] && return 0
  echo "ERROR: settings.yaml is missing. Run: settings.sh --prepare" >&2
  return 110
}

# ── атомичная запись «только при изменении» (+валидация) ──────────────────
# _write_if_changed <dst> <tmp> [yaml]
# Контракт:
#   • 0  → <dst> обновлён (содержимое реально изменилось)
#   • 1  → без изменений (атомарная замена не выполнялась)
#   • 2  → провал валидации YAML (если 3-й аргумент == 'yaml')
#   • >2 → прочие IO/системные ошибки
# Побочные эффекты:
#   • сохраняет uid/gid/права существующего <dst>; если файла не было —
#     выставляет root:root 0644 и (при наличии) делает restorecon.
#   • всегда удаляет временный <tmp> (даже при ошибках).
_write_if_changed() {
  local dst="$1" tmp="$2" v="${3-}"
  local _mode="" _uid="" _gid="" need_update=1 rc=1 _used_root0644=0
  if [[ "$v" == yaml ]]; then
    if ! _have yq || ! yq e '.' "$tmp" >/dev/null 2>&1; then
      echo "YAML validation failed for $dst" >&2
      rm -f "$tmp"; return 2
    fi
  fi
  # Определяем, отличается ли содержимое безопасно (без падений при отсутствии diff/cmp)
  if [[ -f "$dst" ]]; then
    # Снимем текущие атрибуты, чтобы восстановить после замены
    _mode="$(stat -c '%a' "$dst" 2>/dev/null || echo '')"
    _uid="$(stat -c '%u' "$dst" 2>/dev/null || echo '')"
    _gid="$(stat -c '%g' "$dst" 2>/dev/null || echo '')"
    need_update=0
    if _have cmp; then
      cmp -s "$tmp" "$dst" || need_update=1
    elif _have diff; then
      diff -q "$dst" "$tmp" >/dev/null 2>&1 || need_update=1
    else
      need_update=1
    fi
  fi
  if (( need_update )); then
    # Снимем ACL/xattr исходного файла, если он существует
    local _acl_tmp="" _xattr_tmp=""
    if [[ -f "$dst" ]]; then
      if _have getfacl && _have setfacl; then
        _acl_tmp="$(mktemp)" || true
        getfacl --absolute-names -p -- "$dst" >"$_acl_tmp" 2>/dev/null || { rm -f -- "$_acl_tmp"; _acl_tmp=""; }
      fi
      if _have getfattr && _have setfattr; then
        _xattr_tmp="$(mktemp)" || true
        # setfattr --restore ожидает формат getfattr --dump
        getfattr --absolute-names --dump -m - -- "$dst" >"$_xattr_tmp" 2>/dev/null || { rm -f -- "$_xattr_tmp"; _xattr_tmp=""; }
      fi
    fi
    # Пишем во временный файл рядом и делаем атомарный rename
    local dir base tmp2
    dir="$(dirname -- "$dst")"
    base="$(basename -- "$dst")"
    if ! tmp2="$(mktemp "${dir}/.${base}.XXXXXX" 2>/dev/null)"; then
      tmp2="${dir}/.${base}.$$.$RANDOM"
      : >"$tmp2" 2>/dev/null || { echo "tmp create failed in $dir" >&2; rm -f -- "$tmp"; return 1; }
    fi
    mv -f -- "$tmp" "$tmp2"
    if ! mv -f -- "$tmp2" "$dst"; then
      # вернуть исходный tmp на место и сообщить об ошибке
      mv -f -- "$tmp2" "$tmp" 2>/dev/null || true
      rm -f -- "$tmp"
      echo "rename failed: $dst" >&2
      return 1
    fi
    # Восстановим ACL/xattr (если снимали)
    if [[ -n "$_acl_tmp" ]] && [[ -s "$_acl_tmp" ]] && command -v setfacl >/dev/null 2>&1; then
      setfacl --restore="$_acl_tmp" 2>/dev/null || true
    fi
    if [[ -n "$_xattr_tmp" ]] && [[ -s "$_xattr_tmp" ]] && command -v setfattr >/dev/null 2>&1; then
      setfattr --restore="$_xattr_tmp" 2>/dev/null || true
    fi
    # Восстанавливаем права/владельца (или ставим дефолтные)
    if [[ -n "$_mode$_uid$_gid" ]]; then
      chown "${_uid:-0}:${_gid:-0}" "$dst" 2>/dev/null || true
      # безопасная нормализация: только 3–4 восьмеричные цифры
      [[ "$_mode" =~ ^0?[0-7]{3,4}$ ]] || _mode=0644
      chmod "${_mode}" "$dst" 2>/dev/null || true
    else
      _root0644 "$dst"
      _used_root0644=1
    fi
    # Если _root0644 уже делал restorecon — второй раз не нужно
    if (( _used_root0644 == 0 )); then
      if _have selinuxenabled && selinuxenabled; then
        _have restorecon && restorecon -F "$dst" || true
      fi
    fi
    rc=0
  fi
  rm -f "$tmp" ${_acl_tmp:+"$_acl_tmp"} ${_xattr_tmp:+"$_xattr_tmp"}
  return $rc
}

# ── YAML-конфиги (defaults * settings) ───────────────────────────────────────
: "${DEFAULTS_YAML:=${BASE_DIR}/config/templates/settings_defaults.yaml}"
: "${SETTINGS_YAML:=${BASE_DIR}/settings.yaml}"

# директория и файлы шаблонов AdGuard Home
TEMPLATE_DIR="${BASE_DIR}/config/templates"
AGH_TMPL_BASE="${TEMPLATE_DIR}/adguardhome_defaults.yaml"
AGH_TMPL_PATCH="${TEMPLATE_DIR}/adguardhome_patch.yaml"
: "${AGH_DIR:=/opt/AdGuardHome}"

# ──────────────────────────────────────────────────────────────────────────────
# Публичные функции:
#   agh_heal               — создать/восстановить /opt/AdGuardHome/AdGuardHome.yaml
#                            из шаблонов; «плохие» поля (null/""/[]) дозаполняет из патча.
#   server_domain          — вернуть домен ('' если auto/пусто)
#   server_ip4 [wait]      — внешний IPv4: явный из settings или автоопределение (wait сек)
#   server_ip6 [wait]      — внешний IPv6: явный из settings или автоопределение (wait сек)
#   ipv4_host CIDR        — вернуть первый пригодный IPv4-хост для сети (CIDR).
#                           Корректно обрабатывает любые маски:
#                           /0..30 → первый адрес хоста (network+1),
#                           /31,/32 → сам сетевой адрес (без +1).
#   vpn_addrs_from_cidrs SVPN_NET4 FVPN_NET4
#                         — установить: SVPN_IP, FVPN_IP, SVPN_ADDR, FVPN_ADDR,
#                           SVPN_DNS_IP, FVPN_DNS_IP.
# ──────────────────────────────────────────────────────────────────────────────

# ——— helpers ————————————————————————————————————————————————————————————————
_have() { command -v "$1" >/dev/null 2>&1; }
# root:root 0644/root0600 для конфигов
_root0644() {
  local f="$1"
  chown root:root "$f" 2>/dev/null || true
  chmod 0644 "$f" 2>/dev/null || true
  if _have selinuxenabled && selinuxenabled; then
    _have restorecon && restorecon -F "$f" || true
  fi
}
_root0600() {
  local f="$1"
  chown root:root "$f" 2>/dev/null || true
  chmod 0600 "$f" 2>/dev/null || true
  if _have selinuxenabled && selinuxenabled; then
    _have restorecon && restorecon -F "$f" || true
  fi
}

_root0640() {
  local f="$1"
  chown root:root "$f" 2>/dev/null || true
  chmod 0640 "$f" 2>/dev/null || true
  if _have selinuxenabled && selinuxenabled; then
    _have restorecon && restorecon -F "$f" || true
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# ipset helpers: единая реализация создания наборов и флага comment
# ─────────────────────────────────────────────────────────────────────────────
# Вернёт "comment", если ядро+ipset поддерживают комментарии; иначе — пусто.
_ipset_comment_flag() {
  if [[ -n "${_IPSET_CMT_FLAG_CACHED:-}" ]]; then
    printf '%s' "$_IPSET_CMT_FLAG_CACHED"; return 0
  fi
  _IPSET_CMT_FLAG_CACHED=""
  if _have ipset; then
    # уникальные имена, чтобы параллельные запуски не спорили за один и тот же набор
    local __suf="__$$_$RANDOM"
    local __p4="__cmt_probe${__suf}"
    local __p6="__cmt_probe6${__suf}"
    if ipset -! create "$__p4"  hash:ip  family inet  comment >/dev/null 2>&1 \
       && ipset -! create "$__p6" hash:ip  family inet6 comment >/dev/null 2>&1
    then
      _IPSET_CMT_FLAG_CACHED="comment"
      ipset destroy "$__p4" >/dev/null 2>&1 || true
      ipset destroy "$__p6" >/dev/null 2>&1 || true
    fi
  fi
  printf '%s' "$_IPSET_CMT_FLAG_CACHED"
}

# Создать (если нужно) все базовые наборы ipset, устойчиво к старым сборкам.
ipset_ensure_skeleton() {
  _have ipset || return 0
  local C; C="$(_ipset_comment_flag)"
  # allow (список доверенных сетей)
  ipset create ipset-allow   hash:net              ${C} -exist 2>/dev/null || true
  ipset create ipset-allow6  hash:net family inet6 ${C} -exist 2>/dev/null || true
  # динамические баны / «watch»
  ipset create ipset-block   hash:ip  family inet  timeout 0 ${C} maxelem 200000 -exist 2>/dev/null || true
  ipset create ipset-block6  hash:ip  family inet6 timeout 0 ${C} maxelem 200000 -exist 2>/dev/null || true
  ipset create ipset-watch   hash:ip,port              timeout 60 ${C} -exist 2>/dev/null || true
  ipset create ipset-watch6  hash:ip,port family inet6 timeout 60 ${C} -exist 2>/dev/null || true
  # DoT upstream
  ipset create ipset-dot     hash:ip  family inet  ${C} -exist 2>/dev/null || true
  ipset create ipset-dot6    hash:ip  family inet6 ${C} -exist 2>/dev/null || true
}

# Сброс кэша всех экземпляров kresd (идемпотентно, best-effort)
kresd_flush_all() {
  _have socat || return 0
  local _sc="socat"
  _have timeout && _sc="timeout 1s socat"
  local s
  for s in /run/knot-resolver/control/*; do
    [[ -S "$s" ]] || continue
    echo 'cache.clear()' | $_sc - "UNIX-CONNECT:$s" >/dev/null 2>&1 || true
  done
}

# ── change-tracking flags (0/1) ──────────────────────────────────────────────
SSHD_PORT_CHANGED=0
F2B_PORT_CHANGED=0
F2B_IGNOREIP_CHANGED=0
KRESD_UPSTREAM_CHANGED=0
DNS_IPS_CHANGED=0
AGH_ALLOWED_CHANGED=0
_reset_changed_flags(){ : \
 ; SSHD_PORT_CHANGED=0 F2B_PORT_CHANGED=0 F2B_IGNOREIP_CHANGED=0 \
   KRESD_UPSTREAM_CHANGED=0 DNS_IPS_CHANGED=0 \
   AGH_ALLOWED_CHANGED=0; }

# Быстрые проверки статуса systemd (мягкие)
_svc_is_enabled(){ command -v systemctl >/dev/null && systemctl is-enabled --quiet "$1"; }
_svc_is_active(){  command -v systemctl >/dev/null && systemctl is-active  --quiet "$1"; }

# Мягкий reload proxy.service только если сервис активен
_proxy_reload_safely() {
  # не пытаемся HUP-ить неактивный сервис
  if _svc_is_active proxy.service; then
    # Если у юнита есть ExecReload — сработает первый вызов; иначе прямой HUP.
    _settings__svc reload proxy.service || \
      systemctl kill -s HUP proxy.service 2>/dev/null || true
  fi
}

# DoT ipset: единая точка правды для адресов апстрима (v4/v6)
dot_ipset_sync() {
  command -v ipset >/dev/null 2>&1 || { echo "[INFO] ipset missing; skip dot sync"; return 0; }
  # Определим, поддерживает ли ipset опцию 'comment'
  local _CMT; _CMT="$(_ipset_comment_flag)"
  # Межпроцессный лок только на время работы с наборами DoT
  local _lockdir="/run"
  [[ -d "$_lockdir" && -w "$_lockdir" ]] || _lockdir="/tmp"
  local _lock="$_lockdir/rzans_ipset_dot.lock"
  local _locked=0 _fd_opened=0
  exec 9>"$_lock" && _fd_opened=1 || true
  if (( _fd_opened )) && command -v flock >/dev/null 2>&1; then
    flock -w 10 9 || { echo "[INFO] dot_ipset_sync: busy, skip"; exec 9>&-; return 0; }
    _locked=1
  fi

  # Читаем «квадру» (ipv4a ipv4b ipv6a ipv6b)
  readarray -t Q < <(yaml_bootstrap)

  # Уникальные имена временных наборов (чтобы параллельные запуски не пересекались)
  local SUF="__$$_$RANDOM"
  local S4N="ipset-dot${SUF}" S6N="ipset-dot6${SUF}"

  # Создаём боевые (на случай первого запуска) и временные наборы
  ipset create ipset-dot  hash:ip  family inet  ${_CMT} -exist 2>/dev/null || true
  ipset create ipset-dot6 hash:ip  family inet6 ${_CMT} -exist 2>/dev/null || true
  ipset create "$S4N"     hash:ip  family inet  ${_CMT} -exist 2>/dev/null || true
  ipset create "$S6N"     hash:ip  family inet6 ${_CMT} -exist 2>/dev/null || true

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
  (( _locked ))    && flock -u 9 || true
  (( _fd_opened )) && exec 9>&-
}

# #############################################################################
# Коалесинг: аккумулятор NEED и единый исполнитель run_needs
# #############################################################################
declare -A NEED=()
need() { local k="$1"; [[ -n "$k" ]] && NEED["$k"]=1; }

# Порядок: firewall/ipset → конфиги/косметика → enable/disable → рестарты → WG/клиенты
run_needs() {
  local DID_AGH_ENABLE=0 DID_F2B_ENABLE=0
  
  # --- coalesce сервисных действий -----------------------------------------
  # если запрошен restart proxy — reload не выполняем (restart доминирует)
  if [[ -n "${NEED[svc:proxy.restart]:-}" ]]; then
    unset 'NEED[svc:proxy.reload]'
  fi


  # --- firewall/ipset --------------------------------------------------------
  if [[ -n "${NEED[ipset:dot_sync]:-}"    ]]; then dot_ipset_sync || true; fi
  if [[ -n "${NEED[fw:dot-port]:-}"       ]]; then "${FIREWALL_DIR}/up.sh" --fw-dot-port       || true; fi
  if [[ -n "${NEED[fw:ssh]:-}"            ]]; then "${FIREWALL_DIR}/up.sh" --fw-ssh            || true; fi
  if [[ -n "${NEED[fw:vpn-ports]:-}"      ]]; then "${FIREWALL_DIR}/up.sh" --fw-vpn-ports      || true; fi
  if [[ -n "${NEED[fw:nets]:-}"           ]]; then "${FIREWALL_DIR}/up.sh" --fw-nets           || true; fi
  if [[ -n "${NEED[dns:map]:-}" ]]; then
    # Если в этой же партии включаем AGH, откладываем dns:map до post-AGH,
    # чтобы исключить окно, когда DNAT уже указывает на ещё не поднятый AGH.
    if [[ -n "${NEED[svc:agh.enable]:-}" ]] && [[ -z "${NEED[svc:agh.disable]:-}" ]]; then
      :
    else
      "${FIREWALL_DIR}/up.sh" --dns-map || true
    fi
  fi
  if [[ -n "${NEED[fw:mapping]:-}"        ]]; then "${FIREWALL_DIR}/up.sh" --fw-mapping        || true; fi
  if [[ -n "${NEED[fw:snat]:-}"           ]]; then "${FIREWALL_DIR}/up.sh" --vpn-snat          || true; fi
  if [[ -n "${NEED[wg:listen-ports]:-}"   ]]; then "${FIREWALL_DIR}/up.sh" --wg-listen-ports   || true; fi

  # --- Конфиги/косметика (формируют *_CHANGED) -------------------------------
  if [[ -n "${NEED[kresd:upstream]:-}" ]]; then _with_lock kresd_heal || true; fi
  if [[ -n "${NEED[settings:dns-cosmetics]:-}" ]]; then _with_lock update_dns_ips          || true; fi
  if [[ -n "${NEED[sys:upstream-cosmetics]:-}" ]]; then _with_lock _update_system_upstream || true; fi
  if [[ -n "${NEED[f2b:update-port]:-}"      ]]; then _update_f2b_port       || true; fi
  if [[ -n "${NEED[f2b:update-ignoreip]:-}"  ]]; then _update_f2b_ignoreip   || true; fi
  if [[ "$(yaml_bool 'adguard_home.enable')" == y ]]; then
    if [[ -n "${NEED[agh:heal]:-}"     ]]; then _with_lock agh_heal || true; fi
    if [[ -n "${NEED[agh:allowed]:-}" ]]; then
      # Флаг действует только для этого вызова (не влияет на остальной run_needs)
      DEFER_RESTARTS=1 _with_lock agh_allowed_clients || true
    fi
  fi

  # --- enable/disable (только при рассинхроне) -------------------------------
  if [[ -n "${NEED[svc:agh.enable]:-}" ]]; then
    if ! _svc_is_active AdGuardHome.service; then _settings__svc enable --now AdGuardHome.service || true; DID_AGH_ENABLE=1; fi
  fi
  if [[ -n "${NEED[svc:agh.disable]:-}" ]]; then
    if _svc_is_active AdGuardHome.service || _svc_is_enabled AdGuardHome.service; then _settings__svc disable --now AdGuardHome.service 2>/dev/null || true; fi
  fi
  if [[ -n "${NEED[svc:fail2ban.enable]:-}" ]]; then
    if ! _svc_is_active fail2ban; then _settings__svc enable --now fail2ban || true; DID_F2B_ENABLE=1; fi
  fi
  if [[ -n "${NEED[svc:fail2ban.disable]:-}" ]]; then
    if _svc_is_active fail2ban || _svc_is_enabled fail2ban; then _settings__svc disable --now fail2ban 2>/dev/null || true; fi
  fi

  # --- post-enable AGH: применить DNAT только ПОСЛЕ запуска сервиса ----------
  if [[ -n "${NEED[dns:map-post-agh]:-}" ]]; then
    # ждём до ~8s, чтобы AGH стал active (не держим тяжёлых локов)
    if ! _svc_is_active AdGuardHome.service; then
      if command -v systemctl >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
        timeout 8s bash -c 'until systemctl is-active --quiet AdGuardHome.service; do sleep 0.5; done' 2>/dev/null || true
      else
        for _i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
          _svc_is_active AdGuardHome.service && break
          sleep 0.5
        done
      fi
    fi
    # Переключаем DNAT 53 → AGH только если сервис реально активен.
    if _svc_is_active AdGuardHome.service; then
      "${FIREWALL_DIR}/up.sh" --dns-map || true
    else
      echo "[INFO] dns:map-post-agh: AdGuardHome не активен, DNAT оставлен без изменений" >&2
    fi
  fi

  # --- перезапуски сервисов (ТОЛЬКО при реальных изменениях) -----------------
  if [[ -n "${NEED[kresd:upstream]:-}" ]] && (( KRESD_UPSTREAM_CHANGED )); then
    kresd_flush_all || true
    for i in 1 2 3 4; do _settings__svc try-reload-or-restart "kresd@${i}" || true; done
  fi
  if [[ -n "${NEED[svc:agh.reload]:-}"  ]] \
     && [[ "$(yaml_bool 'adguard_home.enable')" == y ]] \
     && (( AGH_ALLOWED_CHANGED )) \
     && (( DID_AGH_ENABLE == 0 )); then
    _settings__svc try-reload-or-restart AdGuardHome.service || true
  fi
  if [[ -n "${NEED[svc:sshd.reload]:-}" ]] && (( SSHD_PORT_CHANGED )); then
    _settings__svc try-reload-or-restart sshd || true
    _settings__svc try-reload-or-restart ssh  || true
  fi
  if [[ -n "${NEED[svc:fail2ban.reload]:-}" ]] \
     && [[ "$(yaml_bool 'fail2ban.enable')" == y ]] \
     && (( F2B_PORT_CHANGED || F2B_IGNOREIP_CHANGED )) \
     && (( DID_F2B_ENABLE == 0 )); then
    _settings__svc try-reload-or-restart fail2ban || true
  fi

  # --- proxy: мягкий reload (HUP) и жёсткий restart --------------------------
  # reload используем для переключения AGH ON/OFF (без даунтайма);
  # restart — для смены vpn.map_dns (меняется DNAT/мэппинг, проще и чище рестартнуть).
  if [[ -n "${NEED[svc:proxy.reload]:-}" ]]; then
    _proxy_reload_safely
  fi

  if [[ -n "${NEED[svc:proxy.restart]:-}" ]]; then
    # На всякий случай сбросим цепи мэппинга перед рестартом, чтобы не оставить «осиротевшие» правила
    "${FIREWALL_DIR}/up.sh" --flush-mapping || true
    _settings__svc restart proxy.service || true
  fi

  # --- WireGuard / клиенты ---------------------------------------------------
  if [[ -n "${NEED[clients:regen]:-}" ]]; then
    "${BASE_DIR}/client.sh" 4 >/dev/null 2>&1 || true
  fi
  if [[ -n "${NEED[wg:restart]:-}" ]] && __wg_should_restart; then
    _settings__svc restart wg-quick@rzans_svpn_main || true
    _settings__svc restart wg-quick@rzans_fvpn_main || true
  fi
  NEED=(); _reset_changed_flags
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
    u="$(systemctl show -p User --value AdGuardHome.service 2>/dev/null || true)"
    [[ -z "$u" ]] && u="$(
      ( systemctl cat AdGuardHome.service 2>/dev/null || true ) | awk -F= '/^[[:space:]]*User=/{print $2; exit}'
    )"
  fi
  if [[ -z "$u" ]]; then
    if id -u adguardhome >/dev/null 2>&1; then u="adguardhome"; else u="root"; fi
  fi
  printf '%s' "$u"
}

# Определить пользователя и группу для служб kresd (поддержка kresd@N/kresdN/knot-resolver)
_kresd_unit_user() {
  local candidates=(
    kresd@1.service kresd@2.service kresd@3.service kresd@4.service
    kresd1.service  kresd2.service  kresd3.service  kresd4.service
    knot-resolver.service
  )
  local u="" g=""
  if command -v systemctl >/dev/null 2>&1; then
    for unit in "${candidates[@]}"; do
      systemctl cat "$unit" >/dev/null 2>&1 || continue
      u="$(systemctl show -p User  --value "$unit" 2>/dev/null || true)"
      g="$(systemctl show -p Group --value "$unit" 2>/dev/null || true)"
      # Доп. fallback: если show пусто — парсим сам unit
      if [[ -z "$u" || -z "$g" ]]; then
        local _cat
		_cat="$(systemctl cat "$unit" 2>/dev/null || true)"
        [[ -z "$u" ]] && u="$(awk -F= '/^[[:space:]]*User=/{print $2; exit}'  <<<"$_cat")"
        [[ -z "$g" ]] && g="$(awk -F= '/^[[:space:]]*Group=/{print $2; exit}' <<<"$_cat")"
      fi
      [[ -n "$u" || -n "$g" ]] && break
    done
  fi
  [[ -z "$u" ]] && u="knot-resolver"
  if id -u "$u" >/dev/null 2>&1; then
    [[ -z "$g" ]] && g="$(id -gn "$u" 2>/dev/null || echo "$u")"
  else
    u="root"; g="root"
  fi
  printf '%s:%s' "$u" "$g"
}

# Привести владельца/права AdGuardHome: YAML + каталог/лог (идемпотентно)
agh_fix_perms() {
  local f="${1:-${AGH_DIR}/AdGuardHome.yaml}"
  local u g; u="$(_agh_unit_user)"; g="$(id -gn "$u" 2>/dev/null || echo root)"
  # YAML (если существует)
  if [[ -f "$f" ]]; then
    if id -u "$u" >/dev/null 2>&1; then chown "$u:$g" "$f" 2>/dev/null || true
    else chown root:root "$f" 2>/dev/null || true; fi
    chmod 0640 "$f" 2>/dev/null || true
  if _have selinuxenabled && selinuxenabled; then
    _have restorecon && restorecon -F "$f" || true
    fi
  fi
  # Логи
  local d="/var/log/adguardhome"
  local l="$d/access.log"
  install -d -m 0750 "$d" 2>/dev/null || true
  touch "$l" 2>/dev/null || true
  if id -u "$u" >/dev/null 2>&1; then
    chown "$u:$g" "$d" "$l" 2>/dev/null || true
  else
    chown root:root "$d" "$l" 2>/dev/null || true
  fi
  chmod 0640 "$l" 2>/dev/null || true
  if _have selinuxenabled && selinuxenabled; then
    _have restorecon && restorecon -RF "$d" || true
  fi
}

# Права для файлов kresd (lua/RPZ): идемпотентно, без создания.
# Вызов без аргументов чини́т оба «стандартных» файла: upstream_dns.lua и proxy.rpz (если он есть).
kresd_fix_perms() {
  local ug u g f
  ug="$(_kresd_unit_user)"; u="${ug%:*}"; g="${ug#*:}"
  local files=()
  if (( $# > 0 )); then
    files=( "$@" )
  else
    files=( /etc/knot-resolver/upstream_dns.lua /etc/knot-resolver/proxy.rpz )
  fi
  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    chown "$u:$g" "$f" 2>/dev/null || true
    chmod 0644 "$f" 2>/dev/null || true
    if _have selinuxenabled && selinuxenabled; then
      _have restorecon && restorecon -F "$f" || true
    fi
  done
}

###############################################################################
# Logrotate: гарантированная установка/восстановление конфигов и файлов
###############################################################################
logrotate_ensure() {
  # /etc/logrotate.d
  install -d -m 755 /etc/logrotate.d 2>/dev/null || true

  # 1) AdGuard Home
  local LOGROT_AGH="/etc/logrotate.d/adguardhome"
  # Вычисляем пользователя/группу юнита AGH (fallback → root:root)
  local AGH_U AGH_G
  AGH_U="$(_agh_unit_user)"
  AGH_G="$(id -gn "$AGH_U" 2>/dev/null || echo root)"
  local TMP; TMP="$(mktemp)"
  cat >"$TMP" <<EOF
/var/log/adguardhome/access.log {
    daily
    rotate 7
    size 20M
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ${AGH_U} ${AGH_G}
    postrotate
        systemctl kill -s USR1 AdGuardHome.service 2>/dev/null || true
    endscript
}
EOF
  _write_if_changed "$LOGROT_AGH" "$TMP" || true
  _root0644 "$LOGROT_AGH"

  # 2) Fail2Ban
  local LOGROT_F2B="/etc/logrotate.d/fail2ban"
  # Кросс-дистрибутивно: если есть группа 'adm' → используем её, иначе root
  local F2B_G="root"
  getent group adm >/dev/null 2>&1 && F2B_G="adm"
  TMP="$(mktemp)"
  cat >"$TMP" <<EOF
/var/log/fail2ban.log {
    daily
    rotate 7
    size 20M
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root ${F2B_G}
    postrotate
        fail2ban-client flushlogs >/dev/null 2>&1 || true
    endscript
}
EOF
  _write_if_changed "$LOGROT_F2B" "$TMP" || true
  _root0644 "$LOGROT_F2B"
}

###############################################################################
# AGH точечные апдейты: allowed_clients
###############################################################################

# AGH: обновить только .dns.allowed_clients на основе vpn.nets.split/full
agh_allowed_clients() {
  local AGH_YAML="${AGH_DIR}/AdGuardHome.yaml"
  [[ -f "$AGH_YAML" ]] || { echo "[INFO] AGH YAML not found, skip allowed_clients update"; return 0; }

  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi

  local SVPN_NET4 FVPN_NET4
  SVPN_NET4="$(yaml_get 'vpn.nets.split' '10.29.8.0/24')"
  FVPN_NET4="$(yaml_get 'vpn.nets.full'  '10.28.8.0/24')"

  local TMP; TMP="$(mktemp)"
  cp -f "$AGH_YAML" "$TMP"
  SVPN="$SVPN_NET4" FVPN="$FVPN_NET4" \
  yq e -i '
    .dns.allowed_clients = (
      [env(SVPN), env(FVPN)]
      | map(select(. != null and . != ""))
      | unique | sort
    )
  ' "$TMP" || { rm -f "$TMP"; (( _acq )) && _release_settings_lock; return 1; }

  local _changed=0
  if _write_if_changed "$AGH_YAML" "$TMP" yaml; then _changed=1; fi
  if (( _changed == 1 )); then agh_fix_perms "$AGH_YAML" || true; fi
  if (( _acq )); then _release_settings_lock; fi

  AGH_ALLOWED_CHANGED=$_changed
  if (( _changed == 1 )) && [[ "$(yaml_bool 'adguard_home.enable')" == y ]] && [[ "${DEFER_RESTARTS:-0}" != "1" ]]; then
    _settings__svc try-reload-or-restart AdGuardHome.service >/dev/null 2>&1 || true
  fi
}

# Права для settings.yaml
settings_fix_perms() {
  local f="${1:-$SETTINGS_YAML}"
  [[ -f "$f" ]] || return 0
  _root0600 "$f"
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
    ifc="$(ip -o link show up \
           | awk -F': ' '$2 !~ /^lo(:|$)/{split($2,a,":"); print a[1]; exit}')"
  # убрать возможный хвост @ifN для совместимости с /etc/network/interfaces
  ifc="${ifc%%@*}"
  # ④ крайний fallback
  [[ -z $ifc ]] && ifc="ens3"
  printf '%s' "$ifc"
}

# Публичная обёртка для скриптов up/down: без ожидания по умолчанию.
# Не дублирует логику — использует _primary_iface.
server_iface() { _primary_iface "${1:-0}"; }

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
  _require_root
  # 1) Идемпотентно выключаем и маскируем systemd-resolved
  systemctl disable --now systemd-resolved 2>/dev/null || true
  systemctl mask systemd-resolved 2>/dev/null || true
  # IPv6-доступность и итоговая строка DNS (v4 + опционально v6)
  local IPV6_AVAIL; IPV6_AVAIL="$(_ipv6_available)"
  local HAVE_LO_V6="n"
  if ip -6 addr show dev lo 2>/dev/null | grep -q '::2/128'; then HAVE_LO_V6="y"; fi
  local _dns_line
  if [[ "$IPV6_AVAIL" == y && "$HAVE_LO_V6" == y ]]; then
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
      BEGIN { inres=0; done_dns=0; done_fb=0 }
      /^[[:space:]]*\[Resolve\][[:space:]]*(#.*)?$/ { print; inres=1; next }
      /^[[:space:]]*\[[^][]+\][[:space:]]*(#.*)?$/  { inres=0; print; next }

      inres && $0 ~ /^[[:space:]]*DNS[[:space:]]*=/ && $0 !~ /^[[:space:]]*#/ {
        if (!done_dns) {
          match($0, /^[[:space:]]*/); indent=substr($0, RSTART, RLENGTH)
          p=index($0, "#"); tail=(p?substr($0, p):"")
          print indent "DNS=" NEWDNS (p?" " tail:"")
          done_dns=1
        }
        next
      }

      inres && $0 ~ /^[[:space:]]*FallbackDNS[[:space:]]*=/ && $0 !~ /^[[:space:]]*#/ {
        if (!done_fb) {
          match($0, /^[[:space:]]*/); indent=substr($0, RSTART, RLENGTH)
          p=index($0, "#"); tail=(p?substr($0, p+1):"")       # выкинуть ведущий '#'
          gsub(/^[[:space:]]+/, "", tail)                     # и пробелы после него
          # оставляем закомментированный ключ и сохраняем прежний комментарий после " # "
          print indent "# FallbackDNS=" (tail=="" ? "" : " # " tail)
          done_fb=1
        }
        next
      }
      { print }
    ' "$_rcf" >"$_tmp"
    _write_if_changed "$_rcf" "$_tmp" || true
  fi
  # 3) /etc/resolv.conf → ${KRESD2_IP} (перезаписываем, атомарно в рамках /etc)
  cp -L -- /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null || true
  local _tmpres
  if ! _tmpres="$(mktemp /etc/.resolv.conf.XXXXXX 2>/dev/null)"; then
    _tmpres="/etc/.resolv.conf.$$.$RANDOM"
    : >"$_tmpres" 2>/dev/null || { echo "tmp create failed in /etc" >&2; return 1; }
  fi
  if [[ "$IPV6_AVAIL" == y && "$HAVE_LO_V6" == y ]]; then
    printf 'nameserver %s\nnameserver ::2\noptions edns0 trust-ad\n' "${KRESD2_IP:-127.0.0.2}" >"$_tmpres"
  else
    printf 'nameserver %s\noptions edns0 trust-ad\n' "${KRESD2_IP:-127.0.0.2}" >"$_tmpres"
  fi
  mv -f -- "$_tmpres" /etc/resolv.conf
  _root0644 /etc/resolv.conf
}

# ── YAML helpers (defaults * settings) ───────────────────────────
_yaml_merged() {
  _have yq || { echo "ERROR: yq not found" >&2; return 1; }
  local files=() valid=() f
  [[ -s "$DEFAULTS_YAML"  ]] && files+=("$DEFAULTS_YAML")
  [[ -s "$SETTINGS_YAML"  ]] && files+=("$SETTINGS_YAML")
  # отфильтруем невалидные YAML, чтобы не ронять yq
  for f in "${files[@]}"; do
    yq e '.' "$f" >/dev/null 2>&1 && valid+=("$f")
  done
  [[ ${#valid[@]} -eq 0 ]] && { echo "{}"; return 0; }
  # глубокий мердж документов: правее имеет приоритет
  if [[ ${#valid[@]} -eq 1 ]]; then
    cat "${valid[0]}"
  else
    yq ea -P '. as $item ireduce ({}; . * $item)' "${valid[@]}"
  fi
}

## ───────────────────────────────────────────────────────────────────────────
## STRICT VALIDATION of settings.yaml + FULL REBUILD
##  • Собираем settings.yaml ЦЕЛИКОМ из defaults, накладывая
##    ТОЛЬКО валидные скалярные значения из текущего файла.
##  • Контейнеры (map/seq) не копируем целиком — не ломаем стиль/комментарии.
## ───────────────────────────────────────────────────────────────────────────

# == Примитивные валидаторы ==
__is_port()        { [[ "$1" =~ ^[0-9]+$ ]] && (( 1 <= 10#$1 && 10#$1 <= 65535 )); }
__is_bool_json()   { [[ "$1" == "true" || "$1" == "false" ]]; }
__is_auto_json()   { [[ "${1,,}" == '"auto"' ]]; }

# -- bool helpers: accept legacy "y/n/yes/no/..." and coerce to JSON true/false
__boolish_unquote_lower() {
  local v="$1"
  case "$v" in
    \"*\") v="${v:1:${#v}-2}";;
  esac
  printf '%s' "${v,,}"
}
__is_boolish_json() {
  local s; s="$(__boolish_unquote_lower "$1")"
  case "$s" in
    true|false|y|yes|1|on|enable|enabled|n|no|0|off|disable|disabled) return 0 ;;
    *) return 1 ;;
  esac
}
__to_json_bool() {
  local s; s="$(__boolish_unquote_lower "$1")"
  case "$s" in
    true|y|yes|1|on|enable|enabled)  printf 'true'  ;;
    false|n|no|0|off|disable|disabled) printf 'false' ;;
    *) printf '%s' "$1" ;;
  esac
}

__is_ipv4() {
  local re='^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$'
  [[ "$1" =~ $re ]]
}
__is_ipv4_cidr() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]] || return 1
  IFS=/ read -r ip m <<<"$1"
  __is_ipv4 "$ip" || return 1
  [[ "$m" =~ ^[0-9]+$ ]] && (( m>=0 && m<=32 ))
}

# Достаточно строгая эвристика IPv6 (поддерживает ::, 1..8 хекстретов и IPv4-embedded/mapped)
__is_ipv6() {
  local s="$1"
  # Вариант с вкраплённым IPv4 в конце (например, ::ffff:192.0.2.1)
  if [[ "$s" == *:* && "$s" == *.* ]]; then
    local head="${s%:*}"
    local tail="${s##*:}"
    __is_ipv4 "$tail" || return 1
    [[ "$head" =~ ^[0-9A-Fa-f:]*$ ]] || return 1
    [[ "$(grep -o "::" <<<"$head" | wc -l)" -le 1 ]] || return 1
    local t="${head//::/:x:}"
    IFS=: read -r -a parts <<<"$t"
    ((${#parts[@]} <= 7)) || return 1   # 7 хекстретов + IPv4-хвост = максимум 8 «квадриков»
    return 0
  fi
  [[ "$s" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
  [[ "$s" == *:* ]] || return 1
  [[ "$(grep -o "::" <<<"$s" | wc -l)" -le 1 ]] || return 1
  local t="${s//::/:x:}"
  IFS=: read -r -a parts <<<"$t"
  ((${#parts[@]} <= 8))
}
__is_ipv6_cidr() {
  [[ "$1" =~ ^(.+)/([0-9]{1,3})$ ]] || return 1
  local ip="${BASH_REMATCH[1]}" m="${BASH_REMATCH[2]}"
  __is_ipv6 "$ip" || return 1
  (( m>=0 && m<=128 ))
}

# RFC-1123 hostname (хотя бы одна точка)
__is_domain() {
  local s="$1"
  [[ "$s" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

# Извлечь голый хост из "urlish"-строки (схема, //, путь — отбрасываются).
__extract_host_from_urlish() {
  local s="$1"
  case "$s" in \"*\") s="${s:1:${#s}-2}";; esac   # снять JSON-кавычки, если есть
  s="${s#http://}"; s="${s#https://}"; s="${s#//}"
  s="${s%%/*}"; printf '%s' "$s"
}

# Разбить строку "a b  c" → JSON-массив ["a","b","c"] (пустые токены выкидываются).
__space_split_to_json_array() {
  local s="$1" toks=() out='[' first=1 t
  case "$s" in \"*\") s="${s:1:${#s}-2}";; esac   # снять JSON-кавычки
  # нормализуем пробелы
  s="$(printf '%s' "$s" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
  read -r -a toks <<<"$s"
  for t in "${toks[@]}"; do
    [[ -z "$t" ]] && continue
    t="${t//\\/\\\\}"; t="${t//\"/\\\"}"
    if (( first )); then out+="\"$t\""; first=0; else out+=",\"$t\""; fi
  done
  out+=']'; printf '%s' "$out"
}

# Фильтры JSON-массивов адресов: оставляют только валидные элементы
# Вход: JSON-массив строк (например, ["1.2.3.4","10.0.0.0/8"])
# Выход: JSON-массив строк (без невалидных токенов)
__filter_ipv4_array() {
  local arr_json="$1"
  local -a _arr=()
  mapfile -t _arr < <(printf '%s' "$arr_json" | yq e -o=json -I=0 '.[]' - 2>/dev/null)
  local out='[' first=1 x s
  for x in "${_arr[@]}"; do
    [[ "$x" == \"*\" ]] || continue
    s="${x:1:${#x}-2}"
    if __is_ipv4 "$s" || __is_ipv4_cidr "$s"; then
      s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
      if (( first )); then out+="\"$s\""; first=0; else out+=",\"$s\""; fi
    fi
  done
  out+=']'; printf '%s' "$out"
}
__filter_ipv6_array() {
  local arr_json="$1"
  local -a _arr=()
  mapfile -t _arr < <(printf '%s' "$arr_json" | yq e -o=json -I=0 '.[]' - 2>/dev/null)
  local out='[' first=1 x s
  for x in "${_arr[@]}"; do
    [[ "$x" == \"*\" ]] || continue
    s="${x:1:${#x}-2}"
    if __is_ipv6 "$s" || __is_ipv6_cidr "$s"; then
      s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
      if (( first )); then out+="\"$s\""; first=0; else out+=",\"$s\""; fi
    fi
  done
  out+=']'; printf '%s' "$out"
}

 # Канонизация allowip.ipv4/ipv6 в settings.yaml:
 #  - строка с адресами → массив
 #  - фильтр валидных токенов
 #  - dedup
 #  - компактный flow-вид массива (читаемо: [1.2.3.4, 5.6.7.8])
 normalize_allowip() {
   local _acq=0
   # Брать лок только если его ещё нет (реентерабельно с ipset/allow_sync)
   if [[ -z "${_SETTINGS_LOCK_FD:-}" && -z "${_SETTINGS_LOCK_MDIR:-}" ]]; then
     _ensure_settings_lock || return 1
     _acq=1
   fi
   _require_prepared || { (( _acq )) && _release_settings_lock; return 110; }
 
   local TMP; TMP="$(mktemp)"
   cp -f "$SETTINGS_YAML" "$TMP"
 
   # IPv4
   local VAI _arr_json _filtered
   VAI="$(__get_json_at "$TMP" '["allowip","ipv4"]')"
   if [[ "${VAI,,}" != '"auto"' && "$VAI" != "null" && "$VAI" != '"__absent__"' ]]; then
     if [[ "$VAI" == \"*\" ]]; then
       _arr_json="$(__space_split_to_json_array "$VAI")"
     elif [[ "$VAI" == \[*\] ]]; then
       _arr_json="$VAI"
     else
       _arr_json="[]"
     fi
     _filtered="$(__filter_ipv4_array "$_arr_json")"
     _yq_apply "$TMP" ".allowip.ipv4 = \$V" "$_filtered"
     yq e -i '.allowip.ipv4 style="flow"' "$TMP" || true
   fi
 
   # IPv6
   VAI="$(__get_json_at "$TMP" '["allowip","ipv6"]')"
   if [[ "${VAI,,}" != '"auto"' && "$VAI" != "null" && "$VAI" != '"__absent__"' ]]; then
     if [[ "$VAI" == \"*\" ]]; then
       _arr_json="$(__space_split_to_json_array "$VAI")"
     elif [[ "$VAI" == \[*\] ]]; then
       _arr_json="$VAI"
     else
       _arr_json="[]"
     fi
     _filtered="$(__filter_ipv6_array "$_arr_json")"
     _yq_apply "$TMP" ".allowip.ipv6 = \$V" "$_filtered"
     yq e -i '.allowip.ipv6 style="flow"' "$TMP" || true
   fi
 
   local _ch=0
   if _write_if_changed "$SETTINGS_YAML" "$TMP" yaml; then _ch=1; fi
   rm -f "$TMP"
   (( _ch == 1 )) && settings_fix_perms || true
   (( _acq )) && _release_settings_lock
   return 0
 }

__is_name32() { [[ "$1" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; }

# == JSON-path utils ==
__pjson_to_dot() { # JSON-массив пути → dot-строка (или уже dot-строка)
  case "$1" in
    \[*\])
      # На вход уже приходит JSON-массив; не парсим строкой, а передаём как argjson.
      jq -nr --argjson P "$1" '$P | map(tostring) | join(".")'
      ;;
    *)
      printf '%s\n' "$1"
      ;;
  esac
}
## ↑ заменяем на явный маркер отсутствия пути (не путать с null)
__get_json_at() {
  local P="$2"
  yq e -o=json -I=0 '.' "$1" \
  | jq -c --argjson P "$P" 'try getpath($P) catch "__absent__" // "__absent__"' 2>/dev/null
}
__type_at()        {
  local P="$2"
  yq e -o=json -I=0 '.' "$1" \
  | jq -r --argjson P "$P" '
      (getpath($P) | type) as $t
      | if   $t=="string"  then "!!str"
        elif $t=="number"  then "!!int"
        elif $t=="boolean" then "!!bool"
        elif $t=="array"   then "!!seq"
        elif $t=="object"  then "!!map"
        else $t end
    ' 2>/dev/null
}

# Пути только по map-ключам (форма файла, без индексов массивов)
__map_value_paths() { # печатает dot-пути ТОЛЬКО по map-ключам
  # YAML → JSON → jq paths → dotted
  yq e -o=json -I=0 '.' "$1" \
  | jq -r 'paths
           | select((.[-1]|type)=="string")
           | join(".")' \
  | LC_ALL=C sort -u
}

# == Dynamic (cosmetic/service) keys we DO NOT validate / diff against ==
#  • cosmetics: dns.ipv4 / dns.ipv6 / dns.dot
#  • service meta: fail2ban.version/updated, adguard_home.version/updated
#  ВАЖНО: dns.port_tls НЕ считается «косметикой» и должен валидироваться,
#  храниться и переноситься как полноценная настройка.
__is_dynamic_key() {
  case "$1" in
    dns.ipv4|dns.ipv6|dns.dot|\
    fail2ban.version|fail2ban.updated|\
    adguard_home.version|adguard_home.updated) return 0 ;;
    *) return 1 ;;
  esac
}

# Утилита для фильтрации путей по динамическим ключам (map-значения по dot-путям)
__filter_out_dynamic() {
  grep -Ev '^(dns\.(ipv4|ipv6|dot)|fail2ban\.(version|updated)|adguard_home\.(version|updated))$'
}

# == Персональная проверка значения по ключу (JSON-представление) ==
# $1=dotkey $2=value_json $3=default_yaml_type (!!str/!!int/!!bool/!!seq/!!map)
__kv_valid() {
  local key="$1" vjson="$2" tdef="$3" s
  # Не переносим отсутствие значения/пустоту
  if [[ "$vjson" == "null" || "$vjson" == '"__absent__"' ]]; then
    return 1
  fi
  case "$vjson" in
    null) s="";;
    \"*\") s="${vjson:1:${#vjson}-2}";;
    *) s="$vjson";;
  esac

  # Автокосметику/служебные поля НЕ переносим — их выставит autofill_settings()
  case "$key" in
    dns.ipv4|dns.ipv6|dns.dot|fail2ban.version|fail2ban.updated|adguard_home.version|adguard_home.updated)
      return 1 ;;
  esac

  # Булевы принимаем «по смыслу»:
  #  • всегда, если схема bool;
  #  • а также для типичных булевых ключей, даже если в шаблоне они строковые.
  if __is_boolish_json "$vjson"; then
    [[ "$tdef" == "!!bool" ]] && return 0
    case "$key" in
      *.enable|routing.flags.*|routing.route_all) return 0 ;;
    esac
  fi

  case "$key" in
    server.port_ssh|dns.port_tls|vpn.ports.split|vpn.ports.full)
      __is_auto_json "$vjson" && return 0
      __is_port "$s"
      ;;
    server.domain)
      __is_auto_json "$vjson" && return 0
      [[ "$tdef" == "!!str" ]] || return 1
      # Принимаем urlish-форму, валидируем уже голый хост
      local host; host="$(__extract_host_from_urlish "$vjson")"
      __is_domain "$host"
      ;;
    server.ipv4)
      __is_auto_json "$vjson" && return 0
      [[ "$tdef" == "!!str" ]] || return 1
      __is_ipv4 "$s"
      ;;
    server.ipv6)
      __is_auto_json "$vjson" && return 0
      [[ "$tdef" == "!!str" ]] || return 1
      __is_ipv6 "$s"
      ;;
    dns.upstream)
      # Строго cloudflare|quad9|google
      local __up="${s,,}"
      if [[ "$__up" == "cloudflare" || "$__up" == "quad9" || "$__up" == "google" ]]; then
        return 0
      else
        return 1
      fi
      ;;
    allowip.ipv4)
      __is_auto_json "$vjson" && return 0
      local _is_array=0
      [[ "$vjson" == \[*\] ]] && _is_array=1
      local -a _arr=()
      if (( _is_array )); then
        mapfile -t _arr < <(printf '%s' "$vjson" | yq e -o=json -I=0 '.[]' - 2>/dev/null)
      else
        [[ "$vjson" == \"*\" ]] || return 1
        # Разрешаем строку адресов через пробелы
        mapfile -t _arr < <(__space_split_to_json_array "$vjson" | yq e -o=json -I=0 '.[]' - 2>/dev/null)
      fi
      local x
      for x in "${_arr[@]}"; do
        [[ "$x" == \"*\" ]] || return 1
        x="${x:1:${#x}-2}"
        __is_ipv4 "$x" || __is_ipv4_cidr "$x" || return 1
      done
      return 0
      ;;
    allowip.ipv6)
      __is_auto_json "$vjson" && return 0
      local _is_array=0
      [[ "$vjson" == \[*\] ]] && _is_array=1
      local -a _arr=()
      if (( _is_array )); then
        mapfile -t _arr < <(printf '%s' "$vjson" | yq e -o=json -I=0 '.[]' - 2>/dev/null)
      else
        [[ "$vjson" == \"*\" ]] || return 1
        mapfile -t _arr < <(__space_split_to_json_array "$vjson" | yq e -o=json -I=0 '.[]' - 2>/dev/null)
      fi
      local x
      for x in "${_arr[@]}"; do
        [[ "$x" == \"*\" ]] || return 1
        x="${x:1:${#x}-2}"
        __is_ipv6 "$x" || __is_ipv6_cidr "$x" || return 1
      done
      return 0
      ;;
    vpn.nets.split|vpn.nets.full|vpn.map_dns)
      __is_auto_json "$vjson" && return 0
      [[ "$tdef" == "!!str" ]] || return 1
      __is_ipv4_cidr "$s"
      ;;
    snat)
      # "auto" ИЛИ массив объектов {name, internal, external}
      __is_auto_json "$vjson" && return 0
      [[ "$vjson" == \[*\] ]] || return 1
      local n i name internal external
      n="$(printf '%s' "$vjson" | yq e 'length' - 2>/dev/null)"
      [[ "$n" =~ ^[0-9]+$ ]] || return 1
      declare -A __seen_names=()
      for ((i=0;i<n;i++)); do
        name="$(printf '%s' "$vjson" | yq e -r ".[$i].name // \"\"" - 2>/dev/null)"
        internal="$(printf '%s' "$vjson" | yq e -r ".[$i].internal // \"\"" - 2>/dev/null)"
        external="$(printf '%s' "$vjson" | yq e -r ".[$i].external // \"\"" - 2>/dev/null)"
        [[ -n "$name" && -n "$internal" && -n "$external" ]] || return 1
        __is_name32 "$name" || return 1
        __is_ipv4 "$internal" || return 1
        { __is_ipv4 "$external" || [[ "$external" == "0.0.0.0" ]]; } || return 1
        [[ -z "${__seen_names[$name]:-}" ]] || return 1
        __seen_names[$name]=1
      done
      return 0
      ;;
    fail2ban.enable|adguard_home.enable)
      __is_boolish_json "$vjson"
      return $?
      ;;
    *)
      # Строгая проверка соответствия типов значению из settings
      case "$tdef" in
        # Контейнеры не переносятся «целиком» при heal — так сохраняем блоковый стиль и комментарии.
        # Исключения (allowip.*, snat) обрабатываются выше отдельными кейсами.
        "!!map")  return 1 ;;
        "!!seq")  return 1 ;;
        "!!str")
          [[ "$vjson" == \"*\"      ]] || return 1 ;;
        "!!int")
          [[ "$vjson" =~ ^-?[0-9]+$ ]] || return 1 ;;
        "!!bool")
          __is_boolish_json "$vjson" || return 1 ;;
        *) return 1 ;;
      esac ;;
  esac
}

# == Полная сборка settings.yaml из шаблона с наложением валидных значений ==
settings_heal() {
  local S="$SETTINGS_YAML" D="$DEFAULTS_YAML"
  [[ -s "$D" ]] || { echo "ERROR: defaults not found: $D" >&2; return 1; }

  # Если настроек нет — просто положим шаблон и выйдем.
  if [[ ! -s "$S" ]]; then
    install -D -m600 "$D" "$S"
    settings_fix_perms || true
    return 0
  fi
  # Если пользовательский YAML битый — сохраним бэкап и соберём чисто по шаблону.
  if ! yq e '.' "$S" >/dev/null 2>&1; then
    cp -f -- "$S" "${S}.broken.$(date +%s)" 2>/dev/null || true
    install -D -m600 "$D" "$S"
    settings_fix_perms || true
    return 0
  fi

  # БАЗА — defaults; поверх него накладываем ТОЛЬКО валидные скаляры из S.
  local DST; DST="$(mktemp)"; cp -f "$D" "$DST"

  # Перечисляем все листья схемы defaults (значения, которые НЕ object/array).
  # ВАЖНО: не использовать `paths(scalars)`, т.к. он пропускает boolean=false
  # (фильтр `scalars` возвращает само значение, а `false` – «ложно» в jq).
  mapfile -t _paths < <(
    yq e -o=json -I=0 '.' "$D" \
    | jq -c 'paths | select((.[-1]|type)=="string")'
  )
  local P key TDEF V VD VOUT CUR
  for P in "${_paths[@]}"; do
    key="$(__pjson_to_dot "$P")"
    __is_dynamic_key "$key" && continue
    TDEF="$(__type_at "$D" "$P")"
    V="$(__get_json_at "$S" "$P")"   # из текущего S
    VD="$(__get_json_at "$D" "$P")"  # дефолт из D

    # Нормализация под ожидаемый тип: строковый int → int
    if [[ "$TDEF" == "!!int" && "$V" =~ ^\"-?[0-9]+\"$ ]]; then
      V="${V:1:${#V}-2}"
    fi

    if __kv_valid "$key" "$V" "$TDEF"; then
      VOUT="$V"
      # Всегда: boolish → строгий JSON-bool
      if __is_boolish_json "$V"; then
        VOUT="$(__to_json_bool "$V")"
      fi
      # server.domain: urlish → голый хост
      if [[ "$key" == "server.domain" && "$V" != null && "$V" != '"__absent__"' && "${V,,}" != '"auto"' ]]; then
        local host; host="$(__extract_host_from_urlish "$V")"
        VOUT="\"$host\""
      fi
    else
      VOUT="$VD"
    fi

    CUR="$(__get_json_at "$DST" "$P")"
    [[ "$CUR" == "$VOUT" ]] && continue
    if [[ "$TDEF" == "!!str" && "$VOUT" =~ ^\".*\"$ ]]; then
      local _plain="${VOUT:1:${#VOUT}-2}"
      _yq_apply "$DST" ".${key} = \$V" "$_plain"
    else
      _yq_apply "$DST" ".${key} = \$V" "$VOUT"
    fi
  done

  local _ch=0
  if _write_if_changed "$S" "$DST" yaml; then _ch=1; fi
  rm -f "$DST"
  (( _ch == 1 )) && settings_fix_perms || true
 
   # Единая канонизация allowip.* поверх уже собранного settings.yaml
   normalize_allowip || true
  return 0
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

# yaml_get_num <key> <default>
#  - 'auto', пусто, null, нечисло → <default>
yaml_get_num() {
  local key="$1" def="${2-0}" v
  v="$(yaml_get "$key" "$def")"
  # снять кавычки и трим
  v="$(printf '%s' "$v" | sed -E 's/^["'\'' ]*//; s/["'\'' ]*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')"
  case "${v,,}" in
    ''|auto|null) echo "$def"; return 0 ;;
  esac
  if [[ "$v" =~ ^[0-9]+$ ]]; then
    echo "$v"
  else
    echo "$def"
  fi
}

# yaml_get_port <key> <default>
#  - как yaml_get_num, но с проверкой диапазона 1..65535
yaml_get_port() {
  local key="$1" def="${2-0}" n
  n="$(yaml_get_num "$key" "$def")"
  if [[ "$n" =~ ^[0-9]+$ ]] && (( n>=1 && n<=65535 )); then
    echo "$n"
  else
    echo "$def"
  fi
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
  raw="$(_yaml_merged 2>/dev/null | yq e -r "${expr} // \"__absent__\"" - || echo '"__absent__"')"
  case "${raw,,}" in
    true|yes|y|1|on|enable|enabled)        echo y ;;
    false|no|n|0|off|disable|disabled)     echo n ;;
    "__absent__")                          echo "$def" ;;
    *)                                     echo "$def" ;;
  esac
}

yaml_allow_all() {
  # null→[], "a b  c"→["a","b","c"], массив «как есть»; dedup делаем в jq.
  # Переводим YAML→JSON через yq, дальше вся логика в jq (устойчиво к многострочным def).
  _yaml_merged \
  | yq e -o=json -I=0 '.' - \
  | jq -r '
      def to_seq(x):
        if x == null then []
        elif (x|type) == "string" then
          x | gsub("[[:space:]]+"; " ")
            | sub("^ "; "")
            | sub(" $"; "")
            | split(" ")
        elif (x|type) == "array" then x
        else [x] end;
      to_seq(.allowip.ipv4) as $A |
      to_seq(.allowip.ipv6) as $B |
      ($A + $B)
        | map(select(. != null and . != "auto"))
        | map(sub("^[[:space:]]+"; "") | sub("[[:space:]]+$"; ""))
        | map(select(. != ""))
        | unique
        | .[]
    ' \
  || true
}

# ── Allow-лист: перенесено из sync.sh (единая реализация) ──────────────────
_yaml_adopt_one() { # $1=allowip.ipv4|allowip.ipv6  $2=cidr
  local key="$1" cidr="$2" TMP; TMP="$(mktemp)"
  cp -f "$SETTINGS_YAML" "$TMP"
  KEY="$key" CIDR="$cidr" \
  yq e -i '
    def p: (env(KEY) | split("."));
    setpath(p; ((getpath(p) // []) + [env(CIDR)]) | unique)
  ' "$TMP" || { rm -f "$TMP"; return 0; }
  _write_if_changed "$SETTINGS_YAML" "$TMP" yaml || true
}

allow_sync_ipsets() {
  command -v ipset >/dev/null 2>&1 || { echo "[INFO] ipset missing; skip allow-sync"; return 0; }
  # Определим, умеет ли ipset поле comment (для старых сборок)
  local _CMT; _CMT="$(_ipset_comment_flag)"
  ipset create ipset-allow  hash:net  family inet  ${_CMT} -exist 2>/dev/null || true
  ipset create ipset-allow6 hash:net  family inet6 ${_CMT} -exist 2>/dev/null || true

  declare -A CUR4 CUR6
  while read -r _a _set _cidr _rest; do
    [[ -n "${_cidr:-}" ]] || continue
    local cmt; cmt="$(sed -n 's/.*comment[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$_rest")"
    CUR4["$_cidr"]="${cmt:-}"
  done < <(ipset save ipset-allow  2>/dev/null | awk '$1=="add"')
  while read -r _a _set _cidr _rest; do
    [[ -n "${_cidr:-}" ]] || continue
    local cmt; cmt="$(sed -n 's/.*comment[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$_rest")"
    CUR6["$_cidr"]="${cmt:-}"
  done < <(ipset save ipset-allow6 2>/dev/null | awk '$1=="add"')

  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    if _ensure_settings_lock; then _acq=1; fi
  fi
  [[ -s "$SETTINGS_YAML" ]] || echo "[INFO] allow-sync: $SETTINGS_YAML missing; YAML adopt skipped" >&2
  for k in "${!CUR4[@]}"; do
    [[ "${CUR4[$k]}" == "src=settings" ]] && continue
    _yaml_adopt_one 'allowip.ipv4' "$k" || true
    ipset del ipset-allow "$k" 2>/dev/null || true
    if [[ -n "$_CMT" ]]; then
      ipset -! add ipset-allow "$k" comment "src=settings"
    else
      ipset -! add ipset-allow "$k"
    fi
  done
  for k in "${!CUR6[@]}"; do
    [[ "${CUR6[$k]}" == "src=settings" ]] && continue
    _yaml_adopt_one 'allowip.ipv6' "$k" || true
    ipset del ipset-allow6 "$k" 2>/dev/null || true
    if [[ -n "$_CMT" ]]; then
      ipset -! add ipset-allow6 "$k" comment "src=settings"
    else
      ipset -! add ipset-allow6 "$k"
    fi
  done
  if (( _acq )); then _release_settings_lock; fi

  # Классифицируем без регэкспов: пробуем добавить адрес в наборы разных семейств.
  # Всё валидирует сам ipset; сжатые IPv6-формы обрабатываются корректно.
  local SUF="__$$_$RANDOM"
  local V4TMP="ipset-validate4${SUF}" V6TMP="ipset-validate6${SUF}"
  ipset create "$V4TMP" hash:net family inet  ${_CMT} -exist 2>/dev/null || true
  ipset create "$V6TMP" hash:net family inet6 ${_CMT} -exist 2>/dev/null || true

  declare -A SEEN4 SEEN6
  while IFS= read -r x; do
    [[ -z "$x" ]] && continue
    if ipset add "$V4TMP" "$x" 2>/dev/null; then
      SEEN4["$x"]=1
      [[ "${CUR4[$x]:-}" == "src=settings" ]] || {
        ipset del ipset-allow "$x" 2>/dev/null || true
        if [[ -n "$_CMT" ]]; then
          ipset -! add ipset-allow "$x" comment "src=settings"
        else
          ipset -! add ipset-allow "$x"
        fi
      }
      continue
    fi
    if ipset add "$V6TMP" "$x" 2>/dev/null; then
      SEEN6["$x"]=1
      [[ "${CUR6[$x]:-}" == "src=settings" ]] || {
        ipset del ipset-allow6 "$x" 2>/dev/null || true
        if [[ -n "$_CMT" ]]; then
          ipset -! add ipset-allow6 "$x" comment "src=settings"
        else
          ipset -! add ipset-allow6 "$x"
        fi
      }
      continue
    fi
    # иначе — мусор/неподдерживаемый формат: тихо игнорируем
  done < <(yaml_allow_all || true)

  ipset destroy "$V4TMP" 2>/dev/null || true
  ipset destroy "$V6TMP" 2>/dev/null || true
  for k in "${!CUR4[@]}"; do
    [[ "${CUR4[$k]}" == "src=settings" && -z "${SEEN4[$k]:-}" ]] && ipset del ipset-allow "$k" 2>/dev/null || true
  done
  for k in "${!CUR6[@]}"; do
    [[ "${CUR6[$k]}" == "src=settings" && -z "${SEEN6[$k]:-}" ]] && ipset del ipset-allow6 "$k" 2>/dev/null || true
  done
 
   # Приводим allowip.* к единому виду после «усыновления» адресов из ipset
   normalize_allowip || true
}

# -------- Внешний интерфейс и IP-адреса (централизовано) --------------------
# Кэшируем, чтобы не ждать повторно при многократных вызовах
SERVER_IP4=""; SERVER_IP6=""
# Необязательный helper на случай использования через `source`
server_ip_cache_reset(){ SERVER_IP4=""; SERVER_IP6=""; }

# Внешний IPv4: явный из settings.server.ipv4, иначе — ждём появления на iface.
# Аргумент: timeout ожидания (сек), по умолчанию 30. Возвращает '0.0.0.0' при неудаче.
server_ip4() {
  local wait=${1:-30}
  [[ -n "$SERVER_IP4" && "$SERVER_IP4" != "0.0.0.0" ]] && { echo "$SERVER_IP4"; return 0; }
  local cfg; cfg="$(yaml_get_ip 'server.ipv4' '0.0.0.0')"
  if [[ "$cfg" != "0.0.0.0" ]]; then
    SERVER_IP4="$cfg"
  else
    # уважать фактический таймаут ожидания
    local ifc; ifc="$(_primary_iface "$wait")"
    if (( wait > 0 )); then
      SERVER_IP4="$(wait_ip "$ifc" "$wait" 4 || echo '')"
    fi
    [[ -z "$SERVER_IP4" ]] && SERVER_IP4="0.0.0.0"
  fi
  echo "$SERVER_IP4"
}

# v6-ориентированный выбор интерфейса: сначала default v6, затем наличие глобального v6
_primary_iface_v6() {
  local timeout=${1:-30} ifc=""
  for ((i=0; i<timeout; i++)); do
    ifc="$(ip -o -6 route show to default 2>/dev/null | awk '{print $5; exit}')"
    [[ -n "$ifc" ]] && break
    sleep 1
  done
  [[ -z $ifc ]] && ifc="$(ip -o -6 addr show scope global 2>/dev/null | awk '{print $2; exit}')"
  [[ -z $ifc ]] && ifc="$(_primary_iface "$timeout")"
  printf '%s' "${ifc%%@*}"
}

# Публичная обёртка для v6-ориентированного выбора интерфейса.
# Без ожидания по умолчанию.
server_iface_v6() { _primary_iface_v6 "${1:-0}"; }

# Внешний IPv6: аналогично IPv4. Возвращает '::' при неудаче.
server_ip6() {
  local wait=${1:-30}
  [[ -n "$SERVER_IP6" && "$SERVER_IP6" != "::" ]] && { echo "$SERVER_IP6"; return 0; }
  local cfg; cfg="$(yaml_get_ip 'server.ipv6' '::')"
  if [[ "$cfg" != "::" ]]; then
    SERVER_IP6="$cfg"
  else
    # подбирать iface с учётом v6-маршрута/адресов
    local ifc; ifc="$(_primary_iface_v6 "$wait")"
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

# Endpoint host (IPv4-only): домен → IPv4; без IPv6.
# Арг.: timeout ожидания IPv4 (сек). Если домен задан — IPv4 не обязателен.
# Печатает хост и возвращает 0; иначе код 1.
endpoint_host() {
  local wait=${1:-30}
  local d i4
  d="$(server_domain)"
  if [[ -n "$d" ]]; then
    printf '%s' "$d"
    return 0
  fi
  i4="$(server_ip4 "$wait")"
  if [[ "$i4" != "0.0.0.0" ]]; then
    printf '%s' "$i4"
    return 0
  fi
  return 1
}

# ── yaml_set <key> <value> ────────────────────────────────────────────────
# Записывает (или обновляет) скаляр в settings.yaml.
# • Ключ — в dot-нотации (пример: filters.discord).
# • Значение передаётся как есть: true/false/строка/число.
yaml_set() {
  local key="$1" val="${2-}"
  [[ -z "$key" ]] && { echo "yaml_set: key is empty" >&2; return 1; }
 # Спец-маркеры: __empty__ → "", __null__ → null
 case "$val" in
   "")         [[ -n "${VERBOSE_SETTINGS:-}" ]] && echo "yaml_set: empty value for '$key' – skip" >&2; return 0 ;;
   '""')       val='""' ;;   # позволяем передавать пустую строку как два символа кавычек
   __empty__)  val='""'  ;;
   __null__)   val='null' ;;
 esac

  _require_prepared || return $?
  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi

  local TMP; TMP="$(mktemp)"
  cp -f "$SETTINGS_YAML" "$TMP"
  # Для устойчивости к многострочным значениям используем load() из временного файла.
  local VALTMP; VALTMP="$(mktemp)" || { rm -f "$TMP"; (( _acq )) && _release_settings_lock; return 1; }
  printf '%s' "$val" >"$VALTMP"
  KEY="$key" VALFILE="$VALTMP" \
    yq e -i 'setpath(
               (env(KEY) | split("."));
               (load(env(VALFILE)))
             )' \
      "$TMP" \
      || { rm -f "$TMP" "$VALTMP"; (( _acq )) && _release_settings_lock; return 1; }
  rm -f "$VALTMP"
  local _ch=0
  if _write_if_changed "$SETTINGS_YAML" "$TMP" yaml; then _ch=1; fi
  (( _ch == 1 )) && settings_fix_perms || true
  (( _acq )) && _release_settings_lock
  return 0
}

# Удобные обёртки для записи булевых и строковых значений в settings.yaml
#  • yaml_set_bool KEY y|n        → true/false
#  • yaml_set_str  KEY "value"    → безопасно экранирует кавычки
yaml_set_bool() {
  local key="$1" yn="${2:-n}"
  case "${yn,,}" in
    y|yes|true|1|on|enable|enabled)  yaml_set "$key" "true"  ;;
    n|no|false|0|off|disable|disabled|"") yaml_set "$key" "false" ;;
    *) yaml_set "$key" "$yn" ;;  # на случай, если передали уже true/false
  esac
}
yaml_set_str() {
  local key="$1" v="${2-}"
  # Экранируем обратные слеши, кавычки и переводы строк
  v="${v//\\/\\\\}"
  v="${v//\"/\\\"}"
  v="${v//$'\n'/\\n}"
  yaml_set "$key" "\"$v\""
}

# Единый резолвер профиля апстрима: всё берём из dns.upstream; порт — из dns.port_tls.
__upstream_resolve() {
  local up
  up="$(yaml_get 'dns.upstream' cloudflare | tr '[:upper:]' '[:lower:]')"
  case "$up" in
    quad9)
      UP_IPV4A='9.9.9.10';             UP_IPV4B='149.112.112.10'
      UP_IPV6A='2620:fe::10';          UP_IPV6B='2620:fe::fe:10'
      UP_DOT='tls://dns10.quad9.net'
      ;;
    google)
      UP_IPV4A='8.8.8.8';              UP_IPV4B='8.8.4.4'
      UP_IPV6A='2001:4860:4860::8888'; UP_IPV6B='2001:4860:4860::8844'
      UP_DOT='tls://dns.google'
      ;;
    *)
      # cloudflare (по умолчанию)
      UP_IPV4A='1.1.1.1';              UP_IPV4B='1.0.0.1'
      UP_IPV6A='2606:4700:4700::1111'; UP_IPV6B='2606:4700:4700::1001'
      UP_DOT='tls://one.one.one.one'
      ;;
  esac
}

# Квадра апстрима (ipv4a ipv4b ipv6a ipv6b) — строго из dns.upstream
yaml_bootstrap() {
  __upstream_resolve
  printf '%s\n' "$UP_IPV4A" "$UP_IPV4B" "$UP_IPV6A" "$UP_IPV6B" | tr -d $'\r'
}

# DoT URL и порт TLS: URL — из dns.upstream; порт — из dns.port_tls (auto/мусор → дефолт 853).
yaml_dot() {
  __upstream_resolve
  # Порт нормализуем независимо от __upstream_resolve, чтобы 'auto' не «протёк»
  local port; port="$(yaml_get_port 'dns.port_tls' 853)"
  printf '%s\t%s\n' "$UP_DOT" "$port"
}

## ────────────────────────────────────────────────────────────────────────────
## SSH / Fail2ban: helpers для применения server.port_ssh
## ────────────────────────────────────────────────────────────────────────────
sshd_set_port() {
  local newp; newp="$(yaml_get_port 'server.port_ssh' 22)"
  local cfg=/etc/ssh/sshd_config tmp
  [[ -f "$cfg" ]] || { echo "[WARN] $cfg not found; skip sshd port update"; return 0; }
  tmp="$(mktemp)"
  # Заменяем первую активную строку Port ... на новый порт; остальные активные Port — удаляем.
  awk -v P="$newp" '
    BEGIN{done=0}
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*Port[[:space:]]+/ {
      if(!done){ sub(/^[[:space:]]*Port[[:space:]]+.*/, "Port " P); print; done=1 }
      next
    }
    { print }
    END {
      if(!done){ print "Port " P }
    }
  ' "$cfg" >"$tmp"
  local _ch=0
  if _write_if_changed "$cfg" "$tmp"; then _ch=1; fi
  _root0600 "$cfg"
  SSHD_PORT_CHANGED=$_ch
  # SELinux: разрешить новый порт для sshd, если SELinux включён и есть semanage
  if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v semanage >/dev/null 2>&1; then
    local oldps; oldps="$(semanage port -l 2>/dev/null \
                           | awk '$1=="ssh_port_t" && $2=="tcp"{for(i=4;i<=NF;i++)print $i}' \
                           | tr ',' '\n' | tr -d ' ')"
    grep -qx "$newp" <<<"$oldps" \
      || semanage port -a -t ssh_port_t -p tcp "$newp" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$newp" 2>/dev/null || true
    # Опционально: убрать старые разрешённые tcp-порты ssh_port_t (кроме нового и 22)
    while IFS= read -r p; do
      [[ -z "$p" || "$p" == "$newp" || "$p" == "22" ]] && continue
      semanage port -d -t ssh_port_t -p tcp "$p" 2>/dev/null || true
    done <<<"$oldps"
  fi
  # Перезапуск перенесён в очередь действий (need svc:sshd.reload)
}

_update_f2b_port() {
  local jail=/etc/fail2ban/jail.local
  local newp; newp="$(yaml_get_port 'server.port_ssh' 22)"
  install -d -m 755 /etc/fail2ban 2>/dev/null || true
  [[ -f "$jail" ]] || { echo "[WARN] $jail not found; skip updating sshd jail port"; return 0; }

  local tmp; tmp="$(mktemp)"
  awk -v PORTV="$newp" '
    BEGIN { insshd=0; wrote=0; seen=0 }
    /^[[:space:]]*\[sshd\][[:space:]]*(#.*)?$/ {
      print; insshd=1; wrote=0; seen=1; next
    }
    /^[[:space:]]*\[[^]]+\][[:space:]]*(#.*)?$/ {
      if (insshd && !wrote) { print "port = " PORTV }
      insshd=0; wrote=0; print; next
    }
    {
      if (insshd && $0 ~ /^[[:space:]]*port[[:space:]]*=/) {
        print "port = " PORTV; wrote=1; next
      }
      print
    }
    END {
      if (insshd && !wrote) { print "port = " PORTV }
      if (!seen) { print ""; print "[sshd]"; print "port = " PORTV }
    }
  ' "$jail" >"$tmp"

  local _ch=0
  if _write_if_changed "$jail" "$tmp"; then _ch=1; fi
  _root0644 "$jail"
  F2B_PORT_CHANGED=$_ch
  return 0
}

#──────────────────────────────────────────────────────────────────────────────
# SNAT helpers — создание / удаление правил при добавлении / удалении клиента
#──────────────────────────────────────────────────────────────────────────────
# add_snat <ip> <name>
add_snat() {
  local ip="$1" name="$2"
  [[ -z "$ip" || -z "$name" ]] && return 0
  _have yq || return 0
  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi
  _require_prepared || { (( _acq )) && _release_settings_lock; return 110; }
  local TMP; TMP="$(mktemp)"
  cp -f "$SETTINGS_YAML" "$TMP"
  SNAT_IP="$ip" SNAT_NAME="$name" \
  yq e -i '
    .snat = (.snat // []) |
    .snat |= (
      map(select(.internal != env(SNAT_IP) and .name != env(SNAT_NAME)))
      + [{
          "name":     env(SNAT_NAME),
          "internal": env(SNAT_IP),
          "external": "0.0.0.0"
        }]
    )
  ' "$TMP"
  local _ch=0
  if _write_if_changed "$SETTINGS_YAML" "$TMP" yaml; then _ch=1; fi
  (( _ch == 1 )) && settings_fix_perms || true
  if (( _acq )); then _release_settings_lock; fi
  return 0
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
  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi
 
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
  cp -f "$agh" "$TMP"
  CLIENT_IP="$ip" AGH_NICK="$nick" UPSTREAM_HOST="$UPSTREAM_HOST" AGH_UUID="$AGH_UUID" \
  yq e -i '
    .clients.persistent = (.clients.persistent // []) |
    .clients.persistent =
      (
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
  ' "$TMP"
  local _changed=0
  if _write_if_changed "$agh" "$TMP" yaml; then _changed=1; fi
  if [[ $_changed -eq 1 ]]; then
    agh_fix_perms "$agh"
    # Перед systemctl — отпускаем лок ТОЛЬКО если брали здесь
    if (( _acq )); then _release_settings_lock; _acq=0; fi
    if [[ "${ADD_NO_RESTART:-0}" != 1 ]]; then
      _settings__svc try-reload-or-restart AdGuardHome.service >/dev/null 2>&1 || true
    fi
  fi
  if (( _acq )); then _release_settings_lock; fi
  return 0
}

remove_agh_client() {
  local nick="$1" agh="${AGH_DIR}/AdGuardHome.yaml"
  [[ -f "$agh" && -n "$nick" ]] || return 0
  _have yq || { echo "[WARN] yq not found, skip AdGuardHome client removal"; return 0; }
  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi

  local TMP; TMP="$(mktemp)"
  cp -f "$agh" "$TMP"
  if ! AGH_NICK="$nick" yq e -i '
    .clients.persistent = (
      (.clients.persistent // []) | map(select(.name != env(AGH_NICK)))
    )
  ' "$TMP"; then
    echo "[WARN] yq failed, skip AdGuardHome client removal" >&2
    rm -f "$TMP"
    if (( _acq )); then _release_settings_lock; fi
    return 0
  fi

  if _write_if_changed "$agh" "$TMP" yaml; then
    agh_fix_perms "$agh"
    if (( _acq )); then _release_settings_lock; _acq=0; fi
    if [[ "${ADD_NO_RESTART:-0}" != 1 ]]; then
      _settings__svc try-reload-or-restart AdGuardHome.service >/dev/null 2>&1 || true
    fi
  fi
 if (( _acq )); then _release_settings_lock; fi
 return 0
}

# remove_snat <name>
remove_snat() {
  local name="$1"
  [[ -z "$name" ]] && return 0
  _have yq || return 0
  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi
  _require_prepared || { (( _acq )) && _release_settings_lock; return 110; }
  local TMP; TMP="$(mktemp)"
  cp -f "$SETTINGS_YAML" "$TMP"
  NAME="$name" \
  yq e -i '
    .snat = (
      (.snat // []) | map(select(.name != env(NAME)))
    )
  ' "$TMP"
  local _ch=0
  if _write_if_changed "$SETTINGS_YAML" "$TMP" yaml; then _ch=1; fi
  (( _ch == 1 )) && settings_fix_perms || true
  if (( _acq )); then _release_settings_lock; fi
  return 0
}

###############################################################################
# АВТО-ЗАПОЛНЕНИЕ settings.yaml
###############################################################################

# Обновить «косметические» поля в settings.yaml по dns.upstream:
#   • .dns.ipv4 / .dns.ipv6 — человекочитаемые строки вида "up://A | B"
#   • .dns.dot              — URL DoT (tls://…) для @1
# ПРИМЕЧАНИЕ: dns.port_tls НЕ трогаем (это не «косметика»).
update_dns_ips() {
  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi
  _require_prepared || { (( _acq )) && _release_settings_lock; return 110; }
  local ips=(); mapfile -t ips < <(yaml_bootstrap)   # 0-3: ipv4a ipv4b ipv6a ipv6b
  local ipv4a=${ips[0]} ipv4b=${ips[1]} ipv6a=${ips[2]} ipv6b=${ips[3]}
  local DOT_URL _DOT_PORT_IGN
  read -r DOT_URL _DOT_PORT_IGN < <(yaml_dot)

  # Собираем косметические строки: "up://A | B" (второй может отсутствовать)
  local IPV4_STR=""; local IPV6_STR=""
  if [[ -n "$ipv4a" || -n "$ipv4b" ]]; then
    local _v4=(); [[ -n "$ipv4a" ]] && _v4+=("up://$ipv4a"); [[ -n "$ipv4b" ]] && _v4+=("$ipv4b")
    IPV4_STR="${_v4[0]:-}"
    if ((${#_v4[@]} > 1)); then IPV4_STR+=" | ${_v4[1]}"; fi
  fi
  if [[ -n "$ipv6a" || -n "$ipv6b" ]]; then
    local _v6=(); [[ -n "$ipv6a" ]] && _v6+=("up://$ipv6a"); [[ -n "$ipv6b" ]] && _v6+=("$ipv6b")
    IPV6_STR="${_v6[0]:-}"
    if ((${#_v6[@]} > 1)); then IPV6_STR+=" | ${_v6[1]}"; fi
  fi

  # Редактируем копию файла IN-PLACE, чтобы не терять комментарии из дефолта
  local TMP; TMP="$(mktemp)"
  cp -f "$SETTINGS_YAML" "$TMP"
  IPV4_STR="$IPV4_STR" IPV6_STR="$IPV6_STR" DOT_URL="$DOT_URL" \
  yq e -i '
      .dns.ipv4     = env(IPV4_STR) |
      .dns.ipv6     = env(IPV6_STR) |
      .dns.dot      = env(DOT_URL)
  ' "$TMP"
  local _ch=0
  if _write_if_changed "$SETTINGS_YAML" "$TMP" yaml; then _ch=1; fi
  (( _ch == 1 )) && settings_fix_perms || true
  (( _acq )) && _release_settings_lock
  DNS_IPS_CHANGED=$_ch
  return 0
}

# Детекторы текущих версий сервисов (best-effort). Возвращают ПУСТО, если не нашли.
_detect_ver_fail2ban() {
  local v=""
  if _have fail2ban-server; then
    v="$({ fail2ban-server -V 2>/dev/null || true; } | head -n1 | grep -Eo 'v?[0-9]+([.-][0-9A-Za-z]+)*' || true)"
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
    if _have strings; then
      if out=$(strings "$bin" 2>/dev/null | grep -Eom1 'v?[0-9]+\.[0-9]+(\.[0-9A-Za-z.-]+)?'); then
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
  local svc="$1" new="$2" cur today _acq=0
  [[ -s "$SETTINGS_YAML" ]] || return 0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi
  [[ -z "$new" ]] && { (( _acq )) && _release_settings_lock; return 0; }
  [[ "$new" =~ ^v ]] || new="v${new}"
  cur=$(yq e -r ".${svc}.version // \"\"" "$SETTINGS_YAML")
  if [[ "$cur" == "$new" ]]; then
    (( _acq )) && _release_settings_lock
    return 0
  fi
  today="$(_today)"
  local TMP; TMP="$(mktemp)"
  cp -f "$SETTINGS_YAML" "$TMP"
  SVC="$svc" VER="$new" UPD="$today" \
  yq e -i '
    .[env(SVC)].version = env(VER) |
    .[env(SVC)].updated = env(UPD)
  ' "$TMP"
  local _ch=0
  if _write_if_changed "$SETTINGS_YAML" "$TMP" yaml; then _ch=1; fi
  (( _ch == 1 )) && settings_fix_perms || true
  if (( _acq )); then _release_settings_lock; fi
  # не отдаём «1» наружу при _acq==0 под set -e
  return 0
}

# Единая точка автозаполнения (можно дергать вручную ключом --autofill)
autofill_settings() {
  update_dns_ips
  bump_service_ver fail2ban     "$(_detect_ver_fail2ban)"
  bump_service_ver adguard_home "$(_detect_ver_agh)"
}

# ── ЕДИНЫЙ рендер системных DNS-файлов (без `resolv.conf`, без рестартов) ──
# Делает только косметику в `/etc/network/interfaces`:
#   • всегда держит строки `dns-nameservers` закомментированными;
#   • подставляет актуальные upstream-адреса (видно в файле, но не активно).
_update_system_upstream() {
  # читаем 4 адреса (2×IPv4 + 2×IPv6) построчно
  local _dns=() DNS4_1 DNS4_2 DNS6_1 DNS6_2
  readarray -t _dns < <(yaml_bootstrap)
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
          match($0, /^[[:space:]]*/); indent=substr($0, RSTART, RLENGTH)
          print indent "# dns-nameservers " join2(v4a,v4b)
          in4=0; next
      }
      in4 && (/^iface[[:space:]]/ || /^$/) { in4=0 }   # выход из стэнзы

      # <ifname> / IPv6
      $0 ~ "^iface[[:space:]]+" ifname "[[:space:]]+inet6[[:space:]]+static([[:space:]]*(#.*)*)?$"{
          print; in6=1; next
      }
      in6 && /^[[:space:]]*#?[[:space:]]*dns-nameservers[[:space:]]*/{
          match($0, /^[[:space:]]*/); indent=substr($0, RSTART, RLENGTH)
          if(has6=="y"){ print indent "# dns-nameservers " join2(v6a,v6b) } else print
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
  local cidr="$1" ip mask a b c d ip_i mask_i net first o
  # Базовая валидация: A.B.C.D/M
  [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]{1,2}$ ]] || return 1
  ip=${cidr%/*}; mask=${cidr#*/}
  IFS='.' read -r a b c d <<<"$ip" || return 1
  (( mask >= 0 && mask <= 32 )) || return 1
  for o in "$a" "$b" "$c" "$d"; do
    [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || return 1
  done
  ip_i=$(( (a<<24) | (b<<16) | (c<<8) | d ))
  mask_i=$(( mask==0 ? 0 : ((0xFFFFFFFF << (32-mask)) & 0xFFFFFFFF) ))
  net=$(( ip_i & mask_i ))
  first=$(( mask >= 31 ? net : net + 1 ))
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
    [[ "${svpn%/*}" =~ ^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$ ]] || return 1
    SVPN_IP="${svpn%/*}"
  else
    SVPN_IP="$(ipv4_host "$svpn")" || return 1
  fi
  if [[ "$m2" =~ ^[0-9]+$ ]] && (( m2 >= 31 )); then
    [[ "${fvpn%/*}" =~ ^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$ ]] || return 1
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
  # Собираем allow-лист с «тихой» устойчивостью:
  #   базовые → IPv4 (лексикографически) → IPv6 (лексикографически), с дедупликацией
  local -a V4=() V6=()
  while IFS= read -r _x; do
    [[ -z "${_x//[[:space:]]/}" ]] && continue
    _x="$(printf '%s' "$_x" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    [[ -z "$_x" ]] && continue
    # жёсткая валидация перед добавлением
    if [[ "$_x" == *:* ]]; then
      if __is_ipv6 "$_x" || __is_ipv6_cidr "$_x"; then V6+=("$_x"); fi
    else
      if __is_ipv4 "$_x" || __is_ipv4_cidr "$_x"; then V4+=("$_x"); fi
    fi
  done < <(yaml_allow_all || true)
  local v4s="" v6s=""
  ((${#V4[@]})) && v4s="$(printf '%s\n' "${V4[@]}" | LC_ALL=C sort -u | tr '\n' ' ')"
  ((${#V6[@]})) && v6s="$(printf '%s\n' "${V6[@]}" | LC_ALL=C sort -u | tr '\n' ' ')"
  # Склеиваем и убираем дубли, сохраняя первое вхождение (база остаётся первой)
  local _words
  _words="$(
    { printf '%s\n' "127.0.0.0/8" "::1"; printf '%s' "${v4s:-} ${v6s:-}" | tr ' ' '\n'; } \
    | awk 'NF' | awk '!seen[$0]++'
  )"
  local line
  line="ignoreip = $(printf '%s\n' "${_words}" | paste -sd' ' -)"

  # если файла/каталога нет — создадим
  install -d -m 755 /etc/fail2ban 2>/dev/null || true
  if [[ ! -f "$jail" ]]; then
    echo "[WARN] $jail not found; skip updating (setup must place it from repo)" >&2
    return 0
  fi

  if ! grep -Eq '^[[:space:]]*\[DEFAULT\]' "$jail" 2>/dev/null; then
    # нет секции — добавляем в конец
    local tmp; tmp="$(mktemp)"
    { cat "$jail"; printf '\n[DEFAULT]\n%s\n' "$line"; } >"$tmp"
    local _ch=0
    if _write_if_changed "$jail" "$tmp"; then _ch=1; fi
    _root0644 "$jail"
    F2B_IGNOREIP_CHANGED=$_ch
    return 0
  fi

  # есть секция DEFAULT: проверим, есть ли в ней ignoreip
  if awk '
      /^[[:space:]]*\[DEFAULT\][[:space:]]*(#.*)?$/{inblk=1; next}  # начали секцию
      /^[[:space:]]*\[[^]]+\][[:space:]]*(#.*)?$/ { inblk=0 }         # любой новый заголовок — выходим
      inblk && /^[[:space:]]*ignoreip[[:space:]]*=/ {found=1}
      END{ exit(found?0:1) }
    ' "$jail"; then
    # заменить только внутри DEFAULT
    local tmp; tmp="$(mktemp)"
    awk -v LINE="$line" '
      /^[[:space:]]*\[DEFAULT\][[:space:]]*(#.*)?$/{print; inblk=1; next}
      /^[[:space:]]*\[[^]]+\][[:space:]]*(#.*)?$/ { if (inblk){ inblk=0 } }
      {
        if (inblk && $0 ~ /^[[:space:]]*ignoreip[[:space:]]*=/) {
          if (!replaced) { print LINE; replaced=1 }
          next
        }
        print }
    ' "$jail" >"$tmp"
    local _ch=0; if _write_if_changed "$jail" "$tmp"; then _ch=1; fi
    _root0644 "$jail"; F2B_IGNOREIP_CHANGED=$_ch
  else
    # вставить сразу после заголовка DEFAULT
    local tmp; tmp="$(mktemp)"
    awk -v LINE="$line" '
      /^[[:space:]]*\[DEFAULT\][[:space:]]*(#.*)?$/{print; print LINE; inserted=1; next}
      { print }
      END{
        if(!inserted){
          print "[DEFAULT]"
          print LINE
        }
      }
    ' "$jail" >"$tmp"
    local _ch=0; if _write_if_changed "$jail" "$tmp"; then _ch=1; fi
    _root0644 "$jail"; F2B_IGNOREIP_CHANGED=$_ch
  fi
}

agh_heal() {
  local AGH_YAML="${AGH_DIR}/AdGuardHome.yaml"
  mkdir -p "${AGH_DIR}"
  # инструменты, без которых merge невозможен
  _have yq || { echo "ERROR: yq not found" >&2; return 1; }
  [[ -s "$AGH_TMPL_BASE" ]]  || { echo "ERROR: AGH base template missing: $AGH_TMPL_BASE"  >&2; return 1; }
  [[ -s "$AGH_TMPL_PATCH" ]] || { echo "ERROR: AGH patch template missing: $AGH_TMPL_PATCH" >&2; return 1; }
  # Если lock не был взят ранее, берём его здесь и отпускаем вручную в конце
  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi

  # ── 1. собираем переменные из settings.yaml ─────────────────────
  local SVPN_NET4 FVPN_NET4 ipv4a ipv4b ipv6a ipv6b _quad=()
  SVPN_NET4=$(yaml_get 'vpn.nets.split' 10.29.8.0/24)
  FVPN_NET4=$(yaml_get 'vpn.nets.full'  10.28.8.0/24)
  # читаем 4 адреса построчно (read читает только одну строку; нужен readarray)
  readarray -t _quad < <(yaml_bootstrap)
  ipv4a="${_quad[0]}"; ipv4b="${_quad[1]}"; ipv6a="${_quad[2]}"; ipv6b="${_quad[3]}"
  if ! vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4"; then
    (( _acq )) && _release_settings_lock
    return 1
  fi

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

  # ── адрес GUI и bind_hosts — локальные значения по умолчанию ─
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
    # переменные, которые подставляются в adguardhome_patch.yaml
    export SVPN_IP FVPN_IP SVPN_NET4 FVPN_NET4
    export ipv4a ipv4b ipv6a ipv6b
    export ALLOW_BLOCK="$ALLOW_BLOCK"
    export GUI_ADDR BIND_BLOCK
    export KRESD1_IP KRESD2_IP KRESD3_IP KRESD4_IP PROXY_IP AGH_IP DNS_PORT
    _render "$AGH_TMPL_PATCH"
  } >"$PTMP" || { echo "ERROR: render of AGH patch failed" >&2; rm -f "$PTMP"; (( _acq )) && _release_settings_lock; return 1; }

  # ── 3. merge → GEN_TMP, запись только при изменении ─────────────────
  # 3. Сначала готовим MERGE (без комментариев): base * patch * existing?
  local MERGE_TMP; MERGE_TMP="$(mktemp)"
  # безопасная подстановка документов: невалидные → {}
  safe_doc(){ local f="$1"; yq e '.' "$f" >/dev/null 2>&1 && cat "$f" || echo "{}"; }
  yq ea -P '. as $item ireduce ({}; . * $item)' \
    <(safe_doc "$AGH_TMPL_BASE") \
    <(safe_doc "$PTMP") \
    <(safe_doc "$AGH_YAML") >"$MERGE_TMP"
  rm -f "$PTMP"

  # 5. Комментарии: перенос значений из MERGE поверх копии base (in-place)
  local GEN_TMP; GEN_TMP="$(mktemp)"; cp -f "$AGH_TMPL_BASE" "$GEN_TMP"
  # Собираем пути-листья из MERGE_TMP
  # Пути до «листьев» (всё, что не объект) — в JSON-массивной форме
  mapfile -t _paths_merge < <(
    yq e -o=json -I=0 '.' "$MERGE_TMP" \
    | jq -c 'paths | select((.[-1]|type)=="string")' 2>/dev/null || true
  )
  if ((${#_paths_merge[@]})); then
    local PJSON VAL
    for PJSON in "${_paths_merge[@]}"; do
      # значение из MERGE_TMP по этому пути (через helper на jq)
      VAL="$(__get_json_at "$MERGE_TMP" "$PJSON" 2>/dev/null || echo 'null')"
      # null пропускаем на стороне Bash — без if/then в yq (устойчиво для v4)
      [[ "$VAL" == "null" ]] && continue
      # Безопасная подстановка через временные файлы: load(env(...)) устраняет "Error: EOF" в yq v4
      local _pf _vf
      _pf="$(mktemp)" || { echo "mktemp failed for path" >&2; continue; }
      _vf="$(mktemp)" || { rm -f -- "$_pf"; echo "mktemp failed for value" >&2; continue; }
      printf '%s' "$PJSON" >"$_pf"
      printf '%s' "$VAL"   >"$_vf"
      P_FILE="$_pf" V_FILE="$_vf" \
        yq e -i 'setpath((load(env(P_FILE))); (load(env(V_FILE))))' "$GEN_TMP" || true
      rm -f -- "$_pf" "$_vf"
    done
  fi
  rm -f "$MERGE_TMP"

  # убрать пустые элементы из списков DNS (на случай неполных подстановок)
  yq e -i '
    .dns.upstream_dns = (
      (.dns.upstream_dns
        | ([(. // [])] | flatten)
        | map(select(. != null and . != ""))
        | unique
      )
    ) |
    .dns.bootstrap_dns = (
      (.dns.bootstrap_dns
        | ([(. // [])] | flatten)
        | map(select(. != null and . != ""))
        | unique
      )
    ) |
    .dns.fallback_dns = (
      (.dns.fallback_dns
        | ([(. // [])] | flatten)
        | map(select(. != null and . != ""))
        | unique
      )
    ) |
    .dns.bind_hosts = (
      (.dns.bind_hosts
        | ([(. // [])] | flatten)
        | map(select(. != null and . != ""))
        | unique
      )
    )
  ' "$GEN_TMP"

  _write_if_changed "$AGH_YAML" "$GEN_TMP" yaml || true
  # ВНЕ зависимости от изменений — привести права YAML+логов
  agh_fix_perms "$AGH_YAML"
  if (( _acq )); then _release_settings_lock; fi
  # завершаем успешно, иначе _with_lock увидит «1»
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────
# Kresd: автогенерация upstream_dns.lua + правка прав lua/RPZ
#   ipv4/ipv6   — IP-адреса апстримов
#   dot/port_tls — DoT URL и порт TLS (использует kresd@1)
# Роли:
#   @1 — DoT hub (FORWARD TLS to provider, v4+v6)
#   @2 — System validating → @1
#   @3 — SPLIT (IPv4-only, lists) → @1
#   @4 — FULL  (IPv4-only) → @1
kresd_heal() {
  local _changed=0
  # Читаем «квадру» апстримов: ipv4a ipv4b ipv6a ipv6b
  local _acq=0
  if [[ -z "${_SETTINGS_LOCK_FD:-}" ]]; then
    _ensure_settings_lock || return 1
    _acq=1
  fi
  local ips=()
  readarray -t ips < <(yaml_bootstrap)   # 0-3
  local ipv4a="${ips[0]}" ipv4b="${ips[1]}" ipv6a="${ips[2]}" ipv6b="${ips[3]}"
  local DOT_URL DOT_PORT
  read -r DOT_URL DOT_PORT < <(yaml_dot)
  
  # ── Ensure базовых директорий/файлов Kresd (идемпотентно) ─────────────────
  # Делаем это здесь, чтобы повторный --prepare не трогал ничего лишнего.
  install -d -m 755 /etc/knot-resolver 2>/dev/null || true
  install -d -m 755 /var/lib/knot-resolver 2>/dev/null || true
  install -d -m 755 /var/cache/knot-resolver 2>/dev/null || true
  local d
  for d in 1 2 3 4; do
    install -d -m 755 "/var/cache/knot-resolver/$d" 2>/dev/null || true
  done
  # Пустой RPZ создаём только если отсутствует (не перетираем существующий)
  if [[ ! -f /etc/knot-resolver/proxy.rpz ]]; then
    install -D -m 0644 /dev/null /etc/knot-resolver/proxy.rpz
  fi
  # Приведём владельца директорий/файлов к пользователю юнита kresd (fallback → root)
  local ug u g
  ug="$(_kresd_unit_user)"; u="${ug%:*}"; g="${ug#*:}"
  chown -R "$u:$g" /etc/knot-resolver /var/lib/knot-resolver /var/cache/knot-resolver 2>/dev/null || true

  # Экранируем одинарные кавычки на случай форматов вида 1.1.1.1#853
  local ipv4a_e=${ipv4a//\'/\\\'}
  local ipv4b_e=${ipv4b//\'/\\\'}
  local ipv6a_e=${ipv6a//\'/\\\'}
  local ipv6b_e=${ipv6b//\'/\\\'}

  # Раздельные списки для v4/v6
  local -a UP4_LIST=() UP6_LIST=()
  [[ -n $ipv4a ]] && UP4_LIST+=("'${ipv4a_e}'")
  [[ -n $ipv4b ]] && UP4_LIST+=("'${ipv4b_e}'")
  [[ -n $ipv6a ]] && UP6_LIST+=("'${ipv6a_e}'")
  [[ -n $ipv6b ]] && UP6_LIST+=("'${ipv6b_e}'")

  # Sanity check: если апстримов нет — не трогаем файл и не перезапускаем kresd
  if ((${#UP4_LIST[@]} + ${#UP6_LIST[@]} == 0)); then
    echo "[WARN] kresd_heal: upstream list is empty; skip updating /etc/knot-resolver/upstream_dns.lua" >&2
    (( _acq )) && _release_settings_lock
    return 0
  fi
  local TMP; TMP="$(mktemp)"
  # Пишем ipv4/ipv6 + DoT параметры (dot/port_tls)
  {
    printf "return {\n"
    { local IFS=,; printf "  ipv4 = {%s},\n" "${UP4_LIST[*]}"; }
    { local IFS=,; printf "  ipv6 = {%s},\n" "${UP6_LIST[*]}"; }
    printf "  dot = '%s',\n" "${DOT_URL//\'/\\\'}"
    printf "  port_tls = %s\n" "${DOT_PORT}"
    printf "}\n"
  } >"$TMP"
  local LUA=/etc/knot-resolver/upstream_dns.lua
  if _write_if_changed "$LUA" "$TMP"; then _changed=1; fi
  # Права на lua + proxy.rpz (если есть) — одним вызовом (идемпотентно)
  kresd_fix_perms || true
  KRESD_UPSTREAM_CHANGED=${_changed}
  (( _acq )) && _release_settings_lock
  return 0
}

# Агрегированный «мини-синк» правил — без «apply all».
# Полностью уводим точечные изменения в firewall/up.sh.
sync_fw_all() {
  dot_ipset_sync
  "${FIREWALL_DIR}/up.sh" --fw-dot-port
  "${FIREWALL_DIR}/up.sh" --fw-ssh
  "${FIREWALL_DIR}/up.sh" --fw-vpn-ports
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
  [[ -z "${1-}" ]] && return 0
  if ! _have systemctl; then
    echo "[WARN] systemctl not found; skip: $*" >&2
    return 0
  fi
  local verb="$1"; shift || true
  case "$verb" in
    reload|try-reload-or-restart|restart|try-restart)
      systemctl --no-block "$verb" "$@" || true
      ;;
    *)
      systemctl "$verb" "$@"
      ;;
  esac
}

###############################################################################
# WG restart detector: нужен ли рестарт интерфейсов
###############################################################################
__wg_should_restart() {
  # Вернёт 0 (true), если интерфейсы отсутствуют или их IPv4/маски не совпадают с YAML
  local SVPN_NET4 FVPN_NET4
  SVPN_NET4="$(yaml_get 'vpn.nets.split' '10.29.8.0/24')"
  FVPN_NET4="$(yaml_get 'vpn.nets.full'  '10.28.8.0/24')"
  vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" || { echo "[WARN] __wg_should_restart: invalid CIDRs in settings → forcing restart"; return 0; }
  local need=n
  if ! ip link show rzans_svpn_main &>/dev/null; then
    need=y
  else
    ip -o -4 addr show dev rzans_svpn_main | awk '{print $4}' | grep -qx "$SVPN_ADDR" || need=y
  fi
  if ! ip link show rzans_fvpn_main &>/dev/null; then
    need=y
  else
    ip -o -4 addr show dev rzans_fvpn_main | awk '{print $4}' | grep -qx "$FVPN_ADDR" || need=y
  fi
  [[ "$need" == y ]]
}

wg_server_ensure_missing_only() {
  # Создаём только отсутствующие элементы: key и оба server-конфига.
  install -d -m 700 /etc/wireguard 2>/dev/null || true

  # Адреса/порты из YAML
  local SVPN_NET4 FVPN_NET4 SPLIT_PORT FULL_PORT
  SVPN_NET4="$(yaml_get 'vpn.nets.split' '10.29.8.0/24')"
  FVPN_NET4="$(yaml_get 'vpn.nets.full'  '10.28.8.0/24')"
  vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" || return 0
  SPLIT_PORT="$(yaml_get_port 'vpn.ports.split' 500)"
  FULL_PORT="$(yaml_get_port 'vpn.ports.full'  4500)"

  # Ключ (если отсутствует)
  if [[ ! -f /etc/wireguard/key ]] && _have wg; then
    local PRIVATE_KEY PUBLIC_KEY
    PRIVATE_KEY="$(wg genkey)"
    PUBLIC_KEY="$(echo "${PRIVATE_KEY}" | wg pubkey)"
    printf 'PRIVATE_KEY=%s\nPUBLIC_KEY=%s\n' "$PRIVATE_KEY" "$PUBLIC_KEY" >/etc/wireguard/key
    _root0600 /etc/wireguard/key
  fi
  [[ -f /etc/wireguard/key ]] && . /etc/wireguard/key 2>/dev/null || true
  export PRIVATE_KEY PUBLIC_KEY

  # Шаблон и серверные конфиги (только если отсутствуют)
  local TPL="/etc/wireguard/templates/rzans_vpn_main.conf" tmp
  if [[ ! -f /etc/wireguard/rzans_svpn_main.conf ]]; then
    local tmp; tmp="$(mktemp)" && _render "$TPL" >"$tmp" || { rm -f "$tmp"; return 1; }
    sed -i -E "s|^Address *=.*|Address = ${SVPN_ADDR}|" "$tmp"
    sed -i -E "s|^ListenPort *=.*|ListenPort = ${SPLIT_PORT}|" "$tmp"
    mv -f -- "$tmp" /etc/wireguard/rzans_svpn_main.conf
    _root0600 /etc/wireguard/rzans_svpn_main.conf
  fi
  if [[ ! -f /etc/wireguard/rzans_fvpn_main.conf ]]; then
    local tmp; tmp="$(mktemp)" && _render "$TPL" >"$tmp" || { rm -f "$tmp"; return 1; }
    sed -i -E "s|^Address *=.*|Address = ${FVPN_ADDR}|" "$tmp"
    sed -i -E "s|^ListenPort *=.*|ListenPort = ${FULL_PORT}|" "$tmp"
   mv -f -- "$tmp" /etc/wireguard/rzans_fvpn_main.conf
    _root0600 /etc/wireguard/rzans_fvpn_main.conf
  fi
}

###############################################################################
# Точечные apply_* по ключам (кроме routing.*)
###############################################################################
# server.port_ssh
apply_server_port_ssh() {
  _require_root
  sshd_set_port || true
  _update_f2b_port || true
  need fw:ssh
  need svc:sshd.reload
  if [[ "$(yaml_bool 'fail2ban.enable')" == y ]]; then need svc:fail2ban.reload; fi
}

# Композит: перегенерация профилей и рестарт WG (одна «точка входа»)
apply_server_endpoints(){
  _require_root
  need clients:regen
  need wg:restart
}
# server.domain → влияет на Endpoint
apply_server_domain(){ apply_server_endpoints; }
# server.ipv4 → влияет на Endpoint
apply_server_ipv4(){ apply_server_endpoints; }
# IPv6 не влияет на Endpoint (IPv4-only политика) — ничего не делаем
apply_server_ipv6(){ :; }

# dns.upstream / dns.port_tls → kresd + cosmetics (AGH не трогаем)
apply_dns_upstream() {
  _require_root
  need kresd:upstream
  need ipset:dot_sync
  need fw:dot-port
  need sys:upstream-cosmetics
  need settings:dns-cosmetics
}

# allowip.* → ipset + fail2ban
apply_allowip_ipv4(){ _require_root; allow_sync_ipsets; _update_f2b_ignoreip || true; need svc:fail2ban.reload; need fw:ssh; }
apply_allowip_ipv6(){ _require_root; allow_sync_ipsets; _update_f2b_ignoreip || true; need svc:fail2ban.reload; need fw:ssh; }

# vpn.ports.* → открыть порты и крутануть listen-port на лету
apply_vpn_ports_split(){
  _require_root
  need fw:vpn-ports
  need wg:listen-ports
  need clients:regen
  need wg:restart
}
apply_vpn_ports_full(){
  _require_root
  need fw:vpn-ports
  need wg:listen-ports
  need clients:regen
  need wg:restart
}

# vpn.nets.* → fw nets/dns-map/snat + AGH allowed_clients + wg restart + профили
apply_vpn_nets_split(){
  _require_root
  need fw:nets
  need dns:map
  need fw:snat
  need wg:listen-ports
  if [[ "$(yaml_bool 'adguard_home.enable')" == y ]]; then need agh:allowed; need svc:agh.reload; fi
  need wg:restart
  need clients:regen
}
apply_vpn_nets_full(){ apply_vpn_nets_split; }

# vpn.map_dns влияет на DNAT + SVPN_ALLOWED в профилях
apply_vpn_map_dns(){
  _require_root
  need dns:map
  need fw:mapping
  # Меняется DNAT/мэппинг — безопаснее «жёстко» перезапустить прокси
  need svc:proxy.restart
  need clients:regen
  need wg:restart
}

# snat (массив записей) → только правила/интерфейсные IP
apply_snat(){ _require_root; need fw:snat; }

# enable/disable сервисов
apply_adguard_enable(){
  _require_root
  if [[ "$(yaml_bool 'adguard_home.enable')" == y ]]; then
    need agh:heal
    # DNAT 53 → AGH отложим до пост-старта AGH (см. run_needs: dns:map-post-agh)
    need dns:map-post-agh
    need svc:agh.enable
  else
    need dns:map          # DNAT 53 → KRESD3/4 и обновление INPUT-allow
    need svc:agh.disable
  fi
  # После переключения фронта (AGH ON/OFF) даём прокси мягкий reload (HUP),
  # чтобы он подхватил TTL/источники без даунтайма
  need svc:proxy.reload
}
apply_fail2ban_enable(){
  _require_root
  if [[ "$(yaml_bool 'fail2ban.enable')" == y ]]; then
    need f2b:update-port
    need f2b:update-ignoreip
    need svc:fail2ban.enable
  else
    need svc:fail2ban.disable
  fi
}

# ── Диспетчер: apply-keys "k1,k2 k3"
apply_keys() {
  _require_root
  local raw="${*:-}"; [[ -z "$raw" ]] && { echo "apply_keys: no keys" >&2; return 2; }
  # Разбиваем по пробелам/табам/переводам строки и запятым (глобальный IFS не важен)
  local -a _keys=()
  local IFS=$' \t,\n'
  read -r -a _keys <<< "$raw"
  # Дедупликация входных ключей, чтобы не гонять одинаковые apply_* повторно
  declare -A _seen=()
  local -a _uniq=()
  local _tok
  for _tok in "${_keys[@]}"; do
    [[ -z "${_tok:-}" ]] && continue
    if [[ -z "${_seen[$_tok]:-}" ]]; then
      _seen["$_tok"]=1
      _uniq+=("$_tok")
    fi
  done
  _keys=("${_uniq[@]}")

  local k endpoints_dirty=0
   for k in "${_keys[@]}"; do
    case "$k" in
      server.port_ssh)        _with_lock apply_server_port_ssh ;;
      server.domain)          endpoints_dirty=1 ;;
      server.ipv4)            endpoints_dirty=1 ;;
      server.ipv6)            _with_lock apply_server_ipv6 ;;   # no-op
      dns.upstream|dns.port_tls) _with_lock apply_dns_upstream ;;
      allowip.ipv4)           _with_lock apply_allowip_ipv4    ;;
      allowip.ipv6)           _with_lock apply_allowip_ipv6    ;;
      vpn.ports.split)        _with_lock apply_vpn_ports_split ;;
      vpn.ports.full)         _with_lock apply_vpn_ports_full  ;;
      vpn.nets.split)         _with_lock apply_vpn_nets_split  ;;
      vpn.nets.full)          _with_lock apply_vpn_nets_full   ;;
      vpn.map_dns)            _with_lock apply_vpn_map_dns     ;;
      snat)                   _with_lock apply_snat            ;;
      adguard_home.enable)    _with_lock apply_adguard_enable  ;;
      fail2ban.enable)        _with_lock apply_fail2ban_enable ;;
      *) echo "apply_keys: unknown key '$k' (skip)" >&2 ;;
    esac
  done
  if (( endpoints_dirty )); then
    _with_lock apply_server_endpoints
  fi
  run_needs
}

# Композит: применить все основные ключи в безопасном порядке
apply_all() {
  _require_root
  # Гарантируем отсутствие «дыр» при первом запуске
  wg_server_ensure_missing_only || true
  apply_keys "adguard_home.enable fail2ban.enable server.port_ssh allowip.ipv4 allowip.ipv6 dns.upstream dns.port_tls vpn.ports.split vpn.ports.full vpn.nets.split vpn.nets.full vpn.map_dns snat server.domain server.ipv4"
}

prepare_main() {
  _require_root
  _with_lock settings_heal
  _with_lock autofill_settings
  _with_lock kresd_heal
  _with_lock agh_heal
  _with_lock _update_system_upstream
  _with_lock logrotate_ensure
  # apply_all сам вызывает apply_keys → run_needs, так что здесь не нужно
}

# Обёртка: взять lock, выполнить функцию, всегда отпустить lock (даже при ошибке)
_with_lock() {
  local had=0 rc=0
  # Учитываем оба типа локов: через FD и через каталог
  if [[ -n "${_SETTINGS_LOCK_FD:-}" || -n "${_SETTINGS_LOCK_MDIR:-}" ]]; then
    had=1
  fi
  _ensure_settings_lock || return 1
  "$@" || rc=$?
  (( had == 0 )) && _release_settings_lock || true
  return $rc
}

# ── Read-only вывод для proxy.py ─────────────────────────────────────────────
print_env_proxy() {
  # Берём значения из окружения settings.sh (с дефолтами, как и вверху файла)
  local _proxy="${PROXY_IP:-127.0.0.5}"
  local _k2="${KRESD2_IP:-127.0.0.2}"
  local _port="${DNS_PORT:-53}"
  [[ "$_port" =~ ^[0-9]+$ ]] || _port=53
  printf '{"PROXY_IP":"%s","DNS_PORT":%s,"KRESD2_IP":"%s"}\n' "$_proxy" "$_port" "$_k2"
}

# ── Auto-apply (встроенная замена бывшему dispatcher.sh) ────────
__auto_gen_snapshot() {
  local ALLOW4 ALLOW6 SNAT
  ALLOW4="$(yaml_allow_all | grep -v ':' | awk 'NF' | LC_ALL=C sort -u | paste -sd',' -)"
  ALLOW6="$(yaml_allow_all | grep ':'     | awk 'NF' | LC_ALL=C sort -u | paste -sd',' -)"
  SNAT="$(
    _yaml_merged | yq e -r '
      (.snat // [])
      | map({name: .name, internal: .internal, external: ((.external // "0.0.0.0"))})
      | sort_by([.name, .internal, .external])
      | .[] | "\(.name)=\(.internal):\(.external)"
    ' - 2>/dev/null | paste -sd';' -
  )"
  {
    echo "server.port_ssh=$(yaml_get_port 'server.port_ssh' 22)"
    echo "server.domain=$(server_domain)"
    echo "server.ipv4=$(yaml_get_ip 'server.ipv4' '0.0.0.0')"
    echo "server.ipv6=$(yaml_get_ip 'server.ipv6' '::')"
    echo "dns.upstream=$(yaml_get 'dns.upstream' cloudflare | tr '[:upper:]' '[:lower:]')"
    echo "dns.port_tls=$(yaml_get_port 'dns.port_tls' 853)"
    echo "allowip.ipv4=${ALLOW4}"
    echo "allowip.ipv6=${ALLOW6}"
    echo "vpn.ports.split=$(yaml_get_port 'vpn.ports.split' 500)"
    echo "vpn.ports.full=$(yaml_get_port 'vpn.ports.full'  4500)"
    echo "vpn.nets.split=$(yaml_get 'vpn.nets.split' '10.29.8.0/24')"
    echo "vpn.nets.full=$(yaml_get 'vpn.nets.full'  '10.28.8.0/24')"
    echo "vpn.map_dns=$(yaml_get 'vpn.map_dns' '10.30.0.0/15')"
    echo "snat=${SNAT}"
    echo "adguard_home.enable=$(yaml_bool 'adguard_home.enable' n)"
    echo "fail2ban.enable=$(yaml_bool 'fail2ban.enable' n)"
  } | LC_ALL=C sort -u
}

auto_apply() {
  _require_root
  # Небольшой дебаунс (редакторы пишут «в два приёма»)
  sleep 0.2 2>/dev/null || sleep 1
  install -d -m 755 "$STATE_DIR" 2>/dev/null || true

  # Берём единый конфиг-лок; лок отпустим вручную перед выходом
  if ! _ensure_settings_lock; then
    echo "[auto-apply] lock busy — skip" >&2
    return 0
  fi

  local SNAPSHOT="${STATE_DIR}/settings.snapshot"
  local CUR_SNAP PREV_SNAP
  CUR_SNAP="$(__auto_gen_snapshot)"
  PREV_SNAP="$(cat "$SNAPSHOT" 2>/dev/null || true)"

  if [[ "$CUR_SNAP" == "$PREV_SNAP" ]]; then
    echo "[auto-apply] no effective change — skip" >&2
    _release_settings_lock
    return 0
  fi

  # Вычислить изменившиеся «снимочные» ключи по diff
  local -a CHANGED_KEYS=()
  while IFS= read -r key; do
    [[ -n "$key" ]] && CHANGED_KEYS+=("$key")
  done < <(
    { diff -u <(printf "%s\n" "$PREV_SNAP") <(printf "%s\n" "$CUR_SNAP") 2>/dev/null || true; } \
      | awk '/^[+-][^+-]/ { sub(/^[+-]/,""); split($0,a,"="); print a[1] }' \
      | LC_ALL=C sort -u
  )

  # Смаппить в apply_keys
  local -a APPLY=()
  local k
  for k in "${CHANGED_KEYS[@]}"; do
    case "$k" in
      server.port_ssh)        APPLY+=("server.port_ssh") ;;
      server.domain)          APPLY+=("server.domain")   ;;
      server.ipv4)            APPLY+=("server.ipv4")     ;;
      server.ipv6)            APPLY+=("server.ipv6")     ;;
      dns.upstream|dns.port_tls) APPLY+=("dns.upstream") ;;
      allowip.ipv4)           APPLY+=("allowip.ipv4")    ;;
      allowip.ipv6)           APPLY+=("allowip.ipv6")    ;;
      vpn.ports.split)        APPLY+=("vpn.ports.split") ;;
      vpn.ports.full)         APPLY+=("vpn.ports.full")  ;;
      vpn.nets.split)         APPLY+=("vpn.nets.split")  ;;
      vpn.nets.full)          APPLY+=("vpn.nets.full")   ;;
      vpn.map_dns)            APPLY+=("vpn.map_dns")     ;;
      snat)                   APPLY+=("snat")            ;;
      adguard_home.enable)    APPLY+=("adguard_home.enable") ;;
      fail2ban.enable)        APPLY+=("fail2ban.enable") ;;
    esac
  done
 
   # Косметическая дедупликация APPLY: оставляем первое вхождение каждого ключа
   if ((${#APPLY[@]})); then
     declare -A _seen_apply=()
     local -a _uniq_apply=()
     local _a
     for _a in "${APPLY[@]}"; do
       [[ -z "${_a:-}" ]] && continue
       if [[ -z "${_seen_apply[$_a]:-}" ]]; then
         _seen_apply["$_a"]=1
         _uniq_apply+=("$_a")
       fi
     done
     APPLY=("${_uniq_apply[@]}")
   fi
  if ((${#APPLY[@]})); then
    echo "[auto-apply] apply_keys: ${APPLY[*]}" >&2
  else
    echo "[auto-apply] changed fields are not actionable — skip" >&2
  fi
  # ВАЖНО: отпускаем конфиг-лок перед тяжёлыми действиями (firewall/restart)
  _release_settings_lock
  if ((${#APPLY[@]})); then
    apply_keys "${APPLY[@]}"
  fi

  # (Опционально) снова кратко берём лок — только чтобы записать снапшот
  _ensure_settings_lock 2>/dev/null || true
  # Зафиксировать новый «снимок»
  local tmp; tmp="$(mktemp "${SNAPSHOT}.XXXX")"
  printf "%s\n" "$CUR_SNAP" >"$tmp"
  mv -f -- "$tmp" "$SNAPSHOT"
  _root0600 "$SNAPSHOT"
  _release_settings_lock
}

# ── CLI-интерфейс ───────────────────────────────────────────────
# исполняем только при прямом запуске, при source — просто экспортируем функции
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
case "${1:-}" in
  --print-env-proxy) shift; print_env_proxy; exit $? ;;
  --prepare)          shift; prepare_main                            "$@"; exit $? ;;
  --apply)            shift; apply_all                               "$@"; exit $? ;;
  --apply-all)        shift; apply_all                               "$@"; exit $? ;;
  --apply-keys)       shift; apply_keys                              "$@"; exit $? ;;
  --sync-fw-ssh)      _require_root; shift; "${FIREWALL_DIR}/up.sh" --fw-ssh;       exit $? ;;
  --sync-fw-vpn-ports) _require_root; shift; "${FIREWALL_DIR}/up.sh" --fw-vpn-ports; exit $? ;;
  --sync-fw-dot)       _require_root; shift; "${FIREWALL_DIR}/up.sh" --fw-dot-port;  exit $? ;;
  --sync-fw)           _require_root; shift; _with_lock sync_fw_all                  "$@"; exit $? ;;
  --switch-system-resolve) shift; _with_lock switch_system_resolve   "$@"; exit $? ;;
  --autofill)         shift; _with_lock autofill_settings            "$@"; exit $? ;;
  --agh-allowed-clients) shift;
    DEFER_RESTARTS=1 _with_lock agh_allowed_clients "$@"
    # Если реально были изменения и AGH включён — мягко обновим уже БЕЗ лока
    if (( AGH_ALLOWED_CHANGED )) && [[ "$(yaml_bool 'adguard_home.enable')" == y ]]; then
      _settings__svc try-reload-or-restart AdGuardHome.service || true
    fi
    exit 0 ;;
  --agh-sync)          shift;
    # Держим единое правило: никаких рестартов «под» локом.
    DEFER_RESTARTS=1 _with_lock agh_allowed_clients "$@"
    if (( AGH_ALLOWED_CHANGED )) && [[ "$(yaml_bool 'adguard_home.enable')" == y ]]; then
      _settings__svc try-reload-or-restart AdGuardHome.service || true
    fi
    exit 0 ;;
  --endpoint-host)     shift;
    if h="$(endpoint_host "${1:-30}")"; then
      printf '%s\n' "$h"; exit 0
    else
      exit 1
    fi ;;
  --auto-apply)       shift; auto_apply "$@"; exit $? ;;
  *)
    echo "Usage: $0 [--print-env-proxy|--prepare|--apply|--apply-all|--apply-keys <key[,key...]>|--switch-system-resolve|--sync-fw|--sync-fw-ssh|--sync-fw-vpn-ports|--sync-fw-dot|--autofill|--agh-allowed-clients|--agh-sync|--endpoint-host [wait]]"
    exit 1 ;;
esac
fi
