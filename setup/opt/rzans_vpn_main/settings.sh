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
#                         — вернуть значение тега или DEFAULT.
# ──────────────────────────────────────────────────────────────────────────────

settings_heal() {
  _settings__ensure_placeholder
  _settings__restore_full_from_template
  settings_pretty
}

settings_pretty() {
  [[ -f "$SETTINGS" ]] || return 0

  # вычисляем ширину колонки (минимум 22, +1 пробел)
  local pad
  pad=$(awk '
    /^[[:space:]]*#/ || NF==0 {next}
    { if (length($1) > m) m = length($1) }
    END { print (m < 22 ? 22 : m + 1) }' "$SETTINGS")

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

settings_get_tag() {          # settings_get_tag TAG DEFAULT
  local tag="$1" def="$2" line
  # POSIX-класс вместо \s, stderr → /dev/null (убираем warning’и awk)
  line=$(awk -v t="^[[:space:]]*${tag}[[:space:]]+" \
             '$0~t && $0!~/^[[:space:]]*#/{ $1=""; sub(/^[[:space:]]+/,""); print; exit }' \
             "$SETTINGS" 2>/dev/null \
        | sed -E 's/[[:space:]]*#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')
  [[ -n $line ]] && printf '%s' "$line" || printf '%s' "$def"
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
# ========================================================================
# settings.map (минимальный автосозданный шаблон)
# --- УСТАНОВОЧНЫЕ ОПЦИИ
RZANS_SVPN_MAIN_DNS     1
RZANS_FVPN_MAIN_DNS     1
BLOCK_ADS               n
ADGUARD_HOME            n
SSH_PROTECTION          n
WIREGUARD_HOST          ""
ROUTE_ALL               n
DISCORD_INCLUDE         y
CLOUDFLARE_INCLUDE      y
AMAZON_INCLUDE          n
HETZNER_INCLUDE         n
DIGITALOCEAN_INCLUDE    n
OVH_INCLUDE             n
TELEGRAM_INCLUDE        y
GOOGLE_INCLUDE          y
AKAMAI_INCLUDE          n

# --- Базовые настройки
EXTIP4                  0.0.0.0          # 0.0.0.0 ⇒ авто
EXTIP6                  ::               # ::      ⇒ авто

# --- Доверенные IPv4/IPv6 для SSH/панели AGH
TRUST4                  0.0.0.0          # 0.0.0.0 ⇒ открыт для всех
TRUST6                  ::               # ::      ⇒ закрыт для всех

# --- Базовые порты VPN (новые теги для самолечения)
SVPN_PORT               500
FVPN_PORT               4500

# --- Базовые подсети VPN 
SVPN_NET4               10.29.8.0/24
FVPN_NET4               10.28.8.0/24

# --- Split-DNS / fake-IP диапазон для proxy.py
VPN_MAP_SRC4            10.29.8.0/24
VPN_MAP_DST4            10.30.0.0/15

# --- Персональные SNAT-правила
# SNAT <INTERNAL_IP> <EXTERNAL_IP>
# ========================================================================
EOF
}

_settings__get_raw_val() {          # $1 = TAG → "value [# comment...]" без ключа
  awk -v t="^[[:space:]]*$1[[:space:]]+" '
      $0~t && $0!~/^[[:space:]]*#/ { $1=""; sub(/^[[:space:]]+/,""); print; exit }' \
      "$SETTINGS" 2>/dev/null \
  | sed -E 's/[[:space:]]+$//'
}

_settings__strip_comment() {  # stdin -> stdout (без хвостового #...)
  sed -E 's/[[:space:]]*#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//'
}

_settings__restore_full_from_template() {
  # авто-удаляем tmp-файлы даже при ошибке/exit
  local old tmp pad
  tmp=$(mktemp)
  old=$(mktemp)
  trap 'rm -f "$tmp" "$old"' RETURN

  cp -f "$SETTINGS" "$old" 2>/dev/null || :

  # динамический pad: длина самого длинного тега, минимум 22 (+1 пробел)
  pad=$(
    _settings__template | awk '
      /^[[:space:]]*#/ || NF==0 {next}
      { if (length($1) > m) m = length($1) }
      END { print (m < 22 ? 22 : m + 1) }' )

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

    # комментарий из шаблона (если есть)
    comment=$(printf '%s' "$def" | grep -oE '#.*$' || true)

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
      def_trimmed=$(printf '%s' "$def" | sed -E 's/^[[:space:]]+//')
      printf "%-*s%s\n" "$pad" "$tag" "$def_trimmed" >>"$tmp"
    fi
  done < <(_settings__template)

  # --- дополнительные TRUST4/6 и SNAT с дедупликацией
  awk '/^[[:space:]]*TRUST[46][[:space:]]+/{print}' "$old" \
    | tail -n +2 | awk '!seen[$0]++' >>"$tmp" || true
  grep -E "^[[:space:]]*SNAT[[:space:]]+" "$old" \
    | awk '!seen[$0]++' >>"$tmp" || true

  mv "$tmp" "$SETTINGS" && chmod 600 "$SETTINGS"
}