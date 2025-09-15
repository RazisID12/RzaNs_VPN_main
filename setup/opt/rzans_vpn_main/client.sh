#!/bin/bash
# chmod +x client.sh && ./client.sh [1-5] [имя_клиента]
#
set -eEuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

handle_error() {
    local os
    os="$(lsb_release -ds 2>/dev/null \
         || sed -n '/^PRETTY_NAME=/ { s/^PRETTY_NAME=//; s/^"//; s/"$//; p; }' /etc/os-release)"
    echo "$os $(uname -r) $(date --iso-8601=seconds)"
    # shellcheck disable=SC2059 # форматированная строка нужна для цвета
    printf '\e[1;31mError at line %s: %s\e[0m\n' "$1" "$2"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

export LC_ALL=C

# используем общие helpers из settings.sh (yaml_get/yaml_bool, vpn_addrs_from_cidrs и т.п.)
# shellcheck source=/opt/rzans_vpn_main/settings/settings.sh
. /opt/rzans_vpn_main/settings/settings.sh
_require_prepared || { echo "settings.yaml is missing. Run: settings.sh --prepare"; exit 110; }

# ——— helpers ——————————————————————————————————————————————————
_have() { command -v "$1" >/dev/null 2>&1; }

# ── helper: чинит права на AdGuardHome.yaml и перезапускает сервис ───────────
ensure_agh_yaml_perms_restart() {
  local agh_yaml="/opt/AdGuardHome/AdGuardHome.yaml"
  [[ -f "$agh_yaml" ]] || return 0
  # Единый helper из settings.sh: корректные владелец/группа/SELinux-контекст
  agh_fix_perms "$agh_yaml" || true
  # Мягкое обновление сервиса, чтобы подхватил исправленные права
  _settings__svc try-reload-or-restart AdGuardHome >/dev/null 2>&1 || true
}

# единый рендерер (если settings.sh уже объявил — используем его)
if ! declare -F _render >/dev/null 2>&1; then
  _render() {
    if declare -F render >/dev/null 2>&1; then
      render "$1"
    elif _have render; then
      command render "$1"
    elif _have envsubst; then
      envsubst < "$1"
    else
      echo "ERROR: no template renderer (need 'render' или 'envsubst')" >&2
      return 1
    fi
  }
fi

# проверяем критичные внешние бинари (только wg — для WireGuard)
# yq/uuidgen используются внутри add_agh_client/remove_agh_client (в settings.sh)
for bin in wg; do
  _have "$bin" || { echo "ERROR: '$bin' not found, abort." >&2; exit 127; }
done

askClientName(){
	if ! [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
		echo
		echo 'Enter client name: 1–32 alphanumeric characters (a-z, A-Z, 0-9) with underscore (_) or dash (-)'
		until [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; do
			read -rp 'Client name: ' -e CLIENT_NAME
		done
	fi
}

initWireGuard(){
    # 1) Генерируем ключи, если их ещё нет
    if [[ ! -f /etc/wireguard/key ]]; then
        echo
        echo 'Generating WireGuard/AmneziaWG server keys'
        PRIVATE_KEY="$(wg genkey)"
        PUBLIC_KEY="$(echo "${PRIVATE_KEY}" | wg pubkey)"
        printf 'PRIVATE_KEY=%s\nPUBLIC_KEY=%s\n' "$PRIVATE_KEY" "$PUBLIC_KEY" > /etc/wireguard/key
    fi

    # 1-bis) Загружаем ключи в окружение, чтобы render мог подставить ${PRIVATE_KEY}/${PUBLIC_KEY}
    #       (нужно даже если ключи созданы ранее)
  # shellcheck disable=SC1091
  source /etc/wireguard/key
  export PRIVATE_KEY PUBLIC_KEY

    # 2) Всегда убеждаемся, что оба серверных конфига присутствуют

    if [[ ! -f /etc/wireguard/rzans_svpn_main.conf ]]; then
        _render "/etc/wireguard/templates/rzans_vpn_main.conf" > /tmp/svpn.tmp
        sed -i -E "s|^Address *=.*|Address = ${SVPN_ADDR}|"       /tmp/svpn.tmp
        mv /tmp/svpn.tmp /etc/wireguard/rzans_svpn_main.conf
    else
        # CIDR мог измениться — обновляем Address даже в существующем файле
        sed -i -E "s|^Address *=.*|Address = ${SVPN_ADDR}|" /etc/wireguard/rzans_svpn_main.conf
    fi
    sed -i -E "s/^ListenPort *=.*/ListenPort = ${SPLIT_PORT}/"     /etc/wireguard/rzans_svpn_main.conf

    if [[ ! -f /etc/wireguard/rzans_fvpn_main.conf ]]; then
        _render "/etc/wireguard/templates/rzans_vpn_main.conf" > /tmp/fvpn.tmp
        sed -i -E "s|^Address *=.*|Address = ${FVPN_ADDR}|"       /tmp/fvpn.tmp
        mv /tmp/fvpn.tmp /etc/wireguard/rzans_fvpn_main.conf
    else
        # CIDR мог измениться — обновляем Address даже в существующем файле
        sed -i -E "s|^Address *=.*|Address = ${FVPN_ADDR}|" /etc/wireguard/rzans_fvpn_main.conf
    fi
    sed -i -E "s/^ListenPort *=.*/ListenPort = ${FULL_PORT}/"      /etc/wireguard/rzans_fvpn_main.conf
  chmod 600 /etc/wireguard/rzans_{s,f}vpn_main.conf /etc/wireguard/key

  # плейсхолдеры не должны остаться в серверных конфигах
  for f in /etc/wireguard/rzans_{s,f}vpn_main.conf; do
      # shellcheck disable=SC2016 # хотим буквально искать ${VARS} в файле
      if grep -Eq '\${[A-Z_]+}' "$f"; then
          echo "ERROR: Unsubstituted variables found in $f" >&2
          exit 8
      fi
  done
}

addWireGuard(){

    # --- синхронизируем Address/ListenPort в серверных конфигах при каждом вызове ---
    sed -i -E "s|^Address *=.*|Address = ${SVPN_ADDR}|" /etc/wireguard/rzans_svpn_main.conf
    sed -i -E "s|^Address *=.*|Address = ${FVPN_ADDR}|" /etc/wireguard/rzans_fvpn_main.conf
    sed -i -E "s/^ListenPort *=.*/ListenPort = ${SPLIT_PORT}/" /etc/wireguard/rzans_svpn_main.conf
    sed -i -E "s/^ListenPort *=.*/ListenPort = ${FULL_PORT}/"  /etc/wireguard/rzans_fvpn_main.conf
    if systemctl is-active --quiet wg-quick@rzans_svpn_main; then
        wg syncconf rzans_svpn_main <(wg-quick strip rzans_svpn_main 2>/dev/null)
    fi
    if systemctl is-active --quiet wg-quick@rzans_fvpn_main; then
        wg syncconf rzans_fvpn_main <(wg-quick strip rzans_fvpn_main 2>/dev/null)
    fi
	echo

# ключи могли ещё не существовать при опции 2/3/5
    if [[ -f /etc/wireguard/key ]]; then
        # shellcheck disable=SC1091
        source /etc/wireguard/key
        # симметрия с initWireGuard: гарантируем, что ключи есть в окружении
        export PRIVATE_KEY PUBLIC_KEY
    fi
    # файл /etc/wireguard/ips нужен не всегда: читаем безопасно и пересобираем SVPN_ALLOWED
    if [[ -f /etc/wireguard/ips ]]; then
        IPS=$(tr -s ' \n' ',' </etc/wireguard/ips | sed 's/^,//;s/,$//')
    fi
    : "${IPS:=}"   # ShellCheck/ nounset: безопасная инициализация, если файла нет
    SVPN_ALLOWED="${SVPN_NET4}, ${VPN_MAP_DST4}${IPS:+, ${IPS}}"

	# RzaNs_sVPN_main

	CLIENT_BLOCK="$(sed -n "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/ {p; /^AllowedIPs/q}" /etc/wireguard/rzans_svpn_main.conf)"

	if [[ -n "$CLIENT_BLOCK" ]]; then
		CLIENT_PRIVATE_KEY="$(echo "$CLIENT_BLOCK" | grep '# PrivateKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PUBLIC_KEY="$(echo "$CLIENT_BLOCK" | grep 'PublicKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PRESHARED_KEY="$(echo "$CLIENT_BLOCK" | grep 'PresharedKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_IP="$(echo "$CLIENT_BLOCK" | grep 'AllowedIPs =' | cut -d '=' -f 2- | sed 's/ //g' | cut -d '/' -f 1)"
        if [[ "${REBUILD:-0}" != 1 ]]; then
            echo "Client '${CLIENT_NAME}' already exists – skip peer creation, continue AGH/SNAT upsert and profile render."
        fi
        # REBUILD=1: не добавляем peer, но продолжаем — ниже перегенерятся профили,
        # idempotent-обновятся AGH и SNAT
	else
		CLIENT_PRIVATE_KEY="$(wg genkey)"
		CLIENT_PUBLIC_KEY="$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)"
		CLIENT_PRESHARED_KEY="$(wg genpsk)"
        BASE_CLIENT_IP="$(grep "^Address" /etc/wireguard/rzans_svpn_main.conf | sed 's/.*= *//' | tr -d ' ,' | cut -d'.' -f1-3 | head -n 1)"
        for ((i=2; i<=255; i++)); do
			CLIENT_IP="${BASE_CLIENT_IP}.$i"
            # точная проверка занятости адреса по строке AllowedIPs (без ложных совпадений)
            local _ip_pat="${CLIENT_IP//./\\.}"
			if ! grep -qE "^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*${_ip_pat}/32[[:space:]]*$" /etc/wireguard/rzans_svpn_main.conf; then
				break
			fi
            if (( i == 255 )); then
				echo 'The WireGuard/AmneziaWG subnet can support only 253 clients!'
				exit 4
			fi
		done
        {
            echo
            echo "# Client = ${CLIENT_NAME}"
            echo "# PrivateKey = ${CLIENT_PRIVATE_KEY}"
            echo "[Peer]"
            echo "PublicKey = ${CLIENT_PUBLIC_KEY}"
            echo "PresharedKey = ${CLIENT_PRESHARED_KEY}"
            echo "AllowedIPs = ${CLIENT_IP}/32"
        } >> "/etc/wireguard/rzans_svpn_main.conf"
		if systemctl is-active --quiet wg-quick@rzans_svpn_main; then
			wg syncconf rzans_svpn_main <(wg-quick strip rzans_svpn_main 2>/dev/null)
		fi
	fi

    # гарантируем каталоги один раз
    install -d "/opt/rzans_vpn_main/client/rzans_svpn_main" "/opt/rzans_vpn_main/client/rzans_fvpn_main"
    SERVER_PORT=$SPLIT_PORT
    export SVPN_DNS_IP SVPN_ALLOWED
    # переменные, необходимые для рендера клиентского файла (envsubst)
    export CLIENT_PRIVATE_KEY CLIENT_PRESHARED_KEY CLIENT_IP PUBLIC_KEY SERVER_HOST SERVER_PORT
    SPLIT_FILE="/opt/rzans_vpn_main/client/rzans_svpn_main/RzaNs_sVPN_main-${CLIENT_NAME}.conf"
    _render "/etc/wireguard/templates/rzans_svpn_main.conf" >"$SPLIT_FILE"
    chmod 600 "$SPLIT_FILE"

    # AGH persistent entry для Split-VPN
    ADD_NO_RESTART=1 add_agh_client "$CLIENT_IP" "split" "sVPN ${CLIENT_NAME}"
    # SNAT-автозапись
    add_snat "$CLIENT_IP" "sVPN ${CLIENT_NAME}"

	# RzaNs_fVPN_main

	CLIENT_BLOCK="$(sed -n "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/ {p; /^AllowedIPs/q}" /etc/wireguard/rzans_fvpn_main.conf)"
	if [[ -n "$CLIENT_BLOCK" ]]; then
		CLIENT_PRIVATE_KEY="$(echo "$CLIENT_BLOCK" | grep '# PrivateKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PUBLIC_KEY="$(echo "$CLIENT_BLOCK" | grep 'PublicKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PRESHARED_KEY="$(echo "$CLIENT_BLOCK" | grep 'PresharedKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_IP="$(echo "$CLIENT_BLOCK" | grep 'AllowedIPs =' | cut -d '=' -f 2- | sed 's/ //g' | cut -d '/' -f 1)"
        # Единообразно: если клиент уже есть, пропускаем создание peer'а, но продолжаем upsert/рендер
        if [[ "${REBUILD:-0}" != 1 ]]; then
            echo "Client '${CLIENT_NAME}' already exists – skip peer creation, continue AGH/SNAT upsert and profile render."
        fi
	else
		CLIENT_PRIVATE_KEY="$(wg genkey)"
		CLIENT_PUBLIC_KEY="$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)"
		CLIENT_PRESHARED_KEY="$(wg genpsk)"
        BASE_CLIENT_IP="$(grep "^Address" /etc/wireguard/rzans_fvpn_main.conf | sed 's/.*= *//' | tr -d ' ,' | cut -d'.' -f1-3 | head -n 1)"
        for ((i=2; i<=255; i++)); do
			CLIENT_IP="${BASE_CLIENT_IP}.$i"
            # точная проверка занятости адреса по строке AllowedIPs (без ложных совпадений)
            local _ip_pat="${CLIENT_IP//./\\.}"
			if ! grep -qE "^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*${_ip_pat}/32[[:space:]]*$" /etc/wireguard/rzans_fvpn_main.conf; then
				break
			fi
            if (( i == 255 )); then
				echo 'The WireGuard/AmneziaWG subnet can support only 253 clients!'
				exit 5
			fi
		done
        {
            echo
            echo "# Client = ${CLIENT_NAME}"
            echo "# PrivateKey = ${CLIENT_PRIVATE_KEY}"
            echo "[Peer]"
            echo "PublicKey = ${CLIENT_PUBLIC_KEY}"
            echo "PresharedKey = ${CLIENT_PRESHARED_KEY}"
            echo "AllowedIPs = ${CLIENT_IP}/32"
        } >> "/etc/wireguard/rzans_fvpn_main.conf"
		if systemctl is-active --quiet wg-quick@rzans_fvpn_main; then
			wg syncconf rzans_fvpn_main <(wg-quick strip rzans_fvpn_main 2>/dev/null)
		fi
	fi

    SERVER_PORT=$FULL_PORT
    # экспортируем DNS IP для full-профиля (если используется в шаблоне)
    export FVPN_DNS_IP
    export CLIENT_PRIVATE_KEY CLIENT_PRESHARED_KEY CLIENT_IP PUBLIC_KEY SERVER_HOST SERVER_PORT
    FULL_FILE="/opt/rzans_vpn_main/client/rzans_fvpn_main/RzaNs_fVPN_main-${CLIENT_NAME}.conf"
    _render "/etc/wireguard/templates/rzans_fvpn_main.conf" >"$FULL_FILE"
    chmod 600 "$FULL_FILE"

    # валидация: не осталось ли необработанных ${VARS}
    for f in "$SPLIT_FILE" "$FULL_FILE"; do
        # shellcheck disable=SC2016 # хотим буквально искать ${VARS} в файле
        if grep -Eq '\${[A-Z_]+}' "$f"; then
            echo "ERROR: Unsubstituted variables found in $f" >&2
            exit 7
        fi
    done

    # AGH persistent entry для Full-VPN
    ADD_NO_RESTART=1 add_agh_client "$CLIENT_IP" "full" "fVPN ${CLIENT_NAME}"
    add_snat "$CLIENT_IP" "fVPN ${CLIENT_NAME}"
    # после любых изменений YAML правим владельца/права и рестартуем AGH
    ensure_agh_yaml_perms_restart


    echo "Profiles (split & full) created in /opt/rzans_vpn_main/client/{rzans_svpn_main,rzans_fvpn_main}"
	echo
	echo 'If import fails, shorten filename to 32 chars (Windows) / 15 (Linux/Android/iOS), remove parentheses'
}

deleteWireGuard(){
	echo

	if ! grep -q "# Client = ${CLIENT_NAME}" "/etc/wireguard/rzans_svpn_main.conf" && ! grep -q "# Client = ${CLIENT_NAME}" "/etc/wireguard/rzans_fvpn_main.conf"; then
		echo "Failed to delete client '$CLIENT_NAME'! Please check if client exists"
		exit 6
	fi

	sed -i "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/d" /etc/wireguard/rzans_svpn_main.conf
	sed -i "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/d" /etc/wireguard/rzans_fvpn_main.conf

	sed -i '/^$/N;/^\n$/D' /etc/wireguard/rzans_svpn_main.conf
	sed -i '/^$/N;/^\n$/D' /etc/wireguard/rzans_fvpn_main.conf

    rm -f "/opt/rzans_vpn_main/client/rzans_svpn_main/RzaNs_sVPN_main-${CLIENT_NAME}.conf" \
          "/opt/rzans_vpn_main/client/rzans_fvpn_main/RzaNs_fVPN_main-${CLIENT_NAME}.conf" \
          2>/dev/null || true

    # ── убираем запись клиента из AdGuard Home ─────────────────────
    ADD_NO_RESTART=1 remove_agh_client "sVPN ${CLIENT_NAME}"
    ADD_NO_RESTART=1 remove_agh_client "fVPN ${CLIENT_NAME}"
    remove_snat "sVPN ${CLIENT_NAME}"
    remove_snat "fVPN ${CLIENT_NAME}"

    # убедимся, что AdGuard Home поднимется с корректными правами
    ensure_agh_yaml_perms_restart


	if systemctl is-active --quiet wg-quick@rzans_svpn_main; then
		wg syncconf rzans_svpn_main <(wg-quick strip rzans_svpn_main 2>/dev/null)
	fi

	if systemctl is-active --quiet wg-quick@rzans_fvpn_main; then
		wg syncconf rzans_fvpn_main <(wg-quick strip rzans_fvpn_main 2>/dev/null)
	fi

	echo "Client '$CLIENT_NAME' successfully deleted"
}

listWireGuard(){
    [[ -n "$CLIENT_NAME" ]] && return
    echo
    echo 'Client names:'
    # Избегаем падения при отсутствии клиентов (grep возвращает 1)
    set +e
    CLIENTS_OUT=$(grep -hE '^# Client' \
        /etc/wireguard/rzans_svpn_main.conf \
        /etc/wireguard/rzans_fvpn_main.conf 2>/dev/null \
        | cut -d '=' -f 2- | sed 's/ //g' | sort -u || true)
    set -e
    if [[ -z "$CLIENTS_OUT" ]]; then
        echo '(none)'
        return
    fi
    printf '%s\n' "$CLIENTS_OUT"
}

recreate(){
    echo
    # Всегда синхронизируем server-конфиги с текущими YAML-настройками:
    #   - обновит Address/ListenPort в существующих файлах,
    #   - при отсутствии создаст key + 2 server-конфига.
    initWireGuard
    find /opt/rzans_vpn_main/client -type f -delete

    # Безопасно собираем список клиентов (может быть пустым)
    set +e
    CLIENTS_OUT=$(grep -hE '^# Client' \
        /etc/wireguard/rzans_svpn_main.conf \
        /etc/wireguard/rzans_fvpn_main.conf 2>/dev/null \
        | cut -d '=' -f 2- | sed 's/ //g' | sort -u || true)
    set -e
    if [[ -z "${CLIENTS_OUT:-}" ]]; then
        echo "No clients found — server confs synced (ports/addresses), no profiles to recreate."
    else
        local _n=0
        while IFS= read -r CLIENT_NAME; do
            [[ -z "$CLIENT_NAME" ]] && continue
            if [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
                REBUILD=1 addWireGuard >/dev/null
                _n=$((_n+1))
            else
                echo "Client name '$CLIENT_NAME' is invalid! No profile files recreated"
            fi
        done <<< "$CLIENTS_OUT"
        echo "Recreated profile files for ${_n} client(s) → /opt/rzans_vpn_main/client/{rzans_svpn_main,rzans_fvpn_main}"
    fi
}

backup(){
	echo
	
    # Если backup вызван напрямую (в обход case) — гарантируем SERVER_HOST
    if [[ -z "${SERVER_HOST:-}" ]]; then
      if ! SERVER_HOST="$(endpoint_host 30)"; then
        echo 'No server.domain and no global IPv4 detected' >&2
        return 2
      fi
    fi

    rm -rf /opt/rzans_vpn_main/backup
    mkdir -p /opt/rzans_vpn_main/backup/wireguard
    # Подстрахуемся на случай отсутствующих файлов/директорий
    [[ -e /etc/wireguard/rzans_svpn_main.conf ]] && cp -r /etc/wireguard/rzans_svpn_main.conf /opt/rzans_vpn_main/backup/wireguard
    [[ -e /etc/wireguard/rzans_fvpn_main.conf ]] && cp -r /etc/wireguard/rzans_fvpn_main.conf /opt/rzans_vpn_main/backup/wireguard
    [[ -e /etc/wireguard/key ]] && cp -r /etc/wireguard/key /opt/rzans_vpn_main/backup/wireguard
    [[ -e /opt/rzans_vpn_main/config ]] && cp -r /opt/rzans_vpn_main/config /opt/rzans_vpn_main/backup

    # тэг для имени файла бэкапа: домен или IPv4 (безопасно убираем '[' и ':')
    local _tag="${SERVER_HOST#[[]}"
    _tag="${_tag%]}"
    _tag="${_tag//:/_}"
	BACKUP_FILE="/opt/rzans_vpn_main/backup-$_tag.tar.gz"
    TAR_ITEMS=(wireguard)
    [[ -d /opt/rzans_vpn_main/backup/config ]] && TAR_ITEMS+=(config)
    tar -czf "$BACKUP_FILE" -C /opt/rzans_vpn_main/backup "${TAR_ITEMS[@]}"
	tar -tzf "$BACKUP_FILE" > /dev/null

	rm -rf /opt/rzans_vpn_main/backup

	echo "Clients and config backup (re)created at $BACKUP_FILE"
}

is_port() { [[ $1 =~ ^[0-9]+$ ]] && (( 1 <= $1 && $1 <= 65535 )); }

# ── читаем и валидируем порты из settings.yaml ──────────────────────────────
SPLIT_PORT=$(yaml_get 'vpn.ports.split' 500);  is_port "$SPLIT_PORT" || SPLIT_PORT=500
FULL_PORT=$(yaml_get 'vpn.ports.full'  4500);  is_port "$FULL_PORT"  || FULL_PORT=4500
export SPLIT_PORT FULL_PORT

# --- подсети из settings.yaml ------------------------------------------------
SVPN_NET4=$(yaml_get 'vpn.nets.split' '10.29.8.0/24')
FVPN_NET4=$(yaml_get 'vpn.nets.full'  '10.28.8.0/24')
VPN_MAP_DST4=$(yaml_get 'vpn.map_dns' '10.30.0.0/15')

# адреса и DNS-IP считаем единым helper'ом
vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" \
  || { echo "Bad SVPN_NET4/FVPN_NET4: '$SVPN_NET4' / '$FVPN_NET4'"; exit 1; }

# сначала читаем IPS (если есть), и только затем формируем SVPN_ALLOWED
if [[ -f /etc/wireguard/ips ]]; then
  IPS=$(tr -s ' \n' ',' </etc/wireguard/ips | sed 's/^,//;s/,$//')
fi
SVPN_ALLOWED="${SVPN_NET4}, ${VPN_MAP_DST4}${IPS:+, ${IPS}}"

# ───── аргументы командной строки ──────────
OPTION=${1:-}
CLIENT_NAME=${2:-}

# Ленивая необходимость Endpoint host — нужен только для (1,4,5)
_needs_endpoint_host() { case "$OPTION" in 1|4|5) return 0;; *) return 1;; esac; }

if ! [[ "$OPTION" =~ ^[1-5]$ ]]; then
	echo
	echo 'Choose option:'
	echo '    1) Add client'
	echo '    2) Delete client'
	echo '    3) List clients'
	echo '    4) (Re)create clients profile files'
	echo '    5) (Re)create clients and config backup'
	until [[ "$OPTION" =~ ^[1-5]$ ]]; do
		read -rp 'Option choice [1-5]: ' -e OPTION
	done
fi

# Только для нужных опций вычисляем и печатаем SERVER_HOST (меньше «шума»)
if _needs_endpoint_host; then
  if ! SERVER_HOST="$(endpoint_host 30)"; then
    echo 'No server.domain and no global IPv4 detected' >&2
    exit 2
  fi
  echo "Using Endpoint host: ${SERVER_HOST}"
fi

case "$OPTION" in
	1)
		echo "Add client $CLIENT_NAME"
		askClientName
		initWireGuard
		addWireGuard
		;;
	2)
		echo "Delete client $CLIENT_NAME"
		listWireGuard
		askClientName
		deleteWireGuard
		;;
	3)
		echo 'List clients'
		listWireGuard
		;;
	4)
		echo '(Re)create clients profile files'
		recreate
		;;
	5)
		echo '(Re)create clients and config backup'
		backup
		;;
esac
