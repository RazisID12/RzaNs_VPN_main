#!/bin/bash
# chmod +x client.sh && ./client.sh [1-5] [имя_клиента]
#
set -eEuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

handle_error() {
    local os
    os="$(lsb_release -ds 2>/dev/null \
         || grep -oP '(?<=^PRETTY_NAME=).*' /etc/os-release | tr -d '\"')"
    echo "$os $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

export LC_ALL=C

# используем общие helpers из settings.sh (settings_get_tag, vpn_addrs_from_cidrs и т.п.)
. /opt/rzans_vpn_main/settings.sh

askClientName(){
	if ! [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
		echo
		echo 'Enter client name: 1–32 alphanumeric characters (a-z, A-Z, 0-9) with underscore (_) or dash (-)'
		until [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; do
			read -rp 'Client name: ' -e CLIENT_NAME
		done
	fi
}

# устанавливаем SERVER_HOST (домен или IP) для Endpoint-а и имени файла
setServerHost(){
    [[ -n "$1" ]] && SERVER_HOST="$1" || SERVER_HOST="$SERVER_IP"
}

render() {
	local IFS=''
	while read -r line; do
		while [[ "$line" =~ (\$\{[a-zA-Z_][a-zA-Z_0-9]*\}) ]]; do
			local LHS="${BASH_REMATCH[1]}"
			local RHS="$(eval echo "\"$LHS\"")"
			line="${line//$LHS/$RHS}"
		done
		echo "$line"
	done < "$1"
}

# ────────────────────────────────────────────────────────────────────
# AdGuard Home: регистрация VPN-клиентов в clients.persistent
#   $1 = IP‑адрес клиента
#   $2 = split | full                (по типу профиля)
#   $3 = ник (CLIENT_NAME из Amnezia)
# ────────────────────────────────────────────────────────────────────
add_agh_client() {
    local ip="$1" mode="$2" nick="$3" agh=/opt/AdGuardHome/AdGuardHome.yaml
    [[ -f $agh && -n $ip && -n $mode && -n $nick ]] || return 0

    local port uuid; [[ $mode == split ]] && port=5353 || port=5354
    uuid=$(uuidgen)

    yq eval \
      --arg ip   "$ip" \
      --arg nick "$nick" \
      --arg port "$port" \
      --arg uuid "$uuid" '.clients.persistent //= [] |
        (.clients.persistent[]? | select(.ids | index($ip))) as $c
        | if $c then
            ($c.name = $nick) |
            ($c.upstreams = ["127.0.0.1:" + $port])
          else
            .clients.persistent += [{
              name: $nick,
              ids: [$ip],
              upstreams: ["127.0.0.1:" + $port],
              uid: $uuid,
              use_global_settings: true
            }]
          end
' -i "$agh"

    systemctl restart AdGuardHome >/dev/null 2>&1 || true
}

# ────────────────────────────────────────────────────────────────────
# AdGuard Home: удаление клиента из clients.persistent
#   $1 = ник (CLIENT_NAME из Amnezia)
# ────────────────────────────────────────────────────────────────────
remove_agh_client() {
    local nick="$1" agh=/opt/AdGuardHome/AdGuardHome.yaml
    [[ -f $agh && -n $nick ]] || return 0

    yq eval --arg nick "$nick" '.clients.persistent |= map(select(.name != $nick))' \
      -i "$agh"

    systemctl restart AdGuardHome >/dev/null 2>&1 || true
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
    source /etc/wireguard/key

    # 2) Всегда убеждаемся, что оба серверных конфига присутствуют

    if [[ ! -f /etc/wireguard/rzans_svpn_main.conf ]]; then
        render "/etc/wireguard/templates/rzans_vpn_main.conf" > /tmp/svpn.tmp
        sed -i -E "s|^Address *=.*|Address = ${SVPN_ADDR}|"       /tmp/svpn.tmp
        mv /tmp/svpn.tmp /etc/wireguard/rzans_svpn_main.conf
    fi
    sed -i -E "s/^ListenPort *=.*/ListenPort = ${SPLIT_PORT}/"     /etc/wireguard/rzans_svpn_main.conf

    if [[ ! -f /etc/wireguard/rzans_fvpn_main.conf ]]; then
        render "/etc/wireguard/templates/rzans_vpn_main.conf" > /tmp/fvpn.tmp
        sed -i -E "s|^Address *=.*|Address = ${FVPN_ADDR}|"       /tmp/fvpn.tmp
        mv /tmp/fvpn.tmp /etc/wireguard/rzans_fvpn_main.conf
    fi
    sed -i -E "s/^ListenPort *=.*/ListenPort = ${FULL_PORT}/"      /etc/wireguard/rzans_fvpn_main.conf
}

addWireGuard(){
    setServerHost "$WIREGUARD_HOST"

    # --- синхронизируем ListenPort в конфиге при каждом вызове ---
    sed -i -E "s/^ListenPort *=.*/ListenPort = ${SPLIT_PORT}/" /etc/wireguard/rzans_svpn_main.conf
    sed -i -E "s/^ListenPort *=.*/ListenPort = ${FULL_PORT}/"  /etc/wireguard/rzans_fvpn_main.conf
    if systemctl is-active --quiet wg-quick@rzans_svpn_main; then
        wg syncconf rzans_svpn_main <(wg-quick strip rzans_svpn_main 2>/dev/null)
    fi
    if systemctl is-active --quiet wg-quick@rzans_fvpn_main; then
        wg syncconf rzans_fvpn_main <(wg-quick strip rzans_fvpn_main 2>/dev/null)
    fi
	echo

	source /etc/wireguard/key
    # файл /etc/wireguard/ips нужен не всегда: читаем безопасно
    [[ -f /etc/wireguard/ips ]] && IPS="$(cat /etc/wireguard/ips)" || IPS=""

	# RzaNs_sVPN_main

	CLIENT_BLOCK="$(sed -n "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/ {p; /^AllowedIPs/q}" /etc/wireguard/rzans_svpn_main.conf)"

	if [[ -n "$CLIENT_BLOCK" ]]; then
		CLIENT_PRIVATE_KEY="$(echo "$CLIENT_BLOCK" | grep '# PrivateKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PUBLIC_KEY="$(echo "$CLIENT_BLOCK" | grep 'PublicKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PRESHARED_KEY="$(echo "$CLIENT_BLOCK" | grep 'PresharedKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_IP="$(echo "$CLIENT_BLOCK" | grep 'AllowedIPs =' | cut -d '=' -f 2- | sed 's/ //g' | cut -d '/' -f 1)"
		echo 'Client (RzaNs_sVPN_main) with that name already exists! Please enter different name for new client'
	else
		CLIENT_PRIVATE_KEY="$(wg genkey)"
		CLIENT_PUBLIC_KEY="$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)"
		CLIENT_PRESHARED_KEY="$(wg genpsk)"
		BASE_CLIENT_IP="$(grep "^Address" /etc/wireguard/rzans_svpn_main.conf | sed 's/.*= *//' | tr -d ' ,' | cut -d'.' -f1-3 | head -n 1)"
		for i in {2..255}; do
			CLIENT_IP="${BASE_CLIENT_IP}.$i"
			if ! grep -q "$CLIENT_IP" /etc/wireguard/rzans_svpn_main.conf; then
				break
			fi
			if [[ $i == 255 ]]; then
				echo 'The WireGuard/AmneziaWG subnet can support only 253 clients!'
				exit 4
			fi
		done
		echo >> "/etc/wireguard/rzans_svpn_main.conf"
		echo "# Client = ${CLIENT_NAME}
# PrivateKey = ${CLIENT_PRIVATE_KEY}
[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
PresharedKey = ${CLIENT_PRESHARED_KEY}
AllowedIPs = ${CLIENT_IP}/32
" >> "/etc/wireguard/rzans_svpn_main.conf"
		if systemctl is-active --quiet wg-quick@rzans_svpn_main; then
			wg syncconf rzans_svpn_main <(wg-quick strip rzans_svpn_main 2>/dev/null)
		fi
	fi

    # гарантируем каталоги один раз
    install -d "/opt/rzans_vpn_main/client/rzans_svpn_main" "/opt/rzans_vpn_main/client/rzans_fvpn_main"
    SERVER_PORT=$SPLIT_PORT
    export SVPN_DNS_IP SVPN_ALLOWED
    SPLIT_FILE="/opt/rzans_vpn_main/client/rzans_svpn_main/RzaNs_sVPN_main-${CLIENT_NAME}-(${SERVER_HOST}).conf"
    render "/etc/wireguard/templates/rzans_svpn_main.conf" >"$SPLIT_FILE"
    chmod 600 "$SPLIT_FILE"

    # AGH persistent entry для Split-VPN
    add_agh_client "$CLIENT_IP" "split" "$CLIENT_NAME"

	# RzaNs_fVPN_main

	CLIENT_BLOCK="$(sed -n "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/ {p; /^AllowedIPs/q}" /etc/wireguard/rzans_fvpn_main.conf)"
	if [[ -n "$CLIENT_BLOCK" ]]; then
		CLIENT_PRIVATE_KEY="$(echo "$CLIENT_BLOCK" | grep '# PrivateKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PUBLIC_KEY="$(echo "$CLIENT_BLOCK" | grep 'PublicKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PRESHARED_KEY="$(echo "$CLIENT_BLOCK" | grep 'PresharedKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_IP="$(echo "$CLIENT_BLOCK" | grep 'AllowedIPs =' | cut -d '=' -f 2- | sed 's/ //g' | cut -d '/' -f 1)"
		echo 'Client (RzaNs_fVPN_main) with that name already exists! Please enter different name for new client'
	else
		CLIENT_PRIVATE_KEY="$(wg genkey)"
		CLIENT_PUBLIC_KEY="$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)"
		CLIENT_PRESHARED_KEY="$(wg genpsk)"
		BASE_CLIENT_IP="$(grep "^Address" /etc/wireguard/rzans_fvpn_main.conf | sed 's/.*= *//' | tr -d ' ,' | cut -d'.' -f1-3 | head -n 1)"
		for i in {2..255}; do
			CLIENT_IP="${BASE_CLIENT_IP}.$i"
			if ! grep -q "$CLIENT_IP" /etc/wireguard/rzans_fvpn_main.conf; then
				break
			fi
			if [[ $i == 255 ]]; then
				echo 'The WireGuard/AmneziaWG subnet can support only 253 clients!'
				exit 5
			fi
		done
		echo >> "/etc/wireguard/rzans_fvpn_main.conf"
		echo "# Client = ${CLIENT_NAME}
# PrivateKey = ${CLIENT_PRIVATE_KEY}
[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
PresharedKey = ${CLIENT_PRESHARED_KEY}
AllowedIPs = ${CLIENT_IP}/32
" >> "/etc/wireguard/rzans_fvpn_main.conf"
		if systemctl is-active --quiet wg-quick@rzans_fvpn_main; then
			wg syncconf rzans_fvpn_main <(wg-quick strip rzans_fvpn_main 2>/dev/null)
		fi
	fi

    SERVER_PORT=$FULL_PORT
    # экспортируем DNS IP для full-профиля (если используется в шаблоне)
    export FVPN_DNS_IP
    FULL_FILE="/opt/rzans_vpn_main/client/rzans_fvpn_main/RzaNs_fVPN_main-${CLIENT_NAME}-(${SERVER_HOST}).conf"
    render "/etc/wireguard/templates/rzans_fvpn_main.conf" >"$FULL_FILE"
    chmod 600 "$FULL_FILE"

    # AGH persistent entry для Full-VPN
    add_agh_client "$CLIENT_IP" "full" "$CLIENT_NAME"

    echo "Profiles (split & full) created in /opt/rzans_vpn_main/client/{rzans_svpn_main,rzans_fvpn_main}"
	echo
	echo 'If import fails, shorten filename to 32 chars (Windows) / 15 (Linux/Android/iOS), remove parentheses'
}

deleteWireGuard(){
    setServerHost "$WIREGUARD_HOST"
	echo

	if ! grep -q "# Client = ${CLIENT_NAME}" "/etc/wireguard/rzans_svpn_main.conf" && ! grep -q "# Client = ${CLIENT_NAME}" "/etc/wireguard/rzans_fvpn_main.conf"; then
		echo "Failed to delete client '$CLIENT_NAME'! Please check if client exists"
		exit 6
	fi

	sed -i "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/d" /etc/wireguard/rzans_svpn_main.conf
	sed -i "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/d" /etc/wireguard/rzans_fvpn_main.conf

	sed -i '/^$/N;/^\n$/D' /etc/wireguard/rzans_svpn_main.conf
	sed -i '/^$/N;/^\n$/D' /etc/wireguard/rzans_fvpn_main.conf

    rm -f "/opt/rzans_vpn_main/client/rzans_svpn_main/RzaNs_sVPN_main-${CLIENT_NAME}-(${SERVER_HOST}).conf" \
          "/opt/rzans_vpn_main/client/rzans_fvpn_main/RzaNs_fVPN_main-${CLIENT_NAME}-(${SERVER_HOST}).conf"

    # ── убираем запись клиента из AdGuard Home ─────────────────────
    remove_agh_client "$CLIENT_NAME"


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

    find /opt/rzans_vpn_main/client -type f -delete

	# AmneziaWG
    if [[ -f /etc/wireguard/key && -f /etc/wireguard/rzans_svpn_main.conf && -f /etc/wireguard/rzans_fvpn_main.conf ]]; then
        # Безопасно собираем список клиентов (может быть пустым)
        set +e
        CLIENTS_OUT=$(grep -hE '^# Client' \
            /etc/wireguard/rzans_svpn_main.conf \
            /etc/wireguard/rzans_fvpn_main.conf 2>/dev/null \
            | cut -d '=' -f 2- | sed 's/ //g' | sort -u || true)
        set -e
        if [[ -z "${CLIENTS_OUT:-}" ]]; then
            echo "No clients found — nothing to recreate."
        else
            # обойдём по строкам
            while IFS= read -r CLIENT_NAME; do
                [[ -z "$CLIENT_NAME" ]] && continue
                if [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
                    addWireGuard >/dev/null
                    echo "Profile files recreated for client '$CLIENT_NAME'"
                else
                    echo "Client name '$CLIENT_NAME' is invalid! No profile files recreated"
                fi
            done <<< "$CLIENTS_OUT"
        fi
	else
        CLIENT_NAME="client"
		echo "Creating server keys and first client: '$CLIENT_NAME'"
		initWireGuard
		addWireGuard >/dev/null
	fi
}

backup(){
	echo

	rm -rf /opt/rzans_vpn_main/backup
	mkdir -p /opt/rzans_vpn_main/backup/wireguard

	cp -r /etc/wireguard/rzans_svpn_main.conf /opt/rzans_vpn_main/backup/wireguard
	cp -r /etc/wireguard/rzans_fvpn_main.conf /opt/rzans_vpn_main/backup/wireguard
	cp -r /etc/wireguard/key /opt/rzans_vpn_main/backup/wireguard
	cp -r /opt/rzans_vpn_main/config /opt/rzans_vpn_main/backup

	BACKUP_FILE="/opt/rzans_vpn_main/backup-$SERVER_IP.tar.gz"
	tar -czf "$BACKUP_FILE" -C /opt/rzans_vpn_main/backup wireguard config
	tar -tzf "$BACKUP_FILE" > /dev/null

	rm -rf /opt/rzans_vpn_main/backup

	echo "Clients and config backup (re)created at $BACKUP_FILE"
}

is_port() { [[ $1 =~ ^[0-9]+$ ]] && (( 1 <= $1 && $1 <= 65535 )); }

# ── читаем и валидируем порты из settings.map ───────────────────────────────
# --- порты из settings.map ---------------------------------------------------
SPLIT_PORT=$(settings_get_tag SVPN_PORT 500);  is_port "$SPLIT_PORT" || SPLIT_PORT=500
FULL_PORT=$(settings_get_tag FVPN_PORT 4500);  is_port "$FULL_PORT"  || FULL_PORT=4500
export SPLIT_PORT FULL_PORT            # render() будет подставлять ${SPLIT_PORT} в шаблоны

# --- подсети из settings.map -------------------------------------------------
SVPN_NET4=$(settings_get_tag SVPN_NET4 "10.29.8.0/24")
FVPN_NET4=$(settings_get_tag FVPN_NET4 "10.28.8.0/24")
VPN_MAP_DST4=$(settings_get_tag VPN_MAP_DST4 "10.30.0.0/15")

# адреса и DNS‑IP считаем единым helper'ом
vpn_addrs_from_cidrs "$SVPN_NET4" "$FVPN_NET4" \
  || { echo "Bad SVPN_NET4/FVPN_NET4: '$SVPN_NET4' / '$FVPN_NET4'"; exit 1; }

# список, пригодный для AllowedIPs в шаблоне (IPS может быть пустым)
SVPN_ALLOWED="${SVPN_NET4}, ${VPN_MAP_DST4}${IPS:+, ${IPS}}"
# --- выбираем адрес/домен сервера для Endpoint ------------------------------
# 1) WIREGUARD_HOST из settings.map (если задан и непустой)
# 2) EXTIP4, если задан явный IP (≠ 0.0.0.0)
# 3) авто-детект первого глобального IPv4

WIREGUARD_HOST=$(settings_get_tag WIREGUARD_HOST "")
EXTIP4_RAW=$(settings_get_tag EXTIP4 "0.0.0.0" | awk '{print $1}')  # отбрасываем комментарий

valid_ip4() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

if [[ -n "$WIREGUARD_HOST" && "$WIREGUARD_HOST" != '""' ]]; then
  SERVER_HOST=${WIREGUARD_HOST//\"/}
elif [[ "$EXTIP4_RAW" != "0.0.0.0" ]] && valid_ip4 "$EXTIP4_RAW"; then
  SERVER_HOST=$EXTIP4_RAW
else
  SERVER_HOST=$(ip -o -4 addr show scope global \
                | awk '{print $4}' | cut -d/ -f1 | head -1)
  [[ -z "$SERVER_HOST" ]] && { echo 'Global IPv4 not found'; exit 2; }
fi

# для функций backup() / setServerHost
SERVER_IP=$SERVER_HOST

OPTION=${1:-}
CLIENT_NAME=${2:-}

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
