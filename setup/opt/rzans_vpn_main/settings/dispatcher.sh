#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

BASE_DIR=${BASE_DIR:-/opt/rzans_vpn_main}
SET_SH="${BASE_DIR}/settings/settings.sh"
SETTINGS_YAML="${BASE_DIR}/settings.yaml"
STAMP_DIR="/var/lib/rzans_vpn_main/stamps"
mkdir -p "$STAMP_DIR"

. "$SET_SH"

sha() { sha256sum | awk '{print $1}'; }
changed() { local n="$1" v="$2" f="${STAMP_DIR}/${n}.sha"; [[ ! -s "$f" || "$(cat "$f")" != "$v" ]]; }

# --- DNS (только user-facing ключи) --------------------------------
H_DNS="$(yq e -o=json -I=0 '{up: .dns.upstream, dot: .dns.dot, port: .dns.port_tls}' "$SETTINGS_YAML" | sha)"

# --- Allow ---------------------------------------------------------
H_ALLOW="$(yq e -o=json -I=0 '.allowip' "$SETTINGS_YAML" | sha)"

# --- Services ------------------------------------------------------
H_SVC="$(yq e -o=json -I=0 '{fail2ban,adguard_home}' "$SETTINGS_YAML" | sha)"

# --- VPN topology (без портов и без server.port_ssh) --------------
H_VPN_TOPO="$(
  yq e -o=json -I=0 '{vpn,rollback_timeout,server,map_dns,snat}' "$SETTINGS_YAML" \
  | yq e -o=json -I=0 'del(.vpn.ports) | del(.server.port_ssh)' - | sha
)"

# --- Порты (отдельно) ----------------------------------------------
P_SSH="$(yq e -r '.server.port_ssh // 22'            "$SETTINGS_YAML")"
P_SPLIT="$(yq e -r '.vpn.ports.split // 500'         "$SETTINGS_YAML")"
P_FULL="$(yq e -r '.vpn.ports.full  // 4500'         "$SETTINGS_YAML")"

# DNS
if changed dns "$H_DNS"; then
  echo "[apply] .dns changed → apply_upstream"
  "$SET_SH" --apply-upstream || true
  echo "$H_DNS" >"${STAMP_DIR}/dns.sha"
fi

# Топология VPN — только тут зовём up.sh (до портов!)
if changed vpn_topo "$H_VPN_TOPO"; then
  echo "[apply] VPN topology changed → apply_vpn"
  "$SET_SH" --apply-vpn || true
  echo "$H_VPN_TOPO" >"${STAMP_DIR}/vpn_topo.sha"
fi

# Порты — точечно
if changed ssh_port "$P_SSH"; then
  echo "[apply] server.port_ssh changed → fw_sync_ssh_port"
  "$SET_SH" --sync-fw-ssh || true
  echo "$P_SSH" >"${STAMP_DIR}/ssh_port.sha"
fi
if changed vpn_port_split "$P_SPLIT" || changed vpn_port_full "$P_FULL"; then
  echo "[apply] vpn.ports.* changed → fw_sync_vpn_ports"
  "$SET_SH" --sync-fw-vpn-ports || true
  echo "$P_SPLIT" >"${STAMP_DIR}/vpn_port_split.sha"
  echo "$P_FULL"  >"${STAMP_DIR}/vpn_port_full.sha"
fi

# Allow
if changed allow "$H_ALLOW"; then
  echo "[apply] .allowip changed → apply_allow"
  "$SET_SH" --apply-allow || true
  echo "$H_ALLOW" >"${STAMP_DIR}/allow.sha"
fi

# Services
if changed services "$H_SVC"; then
  echo "[apply] services changed → apply_services"
  "$SET_SH" --apply-services || true
  echo "$H_SVC" >"${STAMP_DIR}/services.sha"
fi