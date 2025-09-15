#!/usr/bin/env bash
# RZANS emergency fallback helper
# - централизует постановку/снятие «аварийки»
# - планирует отложенный запуск через transient unit (systemd-run)
# - хранит токены в ${RUN_DIR}/fallback.<runid>
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -eEuo pipefail

# === CORE PATHS & SETTINGS ====================================================
BASE_DIR="/opt/rzans_vpn_main"
RUN_DIR="/run/rzans_vpn_main"
UNIT_PREFIX="firewall_fallback"
SETTINGS_SH="${BASE_DIR}/settings/settings.sh"
. "${SETTINGS_SH}"

# === STATE / CONFIG DIRS & FILES =============================================
IPSET_STATE_DIR="${IPSET_STATE_DIR:-/var/lib/ipset}"
mkdir -p "$RUN_DIR" "$IPSET_STATE_DIR"
IPSET_BAN_STATE="${IPSET_BAN_STATE:-${IPSET_STATE_DIR}/ipset-bans.rules}"

# Безопасное удаление всех токенов (устраняет проблемы с «глобами» и поведением nullglob)
_rm_all_tokens() {
  local toks=()
  shopt -s nullglob
  toks=("$RUN_DIR"/fallback.*)
  shopt -u nullglob
  [[ ${#toks[@]} -gt 0 ]] && rm -f -- "${toks[@]}"
}

IPT_BIN=$(command -v iptables-nft || command -v iptables || true)
IP6T_BIN=$(command -v ip6tables-nft || command -v ip6tables || true)
[[ -x "$IPT_BIN" ]] || { echo "iptables backend not found" >&2; exit 1; }
ipt()  { "$IPT_BIN"  -w "$@"; }
HAS_IP6=n; [[ -x "$IP6T_BIN" ]] && HAS_IP6=y
ipt6() { if [[ $HAS_IP6 == y ]]; then "$IP6T_BIN" -w "$@"; else return 0; fi; }

read_settings() {
  SSH_PORT="$(yaml_get_port 'server.port_ssh' 22)"
  SVPN_PORT="$(yaml_get_port 'vpn.ports.split' 500)"
  FVPN_PORT="$(yaml_get_port 'vpn.ports.full'  4500)"
}

ensure_fallback_chains() {
  ipt  -t filter -N RZANS_FALLBACK   2>/dev/null || true
  ipt  -t filter -F RZANS_FALLBACK
  ipt  -t filter -C INPUT -j RZANS_FALLBACK 2>/dev/null || ipt  -t filter -I INPUT 1 -j RZANS_FALLBACK
  ipt  -t filter -N RZANS_FALLBACK_FWD 2>/dev/null || true
  ipt  -t filter -F RZANS_FALLBACK_FWD
  ipt  -t filter -C FORWARD -j RZANS_FALLBACK_FWD 2>/dev/null || ipt  -t filter -I FORWARD 1 -j RZANS_FALLBACK_FWD
  if [[ "$HAS_IP6" == y ]]; then
    ipt6 -t filter -N RZANS_FALLBACK6 2>/dev/null || true
    ipt6 -t filter -F RZANS_FALLBACK6
    ipt6 -t filter -C INPUT -j RZANS_FALLBACK6 2>/dev/null || ipt6 -t filter -I INPUT 1 -j RZANS_FALLBACK6
    ipt6 -t filter -N RZANS_FALLBACK6_FWD 2>/dev/null || true
    ipt6 -t filter -F RZANS_FALLBACK6_FWD
    ipt6 -t filter -C FORWARD -j RZANS_FALLBACK6_FWD 2>/dev/null || ipt6 -t filter -I FORWARD 1 -j RZANS_FALLBACK6_FWD
  fi
}

apply_rules() {
  read_settings
  logger -t rzans_fallback "apply emergency rules"
  ensure_fallback_chains
  # v4
  ipt  -t filter -A RZANS_FALLBACK -i lo -m comment --comment RZANS_FALLBACK -j ACCEPT
  ipt  -t filter -A RZANS_FALLBACK -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment RZANS_FALLBACK -j ACCEPT
  ipt  -t filter -A RZANS_FALLBACK -p tcp --dport "$SSH_PORT" -m comment --comment RZANS_FALLBACK -j ACCEPT
  ipt  -t filter -A RZANS_FALLBACK -p udp --dport "$SVPN_PORT" -m comment --comment RZANS_FALLBACK -j ACCEPT
  ipt  -t filter -A RZANS_FALLBACK -p udp --dport "$FVPN_PORT" -m comment --comment RZANS_FALLBACK -j ACCEPT
  if command -v ipset >/dev/null 2>&1 && [[ -s "$IPSET_BAN_STATE" ]]; then
    ipset flush ipset-block   2>/dev/null || true
    ipset flush ipset-block6  2>/dev/null || true
    ipset restore -exist < "$IPSET_BAN_STATE" || true
    ipt  -t filter -I RZANS_FALLBACK 1 -m set --match-set ipset-block src -m comment --comment RZANS_FALLBACK -j DROP || true
  fi
  ipt  -t filter -A RZANS_FALLBACK -m comment --comment RZANS_FALLBACK -j DROP
  ipt  -t filter -A RZANS_FALLBACK_FWD -m conntrack --ctstate INVALID -m comment --comment RZANS_FALLBACK -j DROP
  ipt  -t filter -A RZANS_FALLBACK_FWD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment RZANS_FALLBACK -j ACCEPT
  ipt  -t filter -A RZANS_FALLBACK_FWD -m comment --comment RZANS_FALLBACK -j DROP
  # v6
  if [[ "$HAS_IP6" == y ]]; then
    ipt6 -t filter -A RZANS_FALLBACK6 -i lo -m comment --comment RZANS_FALLBACK -j ACCEPT
    ipt6 -t filter -A RZANS_FALLBACK6 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment RZANS_FALLBACK -j ACCEPT
    ipt6 -t filter -A RZANS_FALLBACK6 -p icmpv6 -m comment --comment RZANS_FALLBACK -j ACCEPT
    ipt6 -t filter -A RZANS_FALLBACK6 -p tcp --dport "$SSH_PORT" -m comment --comment RZANS_FALLBACK -j ACCEPT
    ipt6 -t filter -A RZANS_FALLBACK6 -m comment --comment RZANS_FALLBACK -j DROP
    if command -v ipset >/dev/null 2>&1; then
      ipset list ipset-block6 >/dev/null 2>&1 && \
        ipt6 -t filter -I RZANS_FALLBACK6 1 -m set --match-set ipset-block6 src -m comment --comment RZANS_FALLBACK -j DROP || true
    fi
    ipt6 -t filter -A RZANS_FALLBACK6_FWD -m conntrack --ctstate INVALID -m comment --comment RZANS_FALLBACK -j DROP
    ipt6 -t filter -A RZANS_FALLBACK6_FWD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment RZANS_FALLBACK -j ACCEPT
    ipt6 -t filter -A RZANS_FALLBACK6_FWD -m comment --comment RZANS_FALLBACK -j DROP
  fi
}

cleanup_rules() {
  # снять прыжки INPUT/FORWARD→RZANS_FALLBACK{,6}{,_FWD} и удалить наши цепочки
  ipt  -t filter -S INPUT | awk '$0 ~ /-A INPUT .* -j RZANS_FALLBACK($| )/ {sub(/^-A INPUT /,""); print}' \
    | while read -r -a SPEC; do ipt -t filter -D INPUT "${SPEC[@]}" 2>/dev/null || true; done
  ipt  -t filter -S FORWARD | awk '$0 ~ /-A FORWARD .* -j RZANS_FALLBACK_FWD($| )/ {sub(/^-A FORWARD /,""); print}' \
    | while read -r -a SPEC; do ipt -t filter -D FORWARD "${SPEC[@]}" 2>/dev/null || true; done
  ipt  -t filter -F RZANS_FALLBACK 2>/dev/null || true
  ipt  -t filter -X RZANS_FALLBACK 2>/dev/null || true
  ipt  -t filter -F RZANS_FALLBACK_FWD 2>/dev/null || true
  ipt  -t filter -X RZANS_FALLBACK_FWD 2>/dev/null || true
  if [[ "$HAS_IP6" == y ]]; then
    ipt6 -t filter -S INPUT | awk '$0 ~ /-A INPUT .* -j RZANS_FALLBACK6($| )/ {sub(/^-A INPUT /,""); print}' \
      | while read -r -a SPEC; do ipt6 -t filter -D INPUT "${SPEC[@]}" 2>/dev/null || true; done
    ipt6 -t filter -S FORWARD | awk '$0 ~ /-A FORWARD .* -j RZANS_FALLBACK6_FWD($| )/ {sub(/^-A FORWARD /,""); print}' \
      | while read -r -a SPEC; do ipt6 -t filter -D FORWARD "${SPEC[@]}" 2>/dev/null || true; done
    ipt6 -t filter -F RZANS_FALLBACK6 2>/dev/null || true
    ipt6 -t filter -X RZANS_FALLBACK6 2>/dev/null || true
    ipt6 -t filter -F RZANS_FALLBACK6_FWD 2>/dev/null || true
    ipt6 -t filter -X RZANS_FALLBACK6_FWD 2>/dev/null || true
  fi
}

cmd_preclean() {
  # стопим все наши transient units и чистим токены + failed-состояния
  if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --all --type=timer   "${UNIT_PREFIX}@*.timer"   --no-legend 2>/dev/null | awk '{print $1}' \
      | while read -r u; do [[ -n "$u" ]] && systemctl stop "$u" 2>/dev/null || true; done
    systemctl list-units --all --type=service "${UNIT_PREFIX}@*.service" --no-legend 2>/dev/null | awk '{print $1}' \
      | while read -r u; do [[ -n "$u" ]] && systemctl stop "$u" 2>/dev/null || true; done
    systemctl reset-failed "${UNIT_PREFIX}@*.service" >/dev/null 2>&1 || true
  fi
  _rm_all_tokens
  # на всякий случай снимем и правила аварийки
  cleanup_rules || true
}

cmd_schedule() {
  local delay="${1:-7m}"
  mkdir -p "$RUN_DIR"
  local run_id; run_id="$(date +%s).$$"
  local token="$RUN_DIR/fallback.${run_id}"
  : >"$token"
  if ! command -v systemd-run >/dev/null 2>&1; then
    echo "⚠ systemd-run not found — cannot schedule, only immediate apply available" >&2
    return 0
  fi
  # создаём transient-таймер, который по истечении delay запустит сервис «аварийки» при наличии токена
  systemd-run --unit="${UNIT_PREFIX}@${run_id}" --on-active="${delay}" --collect \
    -p Type=oneshot -p NoNewPrivileges=yes -p RuntimeMaxSec=180 \
    /bin/bash -lc "set -euo pipefail; T='${token}'; [[ -f \"\$T\" ]] || exit 0; logger -t rzans_fallback 'trigger fired'; systemctl start firewall_fallback.service"
  echo "scheduled: unit=${UNIT_PREFIX}@${run_id} token=${token}"
}

cmd_cancel() {
  # отмена конкретного run_id или всех
  local rid="${1:-}"
  if command -v systemctl >/dev/null 2>&1; then
    if [[ -n "$rid" ]]; then
      systemctl stop "${UNIT_PREFIX}@${rid}.timer"   2>/dev/null || true
      systemctl stop "${UNIT_PREFIX}@${rid}.service" 2>/dev/null || true
    else
      systemctl list-units --all --type=timer   "${UNIT_PREFIX}@*.timer"   --no-legend 2>/dev/null | awk '{print $1}' \
        | while read -r u; do [[ -n "$u" ]] && systemctl stop "$u" 2>/dev/null || true; done
      systemctl list-units --all --type=service "${UNIT_PREFIX}@*.service" --no-legend 2>/dev/null | awk '{print $1}' \
        | while read -r u; do [[ -n "$u" ]] && systemctl stop "$u" 2>/dev/null || true; done
    fi
    systemctl reset-failed "${UNIT_PREFIX}@*.service" >/dev/null 2>&1 || true
  fi
  if [[ -n "$rid" ]]; then
    rm -f -- "$RUN_DIR/fallback.${rid}" 2>/dev/null || true
  else
    _rm_all_tokens
  fi
}

case "${1:-}" in
  apply)
    apply_rules
    ;;
  cleanup)
    cleanup_rules
    ;;
  preclean)
    cmd_preclean
    ;;
  schedule)
    shift
    cmd_schedule "${1:-7m}"
    ;;
  cancel)
    shift
    cmd_cancel "${1:-}"
    ;;
  status)
    systemctl status "${UNIT_PREFIX}@*.service" 2>/dev/null || true
    ;;
  *)
    echo "Usage: $0 {apply|cleanup|preclean|schedule [DELAY]|cancel [RUN_ID]|status}" >&2
    exit 1
    ;;
esac
