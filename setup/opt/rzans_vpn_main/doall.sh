#!/bin/bash
# doall.sh — единая точка вызова update / parse / custom-hooks
# согласовано с новыми setup.sh и update.sh

set -eEuo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 027

# DEBUG=1 ./doall.sh [args...]
if [[ "${DEBUG:-0}" == "1" ]]; then
  export PS4='+ $(date "+%F %T") [$$] ${BASH_SOURCE##*/}:${LINENO}: '
  set -x
fi

BASE_DIR=${BASE_DIR:-/opt/rzans_vpn_main}
cd "$BASE_DIR"

# ── анти double-run lock для doall (отдельно от update/parse) ──────────────
DOALL_LOCK="/run/lock/rzans_doall.lock"
install -d "$(dirname "$DOALL_LOCK")"
exec 9>"$DOALL_LOCK" || { echo "Cannot open lock file $DOALL_LOCK"; exit 1; }
if ! flock -n 9; then
  echo "doall already running (see $DOALL_LOCK) — exit."
  exit 0
fi
# Закроем лок в самом конце
_cleanup() { exec 9>&-; }
trap '_cleanup' EXIT

# ── обработчик ошибок (красиво и беззвучно) ─────────────────────────────────
on_err() {
  echo -e "\e[1;31mError at line $1: $2\e[0m"
  exit 1
}
trap 'on_err $LINENO "$BASH_COMMAND"' ERR

# ── main ────────────────────────────────────────────────────────────────────
SECONDS=0
ARGS=("$@")   # поддержка любого числа аргументов

echo "[doall] update.sh ${ARGS[*]:-}"
./update.sh "${ARGS[@]}"

echo "[doall] parse.sh  ${ARGS[*]:-}"
./parse.sh "${ARGS[@]}"

printf '[doall] Execution time: %s seconds\n' "$SECONDS"