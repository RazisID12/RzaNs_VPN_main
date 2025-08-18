#!/bin/bash
# doall.sh — единая точка вызова update / parse / custom-hooks
# согласовано с новыми setup.sh и update.sh

export LC_ALL=C
set -eEuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# при необходимости: DEBUG=1 doall.sh ip
if [[ "${DEBUG:-0}" == "1" ]]; then
  export PS4='+ $(date "+%F %T") [$$] ${BASH_SOURCE##*/}:${LINENO}: '
  set -x
fi

#────────────────────── traps ──────────────────────
on_err() { echo -e "\e[1;31mError at line $1: $2\e[0m"; exit 1; }
trap 'on_err $LINENO "$BASH_COMMAND"' ERR

#────────────────────── main ───────────────────────
SECONDS=0
cd /opt/rzans_vpn_main

ARGS=("$@")                     # поддержка любого числа аргументов

# один запуск update.sh достаточен: повтор удалён
./update.sh "${ARGS[@]}"

./parse.sh "${ARGS[@]}"

printf 'Execution time: %s seconds\n' "$SECONDS"