#!/bin/bash
# doall.sh — единая точка вызова update / parse / custom-hooks
# согласовано с новыми setup.sh и update.sh

export LC_ALL=C
set -eEuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

#────────────────────── traps ──────────────────────
on_err() { echo -e "\e[1;31mError at line $1: $2\e[0m"; exit 1; }
trap 'on_err $LINENO "$BASH_COMMAND"' ERR

#────────────────────── main ───────────────────────
SECONDS=0
cd /opt/rzans_vpn_main

ARGS=("$@")                     # поддержка любого числа аргументов

hash_before=$(sha256sum update.sh | awk '{print $1}')
./update.sh "${ARGS[@]}"
hash_after=$(sha256sum update.sh | awk '{print $1}')

if [[ $hash_before != "$hash_after" ]]; then
  echo 'update.sh has been updated — запускаю заново'
  ./update.sh "${ARGS[@]}"
fi

./parse.sh "${ARGS[@]}"

printf 'Execution time: %s seconds\n' "$SECONDS"