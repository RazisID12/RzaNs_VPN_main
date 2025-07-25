# /opt/rzans_vpn_main/certbot-firewall.sh (новая мини-обёртка)
#!/bin/bash
case "$1" in
  pre)  /opt/rzans_vpn_main/up.sh open80  ;;  # открыть
  post) /opt/rzans_vpn_main/up.sh close80 ;;  # закрыть
  *)    echo "usage: $0 {pre|post}" >&2; exit 2 ;;
esac