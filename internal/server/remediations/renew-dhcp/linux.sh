# Renew the DHCP lease through whichever network manager owns the
# interfaces. Nothing here releases an address first.
running() { pgrep -x "$1" >/dev/null 2>&1 || pidof "$1" >/dev/null 2>&1; }
renewed=0
failed=0
handled=0

if command -v networkctl >/dev/null 2>&1 && running systemd-networkd; then
  handled=1
  for link in $(networkctl list --no-legend 2>/dev/null | awk '$5 == "configured" && $2 != "lo" {print $2}'); do
    # A link without a DHCP client refuses the renew; that is not a failure.
    if networkctl status -- "$link" 2>/dev/null | grep -q 'DHCP4'; then
      if networkctl renew -- "$link"; then echo "$link: lease renewed (systemd-networkd)"; renewed=$((renewed + 1)); else failed=$((failed + 1)); fi
    fi
  done
fi

if command -v nmcli >/dev/null 2>&1 && nmcli -t -f RUNNING general 2>/dev/null | grep -q '^running'; then
  handled=1
  devices=$(nmcli -t -f DEVICE,TYPE,STATE device 2>/dev/null | awk -F: '($2 == "ethernet" || $2 == "wifi") && $3 == "connected" {print $1}')
  for dev in $devices; do
    if nmcli -t -f DHCP4 device show "$dev" 2>/dev/null | grep -q '^DHCP4'; then
      if nmcli device connect "$dev" >/dev/null; then echo "$dev: connection re-activated, lease requested (NetworkManager)"; renewed=$((renewed + 1)); else failed=$((failed + 1)); fi
    fi
  done
fi

if command -v dhcpcd >/dev/null 2>&1 && running dhcpcd; then
  handled=1
  if dhcpcd --renew; then echo "dhcpcd: leases renewed"; renewed=$((renewed + 1)); else failed=$((failed + 1)); fi
fi

if [ "$handled" -eq 0 ]; then
  if running dhclient; then
    echo "FAILED: the interfaces are managed by dhclient, which cannot renew without releasing the address first; renew from the console of the endpoint instead." >&2
    exit 1
  fi
  echo "No DHCP client is running on this endpoint (its addresses are likely fixed); nothing to renew."
  exit 0
fi
[ "$renewed" -gt 0 ] || [ "$failed" -gt 0 ] || echo "No interface holds a DHCP lease; nothing to renew."
[ "$failed" -eq 0 ] || exit 1
exit 0
