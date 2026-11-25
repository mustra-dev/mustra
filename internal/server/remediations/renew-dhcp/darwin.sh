# Ask for the lease again on every active interface that holds one.
renewed=0
failed=0
for iface in $(ifconfig -lu); do
  case $iface in lo*|utun*|awdl*|llw*|bridge*|gif*|stf*|anpi*|ap*) continue ;; esac
  ipconfig getpacket "$iface" >/dev/null 2>&1 || continue
  if ipconfig set "$iface" DHCP; then
    echo "$iface: lease requested again"
    renewed=$((renewed + 1))
  else
    failed=$((failed + 1))
  fi
done
[ "$renewed" -gt 0 ] || [ "$failed" -gt 0 ] || echo "No active interface holds a DHCP lease; nothing to renew."
[ "$failed" -eq 0 ] || exit 1
exit 0
