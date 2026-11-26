# Restart one named service and confirm it is running again.
name=${MUSTRA_PARAM_service:-}
case $name in
  ''|-*|*[!A-Za-z0-9_.@:-]*) echo "FAILED: give one service name (letters, digits and _ . @ : - only)." >&2; exit 2 ;;
esac
case $(printf '%s' "$name" | tr '[:upper:]' '[:lower:]') in
  mustra*|beacon*) echo "REFUSED: $name is the mustra agent's own service; restarting it would end this job before it reports." >&2; exit 2 ;;
esac

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  unit=$name
  case $unit in *.*) ;; *) unit=$unit.service ;; esac
  load=$(systemctl show -p LoadState -- "$unit" 2>/dev/null | sed 's/^LoadState=//')
  case $load in
    loaded) ;;
    masked) echo "REFUSED: $unit is masked; this remediation does not unmask services." >&2; exit 1 ;;
    *) echo "FAILED: there is no unit named $unit on this endpoint." >&2; exit 1 ;;
  esac
  echo "Restarting $unit (it was $(systemctl is-active -- "$unit" 2>/dev/null))."
  if ! systemctl restart -- "$unit"; then
    systemctl status --no-pager -l -- "$unit" 2>&1 | head -n 20
    exit 1
  fi
  sleep 2
  if systemctl is-active --quiet -- "$unit"; then echo "$unit is active."; exit 0; fi
  echo "FAILED: $unit is $(systemctl is-active -- "$unit") after the restart."
  systemctl status --no-pager -l -- "$unit" 2>&1 | head -n 20
  exit 1
fi

if command -v rc-service >/dev/null 2>&1; then
  rc-service "$name" restart || exit 1
  rc-service "$name" status
  exit $?
fi
if command -v service >/dev/null 2>&1; then
  service "$name" restart || exit 1
  service "$name" status
  exit $?
fi
echo "FAILED: no service manager (systemd, OpenRC, service) found on this endpoint." >&2
exit 1
