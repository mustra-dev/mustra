# Cancel every queued CUPS job and restart CUPS.
if ! command -v cancel >/dev/null 2>&1 || ! command -v lpstat >/dev/null 2>&1; then
  echo "CUPS is not installed on this endpoint; nothing to clear."
  exit 0
fi
queued=$(lpstat -o 2>/dev/null | wc -l | tr -d ' ')
echo "Cancelling $queued queued job(s)."
cancel -a 2>/dev/null || echo "cancel -a reported an error (the scheduler may be stuck); restarting CUPS anyway."

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  unit=cups.service
  systemctl cat cups.service >/dev/null 2>&1 || unit=cupsd.service
  systemctl restart -- "$unit" || exit 1
  sleep 2
  systemctl is-active --quiet -- "$unit" || { echo "FAILED: $unit is not active after the restart."; exit 1; }
elif command -v service >/dev/null 2>&1; then
  service cups restart || service cupsd restart || exit 1
elif command -v rc-service >/dev/null 2>&1; then
  rc-service cupsd restart || exit 1
fi
echo "CUPS restarted; $(lpstat -o 2>/dev/null | wc -l | tr -d ' ') job(s) queued now."
exit 0
