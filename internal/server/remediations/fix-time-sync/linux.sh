# Get the configured time service running and synchronise the clock now.
# The configured time servers are not changed.
running() { pgrep -x "$1" >/dev/null 2>&1 || pidof "$1" >/dev/null 2>&1; }
systemd=0
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && systemd=1

start_unit() {
  [ "$systemd" -eq 1 ] || return 1
  for u in "$@"; do
    systemctl cat -- "$u" >/dev/null 2>&1 || continue
    systemctl enable --now -- "$u" >/dev/null 2>&1 && return 0
  done
  return 1
}

if command -v chronyc >/dev/null 2>&1; then
  running chronyd || start_unit chronyd.service chrony.service || { echo "FAILED: chrony is installed but its daemon will not start." >&2; exit 1; }
  sleep 2
  chronyc -a 'burst 4/4' >/dev/null 2>&1
  sleep 10
  chronyc -a makestep || exit 1
  chronyc tracking
  exit 0
fi

if [ "$systemd" -eq 1 ] && systemctl cat systemd-timesyncd.service >/dev/null 2>&1; then
  timedatectl set-ntp true || exit 1
  systemctl restart systemd-timesyncd.service || exit 1
  sleep 5
  timedatectl timesync-status 2>/dev/null || timedatectl status
  [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ] || echo "Not synchronised yet; systemd-timesyncd keeps trying. Check again in a few minutes."
  exit 0
fi

if command -v ntpd >/dev/null 2>&1; then
  if [ "$systemd" -eq 1 ]; then
    systemctl restart ntp.service 2>/dev/null || systemctl restart ntpd.service || exit 1
  elif command -v service >/dev/null 2>&1; then
    service ntp restart 2>/dev/null || service ntpd restart || exit 1
  fi
  sleep 5
  command -v ntpq >/dev/null 2>&1 && ntpq -pn
  exit 0
fi

echo "FAILED: no time synchronisation service (chrony, systemd-timesyncd, ntpd) is installed on this endpoint." >&2
exit 1
