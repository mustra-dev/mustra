# Finish interrupted package installations. Never deletes a lock file and
# never removes a package: a lock held by a live process is a package
# operation that is still running, and breaking it corrupts the database
# this is meant to repair.
if ! command -v dpkg >/dev/null 2>&1; then
  echo "dpkg is not installed on this endpoint; nothing to recover."
  exit 0
fi
export DEBIAN_FRONTEND=noninteractive
wait=${MUSTRA_PARAM_wait_seconds:-600}
wait=${wait%%.*}
case $wait in ''|*[!0-9]*) echo "wait_seconds must be a whole number" >&2; exit 2 ;; esac

holders() {
  if command -v fuser >/dev/null 2>&1; then
    fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null | tr -s ' '
    return
  fi
  # Without fuser (psmisc), look for the package tools by process name;
  # /proc needs nothing installed.
  for p in /proc/[0-9]*; do
    read -r comm < "$p/comm" 2>/dev/null || continue
    case $comm in dpkg|apt|apt-get|aptitude|unattended-upgr*) printf '%s ' "${p#/proc/}" ;; esac
  done
}

waited=0
while :; do
  busy=$(holders | tr -d ' ')
  [ -z "$busy" ] && break
  if [ "$waited" -ge "$wait" ]; then
    echo "FAILED: another package operation is still running after ${waited}s (process $(holders)). Lock files are never removed; try again once it finishes." >&2
    exit 1
  fi
  [ "$waited" -eq 0 ] && echo "Another package operation is running; waiting up to ${wait}s for it to finish."
  sleep 10
  waited=$((waited + 10))
done

echo "== dpkg --audit (before)"
before=$(dpkg --audit 2>&1)
if [ -n "$before" ]; then echo "$before"; else echo "No problems reported."; fi

status=0
echo "== dpkg --configure -a"
dpkg --force-confdef --force-confold --configure -a || status=1

if [ "${MUSTRA_PARAM_fix_dependencies:-true}" = true ] && command -v apt-get >/dev/null 2>&1; then
  echo "== apt-get -f install --no-remove"
  apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    -o DPkg::Lock::Timeout=120 --no-remove -f install || status=1
fi

echo "== dpkg --audit (after)"
after=$(dpkg --audit 2>&1)
if [ -n "$after" ]; then
  echo "$after"
  status=1
else
  echo "No problems reported."
fi
[ "$status" -eq 0 ] || echo "FAILED: the package database still needs attention; see the output above."
exit $status
