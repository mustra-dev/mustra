# Free disk space: package-manager download caches and old temporary files.
# Nothing outside /tmp, /var/tmp and the package caches is deleted.
days=${MUSTRA_PARAM_older_than_days:-7}
days=${days%%.*}
case $days in ''|*[!0-9]*) echo "older_than_days must be a whole number of days" >&2; exit 2 ;; esac
[ "$days" -ge 1 ] || days=1

free_kb() { df -Pk / | awk 'NR==2 {print $4}'; }
before=$(free_kb)
status=0

if command -v apt-get >/dev/null 2>&1; then
  echo "apt: emptying the downloaded package cache"
  apt-get clean || { echo "apt-get clean failed (is another package operation running?)"; status=1; }
fi
if command -v dnf >/dev/null 2>&1; then
  echo "dnf: removing cached packages"
  dnf -q clean packages || status=1
elif command -v yum >/dev/null 2>&1; then
  echo "yum: removing cached packages"
  yum -q clean packages || status=1
fi
if command -v zypper >/dev/null 2>&1; then
  echo "zypper: removing cached packages"
  zypper --non-interactive --quiet clean || status=1
fi

# Neither modified nor read for the whole period. -xdev keeps to each
# directory's own file system. Services' private temp directories and lock
# files that live for a whole session are excluded even when old.
for dir in /tmp /var/tmp; do
  [ -d "$dir" ] || continue
  n=$(find "$dir" -xdev -type f -mtime +"$days" -atime +"$days" \
        ! -path '*/systemd-private-*' ! -path '/tmp/snap-private-tmp/*' \
        ! -path '/tmp/.X11-unix/*' ! -name '.X*-lock' \
        -print -delete 2>/dev/null | wc -l)
  echo "$dir: removed $n file(s) older than $days day(s)"
done

after=$(free_kb)
awk -v b="$before" -v a="$after" 'BEGIN { printf "Free space on /: %.2f GB before, %.2f GB after (%.2f GB freed).\n", b/1048576, a/1048576, (a-b)/1048576 }'
exit $status
