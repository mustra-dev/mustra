# Free disk space: old temporary files, users' application caches and
# Homebrew's download cache. Nothing else is deleted.
days=${MUSTRA_PARAM_older_than_days:-7}
days=${days%%.*}
case $days in ''|*[!0-9]*) echo "older_than_days must be a whole number of days" >&2; exit 2 ;; esac
[ "$days" -ge 1 ] || days=1

free_kb() { df -Pk / | awk 'NR==2 {print $4}'; }
before=$(free_kb)

clean() {
  [ -d "$1" ] || return 0
  # Some application containers under ~/Library/Caches are protected by
  # privacy controls; those are skipped rather than reported as failures.
  n=$(find "$1" -xdev -type f -mtime +"$days" -atime +"$days" -print -delete 2>/dev/null | wc -l | tr -d ' ')
  echo "$1: removed $n file(s) older than $days day(s)"
}

clean /private/tmp
clean /private/var/tmp
for home in /Users/*; do
  [ -d "$home/Library/Caches" ] || continue
  case $home in /Users/Shared) continue ;; esac
  clean "$home/Library/Caches"
done

BREW=$(command -v brew || ls /opt/homebrew/bin/brew /usr/local/bin/brew 2>/dev/null | head -1)
if [ -n "$BREW" ]; then
  # Homebrew refuses to run as root; ask its owner where the cache is.
  OWNER=$(stat -f %Su "$(dirname "$(dirname "$BREW")")")
  CACHE=$(sudo -u "$OWNER" -H "$BREW" --cache 2>/dev/null)
  case $CACHE in
    /Users/*/Library/Caches/Homebrew|/Users/*/Library/Caches/Homebrew/) ;; # already covered above
    /*) clean "$CACHE" ;;
  esac
fi

after=$(free_kb)
awk -v b="$before" -v a="$after" 'BEGIN { printf "Free space on /: %.2f GB before, %.2f GB after (%.2f GB freed).\n", b/1048576, a/1048576, (a-b)/1048576 }'
exit 0
