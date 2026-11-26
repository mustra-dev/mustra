# Flush whichever local DNS caches are running. Most Linux systems without
# one of these do not cache DNS at all, which is not a failure.
running() { pgrep -x "$1" >/dev/null 2>&1 || pidof "$1" >/dev/null 2>&1; }
flushed=0
status=0

if command -v resolvectl >/dev/null 2>&1 && running systemd-resolved; then
  if resolvectl flush-caches; then echo "systemd-resolved: cache flushed"; flushed=1; else status=1; fi
elif command -v systemd-resolve >/dev/null 2>&1 && running systemd-resolved; then
  if systemd-resolve --flush-caches; then echo "systemd-resolved: cache flushed"; flushed=1; else status=1; fi
fi
if command -v nscd >/dev/null 2>&1 && running nscd; then
  if nscd -i hosts; then echo "nscd: hosts cache invalidated"; flushed=1; else status=1; fi
fi
if running dnsmasq; then
  # SIGHUP makes dnsmasq clear its cache (and re-read its hosts files).
  if pkill -HUP -x dnsmasq 2>/dev/null || killall -HUP dnsmasq 2>/dev/null; then echo "dnsmasq: cache cleared"; flushed=1; else status=1; fi
fi

[ "$flushed" -eq 1 ] || [ "$status" -ne 0 ] || echo "No local DNS cache (systemd-resolved, nscd, dnsmasq) is running on this endpoint; nothing to flush."
exit $status
