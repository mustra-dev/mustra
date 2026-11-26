# Switch network time on and synchronise against the configured server.
server=$(systemsetup -getnetworktimeserver 2>/dev/null | sed -n 's/^Network Time Server: //p')
[ -n "$server" ] || server=time.apple.com
systemsetup -setusingnetworktime on >/dev/null 2>&1 || echo "Could not switch network time on with systemsetup; synchronising once anyway."
echo "Synchronising against $server."
sntp -sS "$server" || exit 1
date
exit 0
