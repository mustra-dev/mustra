# Cancel every queued job and restart cupsd.
queued=$(lpstat -o 2>/dev/null | wc -l | tr -d ' ')
echo "Cancelling $queued queued job(s)."
cancel -a 2>/dev/null || echo "cancel -a reported an error (the scheduler may be stuck); restarting cupsd anyway."
launchctl kickstart -k system/org.cups.cupsd || exit 1
sleep 2
echo "cupsd restarted; $(lpstat -o 2>/dev/null | wc -l | tr -d ' ') job(s) queued now."
exit 0
