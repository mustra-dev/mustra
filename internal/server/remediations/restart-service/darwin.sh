# Restart one launchd system daemon by its label and confirm it is loaded.
name=${MUSTRA_PARAM_service:-}
case $name in
  ''|-*|*[!A-Za-z0-9_.-]*) echo "FAILED: give one launchd label, such as com.openssh.sshd." >&2; exit 2 ;;
esac
case $(printf '%s' "$name" | tr '[:upper:]' '[:lower:]') in
  dev.mustra.*|mustra*|beacon*) echo "REFUSED: $name belongs to the mustra agent; restarting it would end this job before it reports." >&2; exit 2 ;;
esac
if ! launchctl print "system/$name" >/dev/null 2>&1; then
  echo "FAILED: no system daemon with the label $name is loaded on this Mac." >&2
  exit 1
fi
echo "Restarting system/$name."
launchctl kickstart -k "system/$name" || exit 1
sleep 2
state=$(launchctl print "system/$name" 2>/dev/null | awk -F'= ' '/^[[:space:]]*state = / {print $2; exit}')
echo "system/$name is ${state:-loaded}."
exit 0
