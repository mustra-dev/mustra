# Erase and rebuild the Spotlight index of the startup volume.
status=$(mdutil -s / 2>&1)
echo "$status"
case $status in
  *"disabled"*) echo "Spotlight indexing is turned off for /; leaving it off."; exit 0 ;;
esac
mdutil -E / || exit 1
echo "Spotlight is rebuilding its index; results are incomplete until it finishes."
exit 0
