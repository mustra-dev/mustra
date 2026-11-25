# Clear the directory-services cache and mDNSResponder's DNS cache.
dscacheutil -flushcache || exit 1
killall -HUP mDNSResponder || exit 1
echo "DNS cache flushed."
exit 0
