# Clear the DNS Client service's cache.
& ipconfig.exe /flushdns
if ($LASTEXITCODE -ne 0) { "FAILED: ipconfig /flushdns exited with $LASTEXITCODE"; exit $LASTEXITCODE }
exit 0
