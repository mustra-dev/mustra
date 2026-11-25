# Make sure the Windows Time service runs, then re-synchronise against the
# sources it is already configured with. Configuration is not changed.
$svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
if (-not $svc) { 'FAILED: the Windows Time service is missing on this endpoint.'; exit 1 }
if ($svc.StartType -eq 'Disabled') {
  'REFUSED: the Windows Time service is disabled, usually by policy (for example on a virtual machine that takes its time from the host). Not overriding it.'
  exit 1
}
if ($svc.Status -ne 'Running') {
  'Starting the Windows Time service.'
  try { Start-Service -Name W32Time -ErrorAction Stop; $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(60)) }
  catch { "FAILED: $($_.Exception.Message)"; exit 1 }
}

& w32tm.exe /resync /force
$code = $LASTEXITCODE
if ($code -ne 0) {
  'No time source answered; re-reading the configuration and rediscovering sources.'
  & w32tm.exe /config /update
  & w32tm.exe /resync /rediscover
  $code = $LASTEXITCODE
}
& w32tm.exe /query /status
if ($code -ne 0) { "FAILED: w32tm could not synchronise (exit $code). Check that a time source is reachable."; exit 1 }
'The clock is synchronised.'
exit 0
