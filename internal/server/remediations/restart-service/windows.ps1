# Restart one named service and confirm it is running again.
$ErrorActionPreference = 'Stop'
$name = "$env:MUSTRA_PARAM_service".Trim()

# Get-Service treats * ? [ ] as wildcards; one name means one service.
if ($name -eq '' -or $name.Length -gt 256 -or $name -match '[\*\?\[\]]') {
  "FAILED: give one service name, without wildcard characters."; exit 2
}
if ($name -match '^(mustra|beacon)') {
  "REFUSED: $name is the mustra agent's own service; restarting it would end this job before it reports."; exit 2
}

$svc = Get-Service -Name $name -ErrorAction SilentlyContinue
if (-not $svc) { $svc = Get-Service -DisplayName $name -ErrorAction SilentlyContinue }
if (-not $svc) { "FAILED: there is no service named '$name' on this endpoint."; exit 1 }
if (@($svc).Count -ne 1) { "FAILED: '$name' matches more than one service."; exit 1 }
if ($svc.Name -match '^(mustra|beacon)') { "REFUSED: that is the mustra agent's own service."; exit 2 }
if ($svc.StartType -eq 'Disabled') { "REFUSED: $($svc.Name) is disabled; this remediation does not start disabled services."; exit 1 }

$dependents = @($svc.DependentServices | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
"Restarting $($svc.Name) ($($svc.DisplayName)); it was $($svc.Status)."
try {
  Restart-Service -InputObject $svc -Force -ErrorAction Stop
  $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(120))
} catch {
  "FAILED: $($_.Exception.Message)"
  exit 1
}
foreach ($d in $dependents) {
  $ds = Get-Service -Name $d
  if ($ds.Status -ne 'Running') {
    try { Start-Service -Name $d -ErrorAction Stop; "Started dependent service $d again." } catch { "WARNING: dependent service $d did not start: $($_.Exception.Message)" }
  }
}
$svc.Refresh()
"$($svc.Name) is $($svc.Status)."
if ($svc.Status -ne 'Running') { exit 1 }
exit 0
