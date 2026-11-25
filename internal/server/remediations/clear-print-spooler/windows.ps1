# Stop the spooler, remove the queued job files, start it again.
$ErrorActionPreference = 'Stop'
$svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if (-not $svc) { 'The Print Spooler service is not installed on this endpoint; nothing to clear.'; exit 0 }
if ($svc.StartType -eq 'Disabled') { 'The Print Spooler is disabled on this endpoint (often deliberately); leaving it disabled.'; exit 0 }

$spool = Join-Path $env:SystemRoot 'System32\spool\PRINTERS'
try {
  $configured = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers' -Name DefaultSpoolDirectory -ErrorAction Stop).DefaultSpoolDirectory
  if ($configured) { $spool = [Environment]::ExpandEnvironmentVariables($configured) }
} catch {}

$dependents = @($svc.DependentServices | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
try {
  if ($svc.Status -ne 'Stopped') {
    'Stopping the Print Spooler.'
    Stop-Service -Name Spooler -Force -ErrorAction Stop
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
  }
  $removed = 0; $failed = 0
  if (Test-Path -LiteralPath $spool -PathType Container) {
    foreach ($f in Get-ChildItem -LiteralPath $spool -File -Force -ErrorAction SilentlyContinue) {
      try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $removed++ } catch { $failed++ }
    }
  }
  "Removed $removed queued job file(s) from $spool" + $(if ($failed) { "; $failed could not be removed" } else { '' }) + '.'
  'Starting the Print Spooler.'
  Start-Service -Name Spooler -ErrorAction Stop
  $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
} catch {
  "FAILED: $($_.Exception.Message)"
  try { Start-Service -Name Spooler -ErrorAction SilentlyContinue } catch {}
  exit 1
}
foreach ($d in $dependents) {
  try { Start-Service -Name $d -ErrorAction Stop } catch { "WARNING: dependent service $d did not start: $($_.Exception.Message)" }
}
'The Print Spooler is running with an empty queue.'
exit 0
