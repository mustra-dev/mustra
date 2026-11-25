# Make Windows Search rebuild its index from scratch on its next start.
$ErrorActionPreference = 'Stop'
$svc = Get-Service -Name WSearch -ErrorAction SilentlyContinue
if (-not $svc) { 'Windows Search is not installed on this endpoint; nothing to rebuild.'; exit 0 }
if ($svc.StartType -eq 'Disabled') { 'Windows Search is disabled on this endpoint; leaving it disabled.'; exit 0 }
try {
  if ($svc.Status -ne 'Stopped') {
    'Stopping Windows Search.'
    Stop-Service -Name WSearch -Force -ErrorAction Stop
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(120))
  }
  Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Search' -Name SetupCompletedSuccessfully -Value 0 -Type DWord -ErrorAction Stop
  'Starting Windows Search.'
  Start-Service -Name WSearch -ErrorAction Stop
  $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(120))
} catch {
  "FAILED: $($_.Exception.Message)"
  try { Start-Service -Name WSearch -ErrorAction SilentlyContinue } catch {}
  exit 1
}
'Windows Search is rebuilding its index; results are incomplete until it finishes.'
exit 0
