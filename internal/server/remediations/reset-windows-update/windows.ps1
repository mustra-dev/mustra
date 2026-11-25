# Reset the Windows Update components: stop the services, set the download
# store and the catalog database aside (renamed, not deleted), start again.
$ErrorActionPreference = 'Stop'

$names = 'UsoSvc', 'wuauserv', 'bits', 'cryptsvc', 'msiserver'
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$folders = @(
  (Join-Path $env:SystemRoot 'SoftwareDistribution'),
  (Join-Path $env:SystemRoot 'System32\catroot2')
)

# Everything that is running now and could be stopped along the way (the
# services themselves and whatever depends on them) is started again at
# the end, whether or not the reset worked.
$restart = New-Object System.Collections.Generic.List[string]
foreach ($n in $names) {
  $s = Get-Service -Name $n -ErrorAction SilentlyContinue
  if (-not $s) { continue }
  foreach ($d in @($s.DependentServices) + $s) {
    if ($d.Status -eq 'Running' -and -not $restart.Contains($d.Name)) { $restart.Add($d.Name) }
  }
}

function Start-Again {
  foreach ($n in @('cryptsvc') + $restart) {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Running' -and $s.StartType -ne 'Disabled') {
      try { Start-Service -Name $n -ErrorAction Stop; "Started $n." } catch { "WARNING: could not start ${n}: $($_.Exception.Message)" }
    }
  }
}

try {
  foreach ($n in $names) {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if (-not $s -or $s.Status -eq 'Stopped') { continue }
    "Stopping $n."
    Stop-Service -Name $n -Force -ErrorAction Stop
    $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(90))
  }
  foreach ($f in $folders) {
    if (-not (Test-Path -LiteralPath $f)) { "$f does not exist; nothing to set aside."; continue }
    $leaf = Split-Path -Leaf $f
    $parent = Split-Path -Parent $f
    # Only the newest copy is kept: older ones this remediation made are
    # what the update store was before an earlier reset.
    Get-ChildItem -LiteralPath $parent -Directory -Filter "$leaf.mustra-*" -ErrorAction SilentlyContinue |
      ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    Rename-Item -LiteralPath $f -NewName "$leaf.mustra-$stamp" -ErrorAction Stop
    "Renamed $f to $leaf.mustra-$stamp."
  }
} catch {
  "FAILED: $($_.Exception.Message)"
  Start-Again
  exit 1
}

Start-Again
'Windows Update components were reset. Windows rebuilds the download store and catalog on its next update scan.'
exit 0
