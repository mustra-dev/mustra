# Free disk space: old temp files, Delivery Optimization cache, superseded
# components. Nothing outside temp directories and caches is deleted.
$ErrorActionPreference = 'Continue'

$days = 7
if ($env:MUSTRA_PARAM_older_than_days) { $days = [int]$env:MUSTRA_PARAM_older_than_days }
$cutoff = (Get-Date).AddDays(-$days)
$componentCleanup = $env:MUSTRA_PARAM_component_cleanup -ne 'false'

function Get-FreeBytes {
  [int64](Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'").FreeSpace
}

# Walks a directory without following junctions or symbolic links (Windows
# PowerShell's -Recurse follows them), so a link inside a temp directory can
# never lead the cleanup somewhere else.
function Get-OldFiles([string]$root) {
  $stack = New-Object System.Collections.Stack
  $stack.Push($root)
  while ($stack.Count -gt 0) {
    $dir = New-Object System.IO.DirectoryInfo ([string]$stack.Pop())
    try { $entries = $dir.GetFileSystemInfos() } catch { continue }
    foreach ($e in $entries) {
      if ($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
      if ($e -is [System.IO.DirectoryInfo]) { $stack.Push($e.FullName); continue }
      if ($e.LastWriteTime -lt $cutoff -and $e.LastAccessTime -lt $cutoff) { $e }
    }
  }
}

function Clear-OldFiles([string]$path) {
  if (-not (Test-Path -LiteralPath $path -PathType Container)) { return }
  $removed = 0; $skipped = 0; $bytes = [int64]0
  foreach ($f in Get-OldFiles $path) {
    try {
      $len = $f.Length
      Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
      $removed++; $bytes += $len
    } catch { $skipped++ }
  }
  '{0}: removed {1} file(s), {2:N1} MB; {3} in use or protected' -f $path, $removed, ($bytes / 1MB), $skipped
}

$before = Get-FreeBytes
"Removing temporary files older than $days day(s)."

$dirs = New-Object System.Collections.Generic.List[string]
$dirs.Add((Join-Path $env:SystemRoot 'Temp'))
if ($env:TEMP) { $dirs.Add($env:TEMP) }
foreach ($p in Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.LocalPath }) {
  $dirs.Add((Join-Path $p.LocalPath 'AppData\Local\Temp'))
}
$seen = @{}
foreach ($d in $dirs) {
  $key = $d.TrimEnd('\').ToLowerInvariant()
  if ($seen.ContainsKey($key)) { continue }
  $seen[$key] = $true
  Clear-OldFiles $d
}

if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
  try {
    Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
    'Delivery Optimization cache cleared.'
  } catch { "Delivery Optimization cache: $($_.Exception.Message)" }
}

$status = 0
if ($componentCleanup) {
  'Cleaning up superseded components (DISM /StartComponentCleanup); this can take a while.'
  & dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart | Select-Object -Last 3
  if ($LASTEXITCODE -ne 0) {
    # A pending reboot is the usual cause; the rest of the cleanup stands.
    "WARNING: component cleanup exited with $LASTEXITCODE (often a pending reboot). Everything else was cleaned."
    $status = 2
  }
}

$after = Get-FreeBytes
'Free space on {0}: {1:N2} GB before, {2:N2} GB after ({3:N2} GB freed).' -f $env:SystemDrive, ($before / 1GB), ($after / 1GB), (($after - $before) / 1GB)
exit $status
