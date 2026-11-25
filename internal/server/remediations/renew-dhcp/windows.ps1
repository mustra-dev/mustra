# Renew (never release) the lease on every enabled DHCP adapter.
$adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE AND DHCPEnabled = TRUE')
if ($adapters.Count -eq 0) { 'No enabled adapter uses DHCP; nothing to renew.'; exit 0 }
$failed = 0
foreach ($a in $adapters) {
  $r = Invoke-CimMethod -InputObject $a -MethodName RenewDHCPLease
  if ($r.ReturnValue -eq 0) {
    $a = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "Index = $($a.Index)"
    "{0}: renewed; address {1}" -f $a.Description, (($a.IPAddress | Where-Object { $_ -notmatch ':' }) -join ', ')
  } else {
    "{0}: renewal failed (code {1})" -f $a.Description, $r.ReturnValue
    $failed++
  }
}
if ($failed -gt 0) { exit 1 }
exit 0
