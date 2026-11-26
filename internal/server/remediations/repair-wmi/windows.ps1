# Verify the WMI repository; salvage it only when it is inconsistent. A
# reset (/resetrepository) throws away every provider's registrations, so
# that is left to a person who knows what this machine needs.
$ErrorActionPreference = 'Continue'

function Test-Repository {
  & winmgmt.exe /verifyrepository 2>&1 | ForEach-Object { "  $_" }
  return $LASTEXITCODE
}

'Verifying the WMI repository:'
$code = Test-Repository
if ($code -eq 0) {
  'The WMI repository is consistent; nothing to repair.'
  exit 0
}

"The repository is inconsistent (exit $code). Salvaging it:"
& winmgmt.exe /salvagerepository 2>&1 | ForEach-Object { "  $_" }
$salvage = $LASTEXITCODE

'Verifying again:'
$code = Test-Repository
if ($code -eq 0) {
  'The WMI repository is consistent after salvage.'
  exit 0
}
"FAILED: the repository is still inconsistent (salvage exit $salvage, verify exit $code). This remediation does not reset it; that discards third-party WMI registrations and needs a person."
exit 1
