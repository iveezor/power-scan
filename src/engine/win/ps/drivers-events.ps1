# Counts driver trouble in the System event log: display driver resets (event 4101) and errors per
# driver over 7 days, and crashes (bug checks) over 30 days.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function J($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)) }

$since = (Get-Date).AddDays(-7)
$tdr = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Display'; Id = 4101; StartTime = $since })
$tdrByDriver = @{}
foreach ($e in $tdr) {
  $n = ''
  try { $n = [string]$e.Properties[0].Value } catch {}
  if (-not $n) { $n = 'display' }
  $tdrByDriver[$n] = 1 + [int]$tdrByDriver[$n]
}
$crashes = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = (Get-Date).AddDays(-30) })
$whea = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Level = 1, 2; StartTime = $since })
$errors = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = $since } -MaxEvents 5000)
$byProvider = @{}
foreach ($e in $errors) { $n = [string]$e.ProviderName; $byProvider[$n] = 1 + [int]$byProvider[$n] }
J @{ type = 'events'; tdr = $tdrByDriver; tdrTotal = $tdr.Count; crashes = $crashes.Count; whea = $whea.Count; providers = $byProvider }
