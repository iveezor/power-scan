# Lists every running program once (grouped by file) with its signature and location.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function J($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)) }

$userWritable = @($env:USERPROFILE, $env:TEMP, $env:TMP, "$env:SystemDrive\Users\Public", "$env:SystemRoot\Temp") |
  Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() + '\' }
$groups = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | Group-Object ExecutablePath)
J @{ type = 'count'; n = $groups.Count }
foreach ($g in $groups) {
  $p = [string]$g.Name
  $exists = Test-Path -LiteralPath $p -PathType Leaf
  $sig = 'Unknown'; $signer = ''
  if ($exists) {
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $sig = [string]$s.Status
    if ($s.SignerCertificate) { $signer = (($s.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '') -replace '"', '' }
  }
  $low = $p.ToLower(); $uw = $false
  foreach ($u in $userWritable) { if ($low.StartsWith($u)) { $uw = $true } }
  J @{ type = 'proc'; name = [string]$g.Group[0].Name; path = $p; pids = @($g.Group | ForEach-Object { [int]$_.ProcessId }); exists = [bool]$exists; sig = $sig; signer = $signer; userWritable = $uw }
}
