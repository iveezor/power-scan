# Lists every running kernel driver with its file, signature and publisher. One JSON object per line.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function J($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)) }

$sysRoot = $env:SystemRoot
$drivers = @(Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' })
J @{ type = 'count'; n = $drivers.Count }
foreach ($d in $drivers) {
  $p = ([string]$d.PathName).Trim().Trim('"')
  if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
  if ($p -match '^\\SystemRoot\\') { $p = Join-Path $sysRoot $p.Substring(12) }
  elseif ($p -match '^system32\\') { $p = Join-Path $sysRoot $p }
  elseif ($p -match '^\\Windows\\') { $p = $env:SystemDrive + $p }
  $exists = $false; $sig = 'Unknown'; $signer = ''; $company = ''
  if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) {
    $exists = $true
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $sig = [string]$s.Status
    if ($s.SignerCertificate) { $signer = (($s.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '') -replace '"', '' }
    $company = [string](Get-Item -LiteralPath $p).VersionInfo.CompanyName
  }
  J @{ type = 'driver'; name = [string]$d.Name; display = [string]$d.DisplayName; path = $p; exists = $exists; sig = $sig; signer = $signer; company = $company }
}
