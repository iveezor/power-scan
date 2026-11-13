# Quick status for the app's header tiles: Defender, Memory integrity, System Restore and fixed drives.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function J($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)) }

$s = Get-MpComputerStatus
if ($s) {
  J @{ type = 'defender'; mode = [string]$s.AMRunningMode; av = [bool]$s.AntivirusEnabled; rtp = [bool]$s.RealTimeProtectionEnabled; engine = [string]$s.AMEngineVersion; sig = [string]$s.AntivirusSignatureVersion; sigAge = [int]$s.AntivirusSignatureAge; tamper = [bool]$s.IsTamperProtected }
} else {
  J @{ type = 'defender'; mode = 'Unavailable'; av = $false; rtp = $false }
}
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
J @{ type = 'hvci'; on = [bool]($dg -and (@($dg.SecurityServicesRunning) -contains 2)) }
$spp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients'
$protected = $false
if ($spp) { foreach ($p in $spp.PSObject.Properties) { if ($p.Name -like '{*}' -and $p.Value) { $protected = $true } } }
J @{ type = 'restore'; on = $protected }
J @{ type = 'drives'; list = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [string]$_.DeviceID }) }
