# Describes the connection in use: gateway, adapter, Wi-Fi signal, power saving and DNS servers.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function J($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)) }

$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
if (-not $r) { J @{ type = 'net'; connected = $false }; exit }
$ad = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex
$isWifi = ([string]$ad.PhysicalMediaType -match '802\.11') -or ([int]$ad.NdisPhysicalMedium -eq 9)
$pm = Get-NetAdapterPowerManagement -Name $ad.Name -ErrorAction SilentlyContinue
$dns = @((Get-DnsClientServerAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4).ServerAddresses)
$signal = $null
if ($isWifi) {
  foreach ($l in (netsh wlan show interfaces)) { if ($l -match ':\s*(\d{1,3})\s*%\s*$') { $signal = [int]$Matches[1] } }
}
J @{
  type = 'net'; connected = $true
  gateway = [string]$r.NextHop; alias = [string]$ad.Name; ifIndex = [int]$r.InterfaceIndex
  desc = [string]$ad.InterfaceDescription; isWifi = [bool]$isWifi; signal = $signal
  powerSaving = [string]$pm.AllowComputerToTurnOffDevice; dns = $dns; linkSpeed = [string]$ad.LinkSpeed
  driverFile = [string]$ad.DriverFileName; pnpId = [string]$ad.PnPDeviceID
}
