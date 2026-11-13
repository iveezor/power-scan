# Lists device drivers (same data as Device Manager) and devices that report a problem code.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function J($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)) }

$ents = @{}
Get-CimInstance Win32_PnPEntity | ForEach-Object { if ($_.DeviceID) { $ents[[string]$_.DeviceID] = $_ } }
$drivers = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -and $_.DeviceID })
J @{ type = 'count'; n = $drivers.Count; devices = $ents.Count }
$seen = @{}
foreach ($d in $drivers) {
  $id = [string]$d.DeviceID
  $seen[$id] = $true
  $e = $ents[$id]
  $date = ''
  if ($d.DriverDate) { try { $date = ([datetime]$d.DriverDate).ToString('yyyy-MM-dd') } catch {} }
  J @{
    type = 'driver'; id = $id; name = [string]$d.DeviceName; cls = [string]$d.DeviceClass
    version = [string]$d.DriverVersion; date = $date; provider = [string]$d.DriverProviderName
    inf = [string]$d.InfName; signed = [bool]$d.IsSigned
    service = [string]$e.Service; hwids = @($e.HardwareID); problem = [int]$e.ConfigManagerErrorCode
  }
}
foreach ($e in $ents.Values) {
  $code = [int]$e.ConfigManagerErrorCode
  if ($code -ne 0 -and -not $seen[[string]$e.DeviceID]) {
    J @{ type = 'problem'; id = [string]$e.DeviceID; name = [string]$e.Name; cls = [string]$e.PNPClass; code = $code; hwids = @($e.HardwareID); service = [string]$e.Service }
  }
}
J @{ type = 'end' }
