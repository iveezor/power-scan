# Asks Windows Update which driver updates it offers for this computer. Read-only.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function J($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)) }

try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'Power Scan'
  $searcher = $session.CreateUpdateSearcher()
  $searcher.Online = $true
  $res = $searcher.Search("IsInstalled=0 and Type='Driver' and IsHidden=0")
  foreach ($u in $res.Updates) {
    $ver = ''
    $m = [regex]::Match([string]$u.Title, '(\d+(?:\.\d+){1,4})\)?\s*$')
    if ($m.Success) { $ver = $m.Groups[1].Value }
    $date = ''
    try { $date = ([datetime]$u.DriverVerDate).ToString('yyyy-MM-dd') } catch {}
    J @{
      type = 'update'; id = [string]$u.Identity.UpdateID; title = [string]$u.Title; version = $ver; date = $date
      hwid = [string]$u.DriverHardwareID; cls = [string]$u.DriverClass; model = [string]$u.DriverModel
      provider = [string]$u.DriverProvider; size = [double]$u.MaxDownloadSize
    }
  }
  J @{ type = 'done'; count = [int]$res.Updates.Count }
} catch {
  J @{ type = 'error'; message = $_.Exception.Message }
}
