# Lists everything that starts automatically: Run keys, startup folders, scheduled tasks, services,
# Winlogon, AppInit_DLLs and Image File Execution Options debuggers. One JSON object per line.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function J($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)) }

$userWritable = @($env:USERPROFILE, $env:TEMP, $env:TMP, "$env:SystemDrive\Users\Public", "$env:SystemRoot\Temp") |
  Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() + '\' }

function Resolve-Exe([string]$cmd) {
  if (-not $cmd) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  $exe = $null
  if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { $exe = $c.Substring(1, $e - 1) } }
  if (-not $exe) {
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|dll|ps1|vbs|js|scr))(?=\s|,|$)', 'IgnoreCase')
    if ($m.Success) { $exe = $m.Groups[1].Value } else { $exe = ($c -split '\s+')[0] }
  }
  if ($exe -match '(^|\\)rundll32(\.exe)?$') {
    $m2 = [regex]::Match($c, 'rundll32(\.exe)?"?\s+"?([^",]+\.dll)', 'IgnoreCase')
    if ($m2.Success) { $exe = $m2.Groups[2].Value }
  }
  if ($exe -and -not [System.IO.Path]::IsPathRooted($exe)) {
    $found = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $exe = $found.Source }
    else { $cand = Join-Path "$env:SystemRoot\System32" $exe; if (Test-Path -LiteralPath $cand) { $exe = $cand } }
  }
  return $exe
}

function Describe([string]$where, [string]$name, [string]$command, [hashtable]$extra) {
  $exe = Resolve-Exe $command
  $exists = $false; $sig = 'Unknown'; $signer = ''
  if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
    $exists = $true
    $s = Get-AuthenticodeSignature -LiteralPath $exe
    $sig = [string]$s.Status
    if ($s.SignerCertificate) { $signer = (($s.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '') -replace '"', '' }
  }
  $low = ([string]$exe).ToLower()
  $uw = $false
  foreach ($u in $userWritable) { if ($low.StartsWith($u)) { $uw = $true } }
  $o = @{ type = 'entry'; where = $where; name = $name; command = $command; exe = [string]$exe; exists = $exists; sig = $sig; signer = $signer; userWritable = $uw }
  if ($extra) { foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] } }
  J $o
}

$skipProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
$runKeys = @(
  @{ hive = 'HKCU'; path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' },
  @{ hive = 'HKCU-Once'; path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
  @{ hive = 'HKLM'; path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
  @{ hive = 'HKLM-Once'; path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
  @{ hive = 'HKLM32'; path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' },
  @{ hive = 'HKLM32-Once'; path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' }
)
foreach ($k in $runKeys) {
  $props = Get-ItemProperty -LiteralPath $k.path
  if (-not $props) { continue }
  foreach ($p in $props.PSObject.Properties) {
    if ($skipProps -contains $p.Name) { continue }
    Describe ('Run key (' + $k.hive + ')') $p.Name ([string]$p.Value) @{ kind = 'run'; hive = $k.hive; valueName = $p.Name }
  }
}

$shell = New-Object -ComObject WScript.Shell
foreach ($f in @(@{ scope = 'user'; path = [Environment]::GetFolderPath('Startup') }, @{ scope = 'all'; path = [Environment]::GetFolderPath('CommonStartup') })) {
  if (-not $f.path) { continue }
  Get-ChildItem -LiteralPath $f.path -File | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
    $cmdline = '"' + $_.FullName + '"'
    if ($_.Extension -eq '.lnk') { $lnk = $shell.CreateShortcut($_.FullName); $cmdline = '"' + $lnk.TargetPath + '" ' + $lnk.Arguments }
    Describe ('Startup folder (' + $f.scope + ')') $_.Name $cmdline @{ kind = 'folder'; scope = $f.scope; file = $_.FullName }
  }
}

Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  $t = $_
  foreach ($a in @($t.Actions)) {
    if ($a.Execute) {
      Describe 'Scheduled task' $t.TaskName ('"' + ([string]$a.Execute).Trim('"') + '" ' + $a.Arguments) @{ kind = 'task'; taskPath = [string]$t.TaskPath; taskName = [string]$t.TaskName }
    }
  }
}

Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName } | ForEach-Object {
  if ($_.PathName -match '\\system32\\svchost\.exe') { return }
  Describe 'Service' ([string]$_.DisplayName) ([string]$_.PathName) @{ kind = 'service'; service = [string]$_.Name }
}

$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
J @{ type = 'winlogon'; shell = [string]$wl.Shell; userinit = [string]$wl.Userinit }
$wlu = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wlu -and $wlu.Shell) { J @{ type = 'winlogon-user'; shell = [string]$wlu.Shell } }
foreach ($view in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
  $w = Get-ItemProperty $view
  if ($w) { J @{ type = 'appinit'; key = $view; dlls = [string]$w.AppInit_DLLs; load = [int]$w.LoadAppInit_DLLs } }
}
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
  $dbg = (Get-ItemProperty -LiteralPath $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
  if ($dbg) { J @{ type = 'ifeo'; exe = [string]$_.PSChildName; debugger = [string]$dbg } }
}
J @{ type = 'end' }
