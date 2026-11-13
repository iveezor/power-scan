param([string]$In, [string]$Out)
# Runs only after the user confirms a change in Power Scan and approves the Windows administrator prompt.
# Accepts a fixed list of operations; every value is validated before use. Writes one JSON line per step to $Out.
$ErrorActionPreference = 'Stop'
function W($o) { Add-Content -LiteralPath $Out -Value ($o | ConvertTo-Json -Compress -Depth 5) -Encoding UTF8 }
function Adapter([string]$a) { return (Get-NetAdapter -Name $a -ErrorAction Stop).Name }
function SafeName([string]$s) { if ($s -notmatch '^[\w .()\-]{1,120}$') { throw "Unexpected name: $s" }; return $s }
function Ips($list) {
  $ok = @($list | ForEach-Object { [string]$_ } | Where-Object { $_ -match '^(\d{1,3}\.){3}\d{1,3}$' })
  if ($ok.Count -eq 0) { throw 'No valid DNS server addresses' }
  return $ok
}
function RunKey([string]$hive) {
  switch ($hive) {
    'HKLM' { return 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' }
    'HKLM-Once' { return 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
    'HKLM32' { return 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' }
    'HKLM32-Once' { return 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' }
  }
  throw "Unknown key: $hive"
}

$req = Get-Content -LiteralPath $In -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($op in @($req.ops)) {
  $r = @{ op = [string]$op.op; id = [string]$op.id; ok = $true; message = '' }
  W @{ progress = [string]$op.op; id = [string]$op.id }
  try {
    switch ([string]$op.op) {
      'restore-point' {
        $before = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count
        Checkpoint-Computer -Description 'Power Scan changes' -RestorePointType 'MODIFY_SETTINGS' -WarningVariable wv -WarningAction SilentlyContinue
        $after = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count
        if ($after -gt $before) { $r.message = 'made' } elseif ($wv) { $r.message = 'recent' } else { $r.message = 'made' }
      }
      'driver-install' {
        if (-not $script:wu) {
          $script:session = New-Object -ComObject Microsoft.Update.Session
          $script:session.ClientApplicationID = 'Power Scan'
          $s = $script:session.CreateUpdateSearcher()
          $script:wu = $s.Search("IsInstalled=0 and Type='Driver'")
        }
        $target = $null
        foreach ($u in $script:wu.Updates) { if ([string]$u.Identity.UpdateID -eq [string]$op.updateId) { $target = $u } }
        if (-not $target) { throw 'Windows Update no longer offers this driver.' }
        if (-not $target.EulaAccepted) { $target.AcceptEula() }
        $coll = New-Object -ComObject Microsoft.Update.UpdateColl
        [void]$coll.Add($target)
        W @{ progress = 'download'; id = [string]$op.id }
        $dl = $script:session.CreateUpdateDownloader(); $dl.Updates = $coll
        $d = $dl.Download()
        if ($d.ResultCode -ne 2 -and $d.ResultCode -ne 3) { throw "Download failed (result $($d.ResultCode))" }
        W @{ progress = 'install'; id = [string]$op.id }
        $inst = $script:session.CreateUpdateInstaller(); $inst.Updates = $coll
        $res = $inst.Install()
        $ur = $res.GetUpdateResult(0)
        if ($ur.ResultCode -ne 2 -and $ur.ResultCode -ne 3) { throw ('Install failed (0x{0:X8})' -f $ur.HResult) }
        $r.reboot = [bool]$res.RebootRequired
      }
      'flushdns' { ipconfig /flushdns | Out-Null; Clear-DnsClientCache }
      'dns-set' {
        $name = Adapter $op.alias
        $guid = (Get-NetAdapter -Name $name).InterfaceGuid
        $static = [string](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
        $r.previous = @{ static = [bool]$static; servers = @($static -split '[,\s]+' | Where-Object { $_ }) }
        Set-DnsClientServerAddress -InterfaceAlias $name -ServerAddresses (Ips $op.servers)
      }
      'dns-restore' {
        $name = Adapter $op.alias
        if ($op.static -and @($op.servers).Count -gt 0) { Set-DnsClientServerAddress -InterfaceAlias $name -ServerAddresses (Ips $op.servers) }
        else { Set-DnsClientServerAddress -InterfaceAlias $name -ResetServerAddresses }
      }
      'renew' {
        $name = Adapter $op.alias
        ipconfig /release "$name" | Out-Null
        ipconfig /renew "$name" | Out-Null
      }
      'adapter-restart' { Restart-NetAdapter -Name (Adapter $op.alias) -Confirm:$false }
      'wifi-powersave-off' { Set-NetAdapterPowerManagement -Name (Adapter $op.alias) -AllowComputerToTurnOffDevice Disabled }
      'service-disable' {
        $n = SafeName $op.name
        & sc.exe config $n start= disabled | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe could not change $n (exit $LASTEXITCODE)" }
      }
      'run-remove' {
        $key = RunKey $op.hive
        $val = (Get-ItemProperty -LiteralPath $key -Name ([string]$op.name)).([string]$op.name)
        $r.backup = [string]$val
        Remove-ItemProperty -LiteralPath $key -Name ([string]$op.name)
      }
      'task-disable' { Disable-ScheduledTask -TaskPath ([string]$op.taskPath) -TaskName ([string]$op.taskName) | Out-Null }
      'winlogon-reset' {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if ($op.field -eq 'Shell') { Set-ItemProperty -LiteralPath $k -Name Shell -Value 'explorer.exe' }
        elseif ($op.field -eq 'Userinit') { Set-ItemProperty -LiteralPath $k -Name Userinit -Value "$env:SystemRoot\system32\userinit.exe," }
        else { throw 'Unknown field' }
      }
      'appinit-reset' {
        foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
          if (Test-Path -LiteralPath $k) { Set-ItemProperty -LiteralPath $k -Name AppInit_DLLs -Value ''; Set-ItemProperty -LiteralPath $k -Name LoadAppInit_DLLs -Value 0 -Type DWord }
        }
      }
      'ifeo-remove' {
        $e = SafeName $op.exe
        Remove-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$e" -Name Debugger
      }
      'bcd-testsigning-off' { & bcdedit.exe /set testsigning off | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'bcdedit failed' } }
      'bcd-integrity-on' { & bcdedit.exe /deletevalue nointegritychecks | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'bcdedit failed' } }
      'kill' { Stop-Process -Id ([int]$op.pid) -Force }
      'defender-remove' { Remove-MpThreat }
      'quarantine-file' {
        $src = [string]$op.path
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { throw 'File not found' }
        $dir = Join-Path $env:ProgramData 'PowerScan\Quarantine'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $dest = Join-Path $dir ((Get-Date -Format 'yyyyMMdd-HHmmss') + '_' + [IO.Path]::GetFileName($src) + '.quarantined')
        Move-Item -LiteralPath $src -Destination $dest
        $r.dest = $dest
      }
      default { throw "Unknown operation: $($op.op)" }
    }
  } catch {
    $r.ok = $false
    $r.message = $_.Exception.Message
  }
  W $r
}
W @{ done = $true }
