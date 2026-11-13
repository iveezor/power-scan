# Reads boot protections: Secure Boot, Memory integrity (HVCI), boot options and the early-launch driver.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function J($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)) }

$sb = $null
try { $sb = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch {
  $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue
  if ($null -ne $v) { $sb = ([int]$v.UEFISecureBootEnabled -eq 1) }
}
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
$hvci = $null
if ($dg) { $hvci = (@($dg.SecurityServicesRunning) -contains 2) }
$opts = [string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name SystemStartOptions).SystemStartOptions
$block = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable -ErrorAction SilentlyContinue
$blocklist = $null
if ($null -ne $block) { $blocklist = ([int]$block.VulnerableDriverBlocklistEnable -eq 1) }
J @{
  type = 'boot'
  secureBoot = $sb
  hvci = $hvci
  testSigning = [bool]($opts -match '(^|\s)TESTSIGNING')
  noIntegrity = [bool]($opts -match 'DISABLE_INTEGRITY_CHECKS')
  debug = [bool]($opts -match '(^|\s)DEBUG(\s|=|$)')
  elam = [bool](Test-Path "$env:SystemRoot\System32\drivers\WdBoot.sys")
  blocklist = $blocklist
}
