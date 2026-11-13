# Power Scan

A small desktop app for Windows and Linux with three tabs: a kernel-level **Virus Scan** (with Passive Listener and Traffic), a **Speed Test** that finds and fixes connection drops, and a **Drivers** check. Nothing on the computer changes until you press a button and confirm.

## Download

Get the latest version from the **[Releases page](https://github.com/iveezor/power-scan/releases/latest)**.

| Platform | File | How to install |
| --- | --- | --- |
| Windows 10/11 (x64) | `Power-Scan-Setup-1.0.0.exe` | Run it. Installs for your user account, with Start menu and desktop shortcuts. |
| Windows, no install | `Power-Scan-win-x64.zip` | Unzip anywhere and run `Power Scan.exe`. |
| Ubuntu / Debian (x64) | `power-scan_1.0.0_amd64.deb` | Double-click to open it in App Center, or `sudo apt install ./power-scan_1.0.0_amd64.deb`. Remove with `sudo apt remove power-scan`. |
| Other Linux (x64) | `power-scan-linux-x64.tar.gz` | Extract, then `sudo ./install.sh`, or `./run.sh` to run without installing. |

On Linux, also install ClamAV and rkhunter for file scanning and the rootkit check: `sudo apt install clamav clamav-daemon rkhunter`.

The downloads are not code-signed yet, so Windows SmartScreen may say the publisher is unknown. Choose **More info → Run anyway**. Each release lists SHA-256 checksums so you can check a download is intact.

## What each feature does

### Virus Scan (power button)
Five passes, starting at the kernel:

| Pass | Windows | Linux |
| --- | --- | --- |
| Kernel | Every loaded kernel driver: signature and publisher, drivers loaded from user folders | `/proc/modules` vs `/sys/module` (hidden modules), unsigned modules, taint flags |
| Boot | Secure Boot, Memory integrity (HVCI), test-signing, signature checks, early-launch driver | Secure Boot (`mokutil`), lockdown, module signature enforcement, `/etc/ld.so.preload` |
| Startup | Run keys, startup folders, scheduled tasks, services, Winlogon, AppInit_DLLs, IFEO | systemd units, autostart entries, cron, shell profiles |
| Programs | Unsigned programs running from user folders, programs whose file is gone | Deleted or `/tmp` binaries, processes hidden from `ps` |
| Files | Counts every file first (a few seconds), splits the drives into even pieces, then runs several Microsoft Defender report-only scans in parallel (`MpCmdRun -DisableRemediation`; half the processor cores, 2 to 8) | ClamAV (`clamscan -r /`) plus rkhunter if installed |

Findings wait for **Remove** (or **Disable**, **Remove from startup**, **End and scan**) or **Keep**. Every action shows a confirmation first. Windows removals use Defender's quarantine; Linux removals move files to a quarantine folder with permissions stripped.

Power Scan does not install its own kernel driver. "Kernel-level" means it inspects what is loaded into the kernel and the protections around it, using the operating system's own tools.

### Passive Listener and Traffic
Turning it on runs one full scan first, then watches your Downloads and Desktop folders. Each new file is held while it is checked:

- **Windows:** a "deny execute" rule stops the file from being run while Microsoft Defender scans it. Clean files are released; harmful ones stay held until you choose Remove or Keep. Defender's own real-time protection usually removes known malware the moment it lands, and Power Scan shows that too.
- **Linux:** execute permission is removed while ClamAV checks the file (`clamdscan` if the daemon runs, otherwise `clamscan`).

With Passive Listener on, closing the window keeps Power Scan in the tray, and it starts with the computer.

### Speed Test
Ping, download and upload against Cloudflare's speed test servers, then 30 seconds of pings to your router and to 1.1.1.1, plus DNS lookups, once a second. The diagnosis tells you whether drops come from the Wi-Fi link, your provider, or DNS. **Fix it** lists the exact commands (Wi-Fi power saving, DNS cache, faster DNS, IP renew, adapter restart), runs only the ones you leave ticked, then tests again and shows before and after. A DNS change can be undone.

### Drivers
Inventory, versions, health and performance (the last 7 days of crashes and resets):

- **Windows:** Device Manager data, Windows Update's driver catalog (Microsoft-signed only), problem codes (Code 10, 28, 43…), and the System event log (display driver resets, errors per driver, bug checks). Updates install from Windows Update after a restore point (when System Restore is on). BIOS/firmware updates are flagged and never included in "Update all". Roll back opens the device in Device Manager.
- **Linux:** `lspci`, sysfs, `fwupd` and your package manager (apt, dnf, zypper; Arch gets `pacman -Syu` advice), plus the kernel log for GPU hangs, Wi-Fi firmware crashes, USB and NVMe resets.

## Administrator rights
Power Scan runs as a normal user. Changes that need more rights ask first: a Windows permission (UAC) prompt, or a Linux password prompt through polkit (`pkexec`). On Windows they run through one allow-listed script (`src/engine/win/ps/elevated.ps1`) that checks every value it gets.

## Develop

```bash
npm install
node node_modules/electron/install.js   # npm 12 skips Electron's download step
npm start
node tools/check.js all                  # read-only engine check on this computer
npm run pack                             # portable Windows zip and Linux tarball in dist/
npm run dist:win                         # Windows installer in release/
npm run dist:deb                         # Ubuntu/Debian .deb in dist/
```

Pushing a tag such as `v1.1.0` runs `.github/workflows/release.yml`, which builds the Windows installer and the Linux AppImage and .deb on GitHub and publishes them as a release.

`tools/ui-test.js` drives the real window and saves screenshots: set `POWERSCAN_TEST_SCRIPT=tools/ui-test.js` and `POWERSCAN_TEST_OUT=<folder>` before `npm start`. Test runs use a separate settings folder.

## Status
- Windows: tested on Windows 11 (all features; changes that need confirmation were not applied during testing).
- Linux: implemented and packaged, but not yet tested on a Linux machine. Reports are welcome in Issues.
