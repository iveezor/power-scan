'use strict';
/*
 * Builds downloadable packages into dist/:
 *   win   -> Power Scan-win-x64.zip  (unzip and run "Power Scan.exe")
 *   linux -> power-scan-linux-x64.tar.gz  (extract and run install.sh, or run.sh without installing)
 * Usage: node tools/pack.js win linux
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { packager } = require('@electron/packager');

const ROOT = path.join(__dirname, '..');
const DIST = path.join(ROOT, 'dist');
const pkg = require(path.join(ROOT, 'package.json'));
const targets = process.argv.slice(2).length ? process.argv.slice(2) : ['win', 'linux'];

const LINUX_INSTALL = `#!/bin/sh
# Installs Power Scan for all users. Run:  sudo ./install.sh
set -e
if [ "$(id -u)" -ne 0 ]; then echo "Run this with sudo:  sudo ./install.sh"; exit 1; fi
HERE="$(cd "$(dirname "$0")" && pwd)"
rm -rf /opt/power-scan
mkdir -p /opt/power-scan
cp -a "$HERE/." /opt/power-scan/
chown root:root /opt/power-scan/chrome-sandbox
chmod 4755 /opt/power-scan/chrome-sandbox
chmod 755 /opt/power-scan/power-scan
ln -sf /opt/power-scan/power-scan /usr/local/bin/power-scan
mkdir -p /usr/share/icons/hicolor/512x512/apps
cp /opt/power-scan/resources/app/assets/icon.png /usr/share/icons/hicolor/512x512/apps/power-scan.png
cat > /usr/share/applications/power-scan.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Power Scan
Comment=Virus scan, speed test and driver checker
Exec=/opt/power-scan/power-scan %U
Icon=power-scan
Categories=System;Security;
Terminal=false
EOF
echo "Power Scan is installed. Open it from your app menu or run: power-scan"
echo ""
echo "Power Scan uses these tools when they are installed:"
echo "  ClamAV (file scanning)    Debian/Ubuntu: sudo apt install clamav clamav-daemon   Fedora: sudo dnf install clamav clamav-update clamd"
echo "  rkhunter (rootkit check)  sudo apt install rkhunter    /  sudo dnf install rkhunter"
echo "  fwupd, pciutils, iw, NetworkManager, polkit (pkexec) are usually installed already."
`;

const LINUX_RUN = `#!/bin/sh
# Runs Power Scan from this folder without installing it.
# Electron's sandbox needs chrome-sandbox to be owned by root (install.sh does that). Without it,
# this script starts Power Scan with --no-sandbox; it only ever shows its own local pages.
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ "$(stat -c %u "$HERE/chrome-sandbox" 2>/dev/null)" = "0" ] && [ -u "$HERE/chrome-sandbox" ]; then
  exec "$HERE/power-scan" "$@"
fi
exec "$HERE/power-scan" --no-sandbox "$@"
`;

const README_LINUX = `Power Scan ${pkg.version} for Linux (x64)

Install:   sudo ./install.sh        (adds Power Scan to your app menu)
Or run without installing:  ./run.sh

Optional tools Power Scan uses:
  ClamAV       file scanning and Traffic download checks (clamav, clamav-daemon for fast checks)
  rkhunter     known-rootkit check during the virus scan
  fwupd        firmware updates in the Drivers tab
  pkexec       administrator prompts for changes (part of polkit)
  NetworkManager, iw, ip   Speed Test diagnosis and fixes
`;

const README_WIN = `Power Scan ${pkg.version} for Windows (x64)

Run "Power Scan.exe". No installation needed; keep this folder together.
Power Scan uses Microsoft Defender (built into Windows) for file scanning,
and Windows Update for driver updates. Changes that need administrator rights
show the normal Windows permission prompt first.
`;

function tarLinux(dirName) {
  const tar = 'tar';
  const archive = 'power-scan-linux-x64.tar';
  const execs = ['power-scan', 'chrome-sandbox', 'chrome_crashpad_handler', 'install.sh', 'run.sh'].map((f) => `${dirName}/${f}`);
  const opts = ['--owner=0', '--group=0', '--numeric-owner'];
  execFileSync(tar, [...opts, '--mode=u=rwX,go=rX', '-cf', archive, ...execs.map((e) => `--exclude=${e}`), dirName], { cwd: DIST, stdio: 'inherit' });
  execFileSync(tar, [...opts, '--mode=0755', '-rf', archive, ...execs], { cwd: DIST, stdio: 'inherit' });
  execFileSync('gzip', ['-9f', archive], { cwd: DIST, stdio: 'inherit' });
  return path.join(DIST, archive + '.gz');
}

function zipWin(dirName) {
  const out = path.join(DIST, 'Power-Scan-win-x64.zip');
  if (fs.existsSync(out)) fs.rmSync(out);
  const bsdtar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
  execFileSync(bsdtar, ['-a', '-c', '-f', out, dirName], { cwd: DIST, stdio: 'inherit' });
  return out;
}

async function main() {
  fs.mkdirSync(DIST, { recursive: true });
  for (const t of targets) {
    const platform = t === 'win' ? 'win32' : 'linux';
    console.log(`\n== packaging ${platform}-x64`);
    const [dir] = await packager({
      dir: ROOT,
      out: DIST,
      overwrite: true,
      platform,
      arch: 'x64',
      name: 'Power Scan',
      executableName: platform === 'win32' ? 'Power Scan' : 'power-scan',
      appVersion: pkg.version,
      electronVersion: require(path.join(ROOT, 'node_modules', 'electron', 'package.json')).version,
      asar: false,
      prune: false,
      icon: path.join(ROOT, 'assets', platform === 'win32' ? 'icon.ico' : 'icon.png'),
      ignore: [
        /^\/dist($|\/)/, /^\/release($|\/)/, /^\/\.github($|\/)/, /^\/tools($|\/)/, /^\/\.claude($|\/)/, /^\/\.git($|\/)/, /^\/README\.md$/, /^\/package-lock\.json$/,
        // The fonts are the only runtime dependency; everything else in node_modules is build tooling.
        /^\/node_modules\/(?!@fontsource($|\/))/,
        /^\/node_modules\/@fontsource\/[^/]+\/(?!files($|\/)|package\.json$)/,
        /^\/node_modules\/@fontsource\/[^/]+\/files\/(?![^/]*-latin-\d+-normal\.woff2$)/,
        platform === 'win32' ? /^\/src\/engine\/linux($|\/)/ : /^\/src\/engine\/win($|\/)/,
      ],
      win32metadata: { CompanyName: 'Power Scan', FileDescription: 'Power Scan', ProductName: 'Power Scan', InternalName: 'Power Scan', OriginalFilename: 'Power Scan.exe' },
    });
    const dirName = path.basename(dir);
    if (platform === 'linux') {
      fs.writeFileSync(path.join(dir, 'install.sh'), LINUX_INSTALL);
      fs.writeFileSync(path.join(dir, 'run.sh'), LINUX_RUN);
      fs.writeFileSync(path.join(dir, 'README.txt'), README_LINUX);
      console.log('created', tarLinux(dirName));
    } else {
      fs.writeFileSync(path.join(dir, 'README.txt'), README_WIN);
      console.log('created', zipWin(dirName));
    }
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
