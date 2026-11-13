'use strict';
/*
 * Builds the Ubuntu/Debian installer dist/power-scan_<version>_amd64.deb from the packaged Linux app
 * (run `node tools/pack.js linux` first). Works on Windows: the ar and tar archives are written here
 * directly, so file owners (root) and modes (executables, setuid chrome-sandbox) are exact.
 *
 * Installs to /opt/power-scan, adds /usr/bin/power-scan, an app-menu entry and the icon.
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const pkg = require(path.join(ROOT, 'package.json'));
const APP = path.join(ROOT, 'dist', 'Power Scan-linux-x64');
const OUT = path.join(ROOT, 'dist', `power-scan_${pkg.version}_amd64.deb`);
const SKIP = new Set(['install.sh', 'run.sh', 'README.txt']);
const EXEC = new Set(['power-scan', 'chrome_crashpad_handler']);
const MTIME = Math.floor(Date.now() / 1000);

if (!fs.existsSync(path.join(APP, 'power-scan'))) {
  console.error('Packaged Linux app not found. Run: node tools/pack.js linux');
  process.exit(1);
}

/* ---------- tar (ustar) ---------- */
function tarHeader(name, { size = 0, mode = 0o644, type = '0', link = '' }) {
  const b = Buffer.alloc(512);
  let prefix = '';
  let short = name;
  if (Buffer.byteLength(name) > 100) {
    let cut = name.lastIndexOf('/', name.length - 2);
    while (cut > 0 && Buffer.byteLength(name.slice(cut + 1)) > 100) cut = name.lastIndexOf('/', cut - 1);
    if (cut <= 0 || Buffer.byteLength(name.slice(0, cut)) > 155) throw new Error('Path too long for tar: ' + name);
    prefix = name.slice(0, cut);
    short = name.slice(cut + 1);
  }
  const put = (s, off, len) => b.write(s, off, len, 'utf8');
  const oct = (n, len) => n.toString(8).padStart(len - 1, '0') + '\0';
  put(short, 0, 100);
  put(oct(mode, 8), 100, 8);
  put(oct(0, 8), 108, 8);
  put(oct(0, 8), 116, 8);
  put(oct(size, 12), 124, 12);
  put(oct(MTIME, 12), 136, 12);
  b.fill(0x20, 148, 156);
  put(type, 156, 1);
  put(link, 157, 100);
  put('ustar\0', 257, 6);
  put('00', 263, 2);
  put('root', 265, 32);
  put('root', 297, 32);
  put(prefix, 345, 155);
  let sum = 0;
  for (const x of b) sum += x;
  put(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
  return b;
}

class TarGz {
  constructor(file) {
    this.path = file;
    this.gz = zlib.createGzip({ level: 9 });
    this.out = fs.createWriteStream(file);
    this.gz.pipe(this.out);
  }
  write(buf) { return new Promise((r) => (this.gz.write(buf) ? r() : this.gz.once('drain', r))); }
  async dir(name) { await this.write(tarHeader(name.endsWith('/') ? name : name + '/', { mode: 0o755, type: '5' })); }
  async symlink(name, target) { await this.write(tarHeader(name, { mode: 0o777, type: '2', link: target })); }
  async file(name, data, mode = 0o644) {
    await this.write(tarHeader(name, { size: data.length, mode }));
    await this.write(data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad) await this.write(Buffer.alloc(pad));
  }
  end() {
    return new Promise((r) => { this.out.on('finish', r); this.gz.end(Buffer.alloc(1024)); });
  }
}

/* ---------- package contents ---------- */
const DESKTOP = `[Desktop Entry]
Type=Application
Name=Power Scan
GenericName=Security scanner
Comment=Virus scan, speed test and driver checker
Exec=/opt/power-scan/power-scan %U
Icon=power-scan
Terminal=false
Categories=System;Security;Utility;
Keywords=virus;malware;antivirus;speed;internet;drivers;
StartupWMClass=Power Scan
`;

const POSTINST = `#!/bin/sh
set -e
chown root:root /opt/power-scan/chrome-sandbox || true
chmod 4755 /opt/power-scan/chrome-sandbox || true
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications || true; fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true; fi
exit 0
`;

const POSTRM = `#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications || true; fi
exit 0
`;

const COPYRIGHT = `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Power Scan
Files: *
Copyright: 2026 Power Scan
License: ${pkg.license || 'MIT'}
Comment: Includes Electron (MIT) and Chromium components; see /opt/power-scan/LICENSES.chromium.html.
`;

function walk(dir, rel = '') {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const r = rel ? rel + '/' + e.name : e.name;
    if (!rel && SKIP.has(e.name)) continue;
    if (e.isDirectory()) out.push({ type: 'dir', rel: r }, ...walk(path.join(dir, e.name), r));
    else if (e.isFile()) out.push({ type: 'file', rel: r, abs: path.join(dir, e.name) });
  }
  return out;
}

async function buildData(file) {
  const tar = new TarGz(file);
  const md5 = [];
  let bytes = 0;
  const add = async (name, data, mode) => {
    await tar.file('./' + name, data, mode);
    md5.push(`${crypto.createHash('md5').update(data).digest('hex')}  ${name}`);
    bytes += data.length;
  };
  for (const d of ['.', './opt', './opt/power-scan', './usr', './usr/bin', './usr/share', './usr/share/applications',
    './usr/share/icons', './usr/share/icons/hicolor', './usr/share/icons/hicolor/512x512', './usr/share/icons/hicolor/512x512/apps',
    './usr/share/doc', './usr/share/doc/power-scan']) await tar.dir(d);
  for (const e of walk(APP)) {
    const name = 'opt/power-scan/' + e.rel;
    if (e.type === 'dir') { await tar.dir('./' + name); continue; }
    const base = path.basename(e.rel);
    const mode = !e.rel.includes('/') && base === 'chrome-sandbox' ? 0o4755 : !e.rel.includes('/') && EXEC.has(base) ? 0o755 : 0o644;
    await add(name, fs.readFileSync(e.abs), mode);
  }
  await tar.symlink('./usr/bin/power-scan', '/opt/power-scan/power-scan');
  await add('usr/share/applications/power-scan.desktop', Buffer.from(DESKTOP));
  await add('usr/share/icons/hicolor/512x512/apps/power-scan.png', fs.readFileSync(path.join(ROOT, 'assets', 'icon.png')));
  await add('usr/share/doc/power-scan/copyright', Buffer.from(COPYRIGHT));
  await tar.end();
  return { md5: md5.join('\n') + '\n', installedKb: Math.ceil(bytes / 1024) };
}

async function buildControl(file, { md5, installedKb }) {
  const maintainer = (pkg.build && pkg.build.linux && pkg.build.linux.maintainer) || `${pkg.author.name} <${pkg.author.email}>`;
  const control = [
    'Package: power-scan',
    `Version: ${pkg.version}`,
    'Architecture: amd64',
    `Maintainer: ${maintainer}`,
    `Installed-Size: ${installedKb}`,
    'Depends: libgtk-3-0t64 | libgtk-3-0, libnss3, libxss1, libxtst6, libatspi2.0-0t64 | libatspi2.0-0, libgbm1, libdrm2, libasound2t64 | libasound2, libsecret-1-0, libnotify4, xdg-utils, pkexec | policykit-1',
    'Recommends: clamav, clamav-daemon, rkhunter, fwupd, iw, pciutils, network-manager',
    'Section: utils',
    'Priority: optional',
    `Homepage: ${pkg.homepage || 'https://example.com'}`,
    'Description: Virus scan, speed test and driver checker',
    ' Power Scan checks the kernel, boot settings, startup entries, running',
    ' programs and every file (with ClamAV), watches new downloads with',
    ' Passive Listener, tests internet speed and stability, and checks drivers.',
    ' Nothing changes until you confirm it.',
    '',
  ].join('\n');
  const tar = new TarGz(file);
  await tar.dir('.');
  await tar.file('./control', Buffer.from(control));
  await tar.file('./md5sums', Buffer.from(md5));
  await tar.file('./postinst', Buffer.from(POSTINST), 0o755);
  await tar.file('./postrm', Buffer.from(POSTRM), 0o755);
  await tar.end();
}

/* ---------- ar ---------- */
function arMember(name, data) {
  const h = Buffer.alloc(60, 0x20);
  h.write(name + '/', 0, 16);
  h.write(String(MTIME), 16, 12);
  h.write('0', 28, 6);
  h.write('0', 34, 6);
  h.write('100644', 40, 8);
  h.write(String(data.length), 48, 10);
  h.write('`\n', 58, 2);
  return Buffer.concat([h, data, data.length % 2 ? Buffer.from('\n') : Buffer.alloc(0)]);
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'ps-deb-'));
  const dataFile = path.join(tmp, 'data.tar.gz');
  const controlFile = path.join(tmp, 'control.tar.gz');
  console.log('writing data.tar.gz (this compresses about 300 MB)...');
  const info = await buildData(dataFile);
  await buildControl(controlFile, info);
  const out = fs.openSync(OUT, 'w');
  fs.writeSync(out, Buffer.from('!<arch>\n'));
  fs.writeSync(out, arMember('debian-binary', Buffer.from('2.0\n')));
  fs.writeSync(out, arMember('control.tar.gz', fs.readFileSync(controlFile)));
  fs.writeSync(out, arMember('data.tar.gz', fs.readFileSync(dataFile)));
  fs.closeSync(out);
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`created ${OUT} (${(fs.statSync(OUT).size / 1e6).toFixed(1)} MB, installs ${(info.installedKb / 1024).toFixed(0)} MB)`);
}

main().catch((e) => { console.error(e); process.exit(1); });
