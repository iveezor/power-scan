'use strict';
/* Microsoft Defender: status, custom scans (report-only or remediating) and output parsing. */
const fs = require('fs');
const path = require('path');
const { run } = require('../util');
const ps = require('./ps');

function cmpVer(a, b) {
  const pa = a.split(/[.-]/).map(Number), pb = b.split(/[.-]/).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

let cachedPath;
/** Newest MpCmdRun.exe from the Defender platform folder, else the copy in Program Files. */
function mpcmdrun() {
  if (cachedPath !== undefined) return cachedPath;
  cachedPath = null;
  const plat = path.join(process.env.ProgramData || 'C:\\ProgramData', 'Microsoft', 'Windows Defender', 'Platform');
  try {
    const dirs = fs.readdirSync(plat).filter((d) => /^\d+\.\d+\.\d+\.\d+/.test(d)).sort(cmpVer).reverse();
    for (const d of dirs) {
      const p = path.join(plat, d, 'MpCmdRun.exe');
      if (fs.existsSync(p)) { cachedPath = p; return p; }
    }
  } catch (_) { /* folder not readable */ }
  const pf = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Windows Defender', 'MpCmdRun.exe');
  if (fs.existsSync(pf)) cachedPath = pf;
  return cachedPath;
}

/** Defender status, Memory integrity, System Restore and fixed drives in one PowerShell call. */
async function status() {
  const { objs } = await ps.json('status.ps1', [], { timeout: 60000 });
  const get = (t) => objs.find((o) => o.type === t) || {};
  return {
    defender: get('defender'),
    hvci: get('hvci').on,
    restoreOn: get('restore').on,
    drives: get('drives').list || [],
  };
}

/**
 * Parses MpCmdRun output. With -DisableRemediation, detections are listed as
 * "Threat information" blocks with "Threat : name" and resource lines such as "file : C:\path".
 */
function parseThreats(out) {
  const threats = [];
  const blocks = String(out || '').split(/-{3,}\s*Threat information\s*-{3,}/i).slice(1);
  for (const b of blocks) {
    const nm = b.match(/^\s*Threat\s*:\s*(.+?)\s*$/im);
    const resources = [];
    const re = /^\s*([A-Za-z]+)\s*:\s*(.+?)\s*$/gm;
    let m;
    while ((m = re.exec(b))) {
      const type = m[1].toLowerCase();
      if (['file', 'containerfile', 'process', 'regkey', 'regkeyvalue', 'service', 'webfile', 'startup', 'folder'].includes(type)) {
        resources.push({ type, path: m[2] });
      }
    }
    if (nm) threats.push({ name: nm[1], resources });
  }
  return threats;
}

/** Custom scan of one file or folder. remediate:false reports only (-DisableRemediation). */
async function scanPath(target, { remediate = false, signal } = {}) {
  const mp = mpcmdrun();
  if (!mp) return { code: -1, threats: [], error: 'Microsoft Defender command-line tool not found.' };
  const args = ['-Scan', '-ScanType', '3', '-File', target];
  if (!remediate) args.push('-DisableRemediation');
  const r = await run(mp, args, { signal });
  const threats = parseThreats(r.stdout);
  // Exit code 2 means both "threats listed" and "scan failed", so failures are read from Defender's own text.
  const hr = (r.stdout.match(/Failed with hr\s*=\s*(0x[0-9a-f]+)/i) || [])[1];
  const failed = !threats.length && !r.aborted && (hr || (r.code !== 0 && r.code !== 2));
  return { code: r.code, threats, hr: hr || null, error: failed ? (hr ? `Defender error ${hr}` : (r.stdout || r.stderr || '').trim().split(/\r?\n/).pop()) : null };
}

async function cancelScans() {
  const mp = mpcmdrun();
  if (mp) await run(mp, ['-Scan', '-Cancel'], { timeout: 20000 });
}

async function updateSignatures(signal) {
  const mp = mpcmdrun();
  if (mp) await run(mp, ['-SignatureUpdate'], { signal, timeout: 240000 });
}

/* Plain-language descriptions and severities by Defender's threat category (the part before ':'). */
const CATEGORY = {
  Ransom: ['Severe', 'Encrypts your files and demands payment to unlock them.'],
  Backdoor: ['Severe', 'Lets someone else control this computer remotely.'],
  Rootkit: ['Severe', 'Hides itself and other malware deep in the system.'],
  Exploit: ['Severe', 'Code that attacks a security hole in another program.'],
  Trojan: ['High', 'Looks harmless but runs harmful actions in the background.'],
  TrojanDownloader: ['High', 'Downloads and runs more malware.'],
  TrojanDropper: ['High', 'Installs more malware when it runs.'],
  TrojanSpy: ['High', 'Watches what you do and sends it to someone else.'],
  PWS: ['High', 'Steals saved passwords.'],
  Spyware: ['High', 'Watches what you do and sends it to someone else.'],
  Worm: ['High', 'Spreads itself to other computers.'],
  Virus: ['High', 'Infects other files on this computer.'],
  HackTool: ['Medium', 'A tool that can be used to break into systems.'],
  MonitoringTool: ['Medium', 'Records activity on this computer.'],
  RemoteAccess: ['Medium', 'Lets someone control this computer remotely.'],
  Behavior: ['Medium', 'Something on this computer acted like malware.'],
  Adware: ['Low', 'Shows unwanted ads.'],
  BrowserModifier: ['Low', 'Changes browser settings without asking.'],
  SoftwareBundler: ['Low', "Installs extra software you didn't ask for."],
  PUA: ['Low', 'Potentially unwanted app, often bundled with other software.'],
  PUADlManager: ['Low', "A download manager that bundles software you didn't ask for."],
  Program: ['Low', 'A program Microsoft Defender considers unwanted.'],
};
function describe(name) {
  if (/EICAR/i.test(name)) return { sev: 'Low', what: 'A harmless test file used to check that antivirus software works.' };
  const cat = String(name).split(':')[0];
  const hit = CATEGORY[cat] || [cat.startsWith('Trojan') ? 'High' : 'Medium', 'Microsoft Defender flagged this as harmful.'];
  return { sev: hit[0], what: hit[1] };
}

module.exports = { mpcmdrun, status, parseThreats, scanPath, cancelScans, updateSignatures, describe };
