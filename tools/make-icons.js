'use strict';
/*
 * Draws the Power Scan icon (yellow rounded square with a power glyph) and writes:
 *   assets/icon.png (512), assets/icon.ico (16-256), assets/tray.png (32), assets/tray@2x.png (64)
 * No dependencies: pixels are computed with 4x4 supersampling and encoded as PNG with zlib.
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const OUT = path.join(__dirname, '..', 'assets');
const YELLOW = [242, 194, 27];
const SHADE = [212, 168, 18];
const INK = [27, 22, 4];

/* ---------- geometry ---------- */
function insideRoundRect(x, y, s, r) {
  if (x < 0 || y < 0 || x > s || y > s) return false;
  const cx = Math.min(Math.max(x, r), s - r);
  const cy = Math.min(Math.max(y, r), s - r);
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}
function distSeg(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}
/* Power glyph in a 24-unit box: stem 12,3.5 -> 12,11.5 and an arc around 12,12.55 r 7.6 with a gap at the top. */
const ARC_C = [12, 12.55], ARC_R = 7.6;
const GAP_A = Math.atan2(7.2 - 12.55, 6.6 - 12); // about -135 degrees
const GAP_B = Math.atan2(7.2 - 12.55, 17.4 - 12); // about -45 degrees
function onGlyph(u, v, w) {
  if (distSeg(u, v, 12, 3.5, 12, 11.5) <= w / 2) return true;
  const a = Math.atan2(v - ARC_C[1], u - ARC_C[0]);
  const inGap = a > GAP_A && a < GAP_B;
  if (!inGap) return Math.abs(Math.hypot(u - ARC_C[0], v - ARC_C[1]) - ARC_R) <= w / 2;
  return Math.hypot(u - 6.6, v - 7.2) <= w / 2 || Math.hypot(u - 17.4, v - 7.2) <= w / 2;
}

function render(size, opts = {}) {
  const ss = 4;
  const radius = size * (opts.radius || 0.23);
  const glyphScale = (size * (opts.glyph || 0.58)) / 24;
  const glyphOff = (size - 24 * glyphScale) / 2;
  const stroke = opts.stroke || (size <= 24 ? 3.1 : size <= 48 ? 2.7 : 2.4);
  const shadeBand = Math.max(1, size * 0.035);
  const px = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const fx = x + (sx + 0.5) / ss, fy = y + (sy + 0.5) / ss;
          if (!insideRoundRect(fx, fy, size, radius)) continue;
          const u = (fx - glyphOff) / glyphScale, v = (fy - glyphOff) / glyphScale;
          let c = YELLOW;
          if (onGlyph(u, v, stroke)) c = INK;
          else if (!insideRoundRect(fx, fy + shadeBand, size, radius)) c = SHADE;
          r += c[0]; g += c[1]; b += c[2]; a += 255;
        }
      }
      const n = ss * ss, i = (y * size + x) * 4;
      if (a > 0) { const k = a / 255; px[i] = Math.round(r / k); px[i + 1] = Math.round(g / k); px[i + 2] = Math.round(b / k); }
      px[i + 3] = Math.round(a / n);
    }
  }
  return px;
}

/* ---------- PNG / ICO encoding ---------- */
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
function crc32(buf) { let c = 0xffffffff; for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, rgba) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) { raw[y * (size * 4 + 1)] = 0; rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4); }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}
function ico(images) {
  const header = Buffer.alloc(6); header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(images.length, 4);
  const dir = Buffer.alloc(16 * images.length);
  let offset = 6 + dir.length;
  images.forEach(({ size, data }, i) => {
    const o = i * 16;
    dir[o] = size >= 256 ? 0 : size; dir[o + 1] = size >= 256 ? 0 : size;
    dir[o + 2] = 0; dir[o + 3] = 0; dir.writeUInt16LE(1, o + 4); dir.writeUInt16LE(32, o + 6);
    dir.writeUInt32LE(data.length, o + 8); dir.writeUInt32LE(offset, o + 12);
    offset += data.length;
  });
  return Buffer.concat([header, dir, ...images.map((im) => im.data)]);
}

fs.mkdirSync(OUT, { recursive: true });
const write = (name, buf) => { fs.writeFileSync(path.join(OUT, name), buf); console.log('wrote', name, buf.length, 'bytes'); };
write('icon.png', png(512, render(512)));
write('icon.ico', ico([16, 24, 32, 48, 64, 128, 256].map((s) => ({ size: s, data: png(s, render(s)) }))));
write('tray.png', png(32, render(32, { radius: 0.26, glyph: 0.66 })));
write('tray@2x.png', png(64, render(64, { radius: 0.26, glyph: 0.66 })));
