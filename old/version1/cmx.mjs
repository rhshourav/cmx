// CMX JavaScript port. Integer-only model; must stay bit-identical to cmx.py.
import zlib from 'node:zlib';
import pako from 'pako';   // pure-JS zlib port: reproduces reference zlib deflate output (Node's built-in zlib does NOT)
import crypto from 'node:crypto';

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const CH = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };

// ---------------------------------------------------------------- tables
const _T = [1, 2, 3, 6, 10, 16, 27, 45, 73, 120, 194, 310, 488, 747, 1101, 1546, 2047, 2549,
  2994, 3348, 3607, 3785, 3901, 3975, 4022, 4050, 4068, 4079, 4085, 4089, 4092, 4093, 4094];
function squash(d) {
  if (d > 2047) return 4095;
  if (d < -2047) return 0;
  const w = d & 127;
  d = (d >> 7) + 16;
  return (_T[d] * (128 - w) + _T[d + 1] * w + 64) >> 7;
}
const STRETCH = new Int16Array(4096);
{
  let pi = 0;
  for (let x = -2047; x < 2048; x++) {
    const v = squash(x);
    for (let i = pi; i <= v; i++) STRETCH[i] = x;
    pi = v + 1;
  }
  for (let i = pi; i < 4096; i++) STRETCH[i] = 2047;
}
const SQ = new Int16Array(4095);
for (let d = -2047; d <= 2047; d++) SQ[d + 2047] = squash(d);
const RT = new Int32Array(256);
for (let n = 0; n < 256; n++) RT[n] = Math.floor(8192 / (2 * n + 3));

const _QT = [0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128];
const QE = new Int32Array(1024);
for (let e = 0; e < 1024; e++) { let k = 0; for (const t of _QT) if (e >= t) k++; QE[e] = k - 1; }

function H(...v) {
  let h = 0x811C9DC5;
  for (const a of v) {
    h = Math.imul((h ^ a) >>> 0, 0x01000193) >>> 0;
    h = (h ^ (h >>> 15)) >>> 0;
  }
  return h;
}

// ---------------------------------------------------------------- arithmetic coder
class Enc {
  constructor() { this.x1 = 0; this.x2 = 0xFFFFFFFF; this.out = []; }
  code(bit, p) {
    const xmid = this.x1 + ((this.x2 - this.x1) >>> 12) * p;
    if (bit) this.x2 = xmid; else this.x1 = xmid + 1;
    while ((((this.x1 ^ this.x2) >>> 0) & 0xFF000000) === 0) {
      this.out.push(this.x2 >>> 24);
      this.x1 = (this.x1 << 8) >>> 0;
      this.x2 = (((this.x2 << 8) >>> 0) | 255) >>> 0;
    }
    return bit;
  }
  finish() {
    for (let nb = 1; nb <= 4; nb++) {
      const sh = 32 - 8 * nb;
      const unit = 2 ** sh;
      const v = Math.ceil(this.x1 / unit) * unit;
      if (v <= this.x2 && v <= 0xFFFFFFFF) {
        for (let i = 0; i < nb; i++) this.out.push(Math.floor(v / 2 ** (24 - 8 * i)) & 255);
        break;
      }
    }
    let n = this.out.length;
    while (n > 0 && this.out[n - 1] === 0) n--;
    return Buffer.from(this.out.slice(0, n));
  }
}
class Dec {
  constructor(d) {
    this.d = d; this.pos = 0; this.x1 = 0; this.x2 = 0xFFFFFFFF; this.x = 0;
    for (let i = 0; i < 4; i++) this.x = ((this.x << 8) | this._nb()) >>> 0;
  }
  _nb() { const b = this.pos < this.d.length ? this.d[this.pos] : 0; this.pos++; return b; }
  code(_b, p) {
    const xmid = this.x1 + ((this.x2 - this.x1) >>> 12) * p;
    const bit = this.x <= xmid ? 1 : 0;
    if (bit) this.x2 = xmid; else this.x1 = xmid + 1;
    while ((((this.x1 ^ this.x2) >>> 0) & 0xFF000000) === 0) {
      this.x1 = (this.x1 << 8) >>> 0;
      this.x2 = (((this.x2 << 8) >>> 0) | 255) >>> 0;
      this.x = (((this.x << 8) >>> 0) | this._nb()) >>> 0;
    }
    return bit;
  }
}

// ---------------------------------------------------------------- CM engine
const LR = 2, SH = 10, LIMIT = 250, WI = Math.floor(65536 * 12 / 100), BITS_ADD = 5;
function bitsFor(n) { return Math.max(16, Math.min(22, (n === 0 ? 0 : 32 - Math.clz32(n)) + BITS_ADD)); }

class CM {
  constructor(nctx, nsel, nsel2, bits) {
    this.n = nctx; this.nin = nctx + 1; this.shift = 32 - bits;
    const size = 1 << bits;
    this.pt = []; this.ct = [];
    for (let i = 0; i < nctx; i++) { this.pt.push(new Uint16Array(size).fill(32768)); this.ct.push(new Uint8Array(size)); }
    this.w1 = []; this.w2 = [];
    for (let i = 0; i < nsel * 8; i++) this.w1.push(new Float64Array(this.nin).fill(WI));
    for (let i = 0; i < nsel2 * 8; i++) this.w2.push(new Float64Array(this.nin).fill(WI));
    this.apm = [];
    for (let c = 0; c < 256; c++) { const a = new Int32Array(33); for (let i = 0; i < 33; i++) a[i] = squash((i - 16) * 128) * 16; this.apm.push(a); }
    this.idx = new Int32Array(nctx); this.x = new Int32Array(this.nin);
  }
  codeByte(coder, sym, ctxs, msel, msel2) {
    const n = this.n, nin = this.nin, shift = this.shift, pt = this.pt, ct = this.ct, idx = this.idx, x = this.x;
    let c0 = 1; x[n] = 256;
    for (let bi = 7; bi >= 0; bi--) {
      const cm = Math.imul(c0, 0x9E3779B1);
      for (let j = 0; j < n; j++) {
        const ix = Math.imul(ctxs[j] ^ cm, 0x85EBCA6B) >>> shift;
        idx[j] = ix; x[j] = STRETCH[pt[j][ix] >> 4];
      }
      const w1 = this.w1[msel * 8 + bi], w2 = this.w2[msel2 * 8 + bi];
      let dot1 = 0, dot2 = 0;
      for (let j = 0; j < nin; j++) { dot1 += x[j] * w1[j]; dot2 += x[j] * w2[j]; }
      let d1 = Math.floor(dot1 / 65536), d2 = Math.floor(dot2 / 65536);
      if (d1 > 2047) d1 = 2047; else if (d1 < -2047) d1 = -2047;
      if (d2 > 2047) d2 = 2047; else if (d2 < -2047) d2 = -2047;
      const p1 = SQ[d1 + 2047], p2 = SQ[d2 + 2047];
      const dm = (d1 + d2) >> 1;
      const pm = SQ[dm + 2047];
      const a = this.apm[c0];
      const pos = (dm + 2048) * 32;
      const lo = pos >> 12, wt = pos & 4095;
      const pa = (a[lo] * (4096 - wt) + a[lo + 1] * wt) >> 16;
      let p = (pm + 3 * pa + 2) >> 2;
      if (p < 1) p = 1; else if (p > 4095) p = 4095;
      const bit = coder.code(sym === null ? 0 : (sym >> bi) & 1, p);
      const tg = bit << 16;
      a[lo] += (tg - a[lo]) >> 6; a[lo + 1] += (tg - a[lo + 1]) >> 6;
      const e1 = ((bit << 12) - p1) * LR, e2 = ((bit << 12) - p2) * LR;
      for (let j = 0; j < nin; j++) { w1[j] += (x[j] * e1) >> SH; w2[j] += (x[j] * e2) >> SH; }
      for (let j = 0; j < n; j++) {
        const t = pt[j], ix = idx[j], c = ct[j], k = c[ix];
        t[ix] += ((tg - t[ix]) * RT[k]) >> 12;
        if (k < LIMIT) c[ix] = k + 1;
      }
      c0 = (c0 << 1) | bit;
    }
    return c0 & 255;
  }
}

// ---------------------------------------------------------------- model states
class GenState {
  constructor() { this.NCTX = 8; this.NSEL = 1; this.NSEL2 = 8; this.lo = 0; this.hi = 0; }
  ctx() {
    const lo = this.lo, hi = this.hi;
    return [[H(0), H(1, lo & 0xFF), H(2, lo & 0xFFFF), H(3, lo & 0xFFFFFF), H(4, lo),
      H(5, lo, hi & 0xFFFF), H(6, (lo >>> 8) & 0xFF), H(7, (lo >>> 16) & 0xFFFF)], 0, (lo & 0xFF) >> 5];
  }
  toSym(a) { return a; }
  push(sym) {
    this.hi = (((this.hi << 8) | (this.lo >>> 24)) >>> 0);
    this.lo = (((this.lo << 8) | sym) >>> 0);
    return sym;
  }
}
function qz(v) { if (v < 3) return v; if (v < 5) return 3; if (v < 9) return 4; if (v < 17) return 5; if (v < 33) return 6; return 7; }
function cl(v, m) { return v > m ? m : (v < -m ? -m : v); }
function leFold(buf, s, len) {  // bytes little-endian -> [lo32, hi32]
  let lo = 0, hi = 0;
  for (let i = 0; i < len; i++) {
    const b = buf[s + i];
    if (i < 4) lo = (lo + b * 2 ** (8 * i)); else hi = (hi + b * 2 ** (8 * (i - 4)));
  }
  return [lo >>> 0, hi >>> 0];
}
class ImgState {
  constructor(rb, bpp, n) {
    this.NCTX = 14; this.NSEL = bpp; this.NSEL2 = 8;
    this.rb = rb; this.bpp = bpp; this.buf = new Uint8Array(n); this.res = new Uint8Array(n); this.i = 0; this.pred = 0;
  }
  ctx() {
    const i = this.i, rb = this.rb, bpp = this.bpp, buf = this.buf, res = this.res;
    const r = Math.floor(i / rb), cb = i - r * rb, k = cb % bpp, hasW = cb >= bpp;
    let W, N, NW, NE, rW, rN, rNW, rNE;
    if (r) {
      N = buf[i - rb]; rN = res[i - rb];
      if (hasW) { W = buf[i - bpp]; rW = res[i - bpp]; NW = buf[i - rb - bpp]; rNW = res[i - rb - bpp]; }
      else { W = N; rW = 0; NW = N; rNW = 0; }
      if (cb + bpp < rb) { NE = buf[i - rb + bpp]; rNE = res[i - rb + bpp]; } else { NE = N; rNE = rN; }
    } else {
      if (hasW) { W = buf[i - bpp]; rW = res[i - bpp]; } else { W = 0; rW = 0; }
      N = NW = NE = W; rN = rNW = rNE = 0;
    }
    let P1 = 0, R1 = 0, P2 = 0;
    if (k > 0) { P1 = buf[i - 1]; R1 = res[i - 1]; P2 = k > 1 ? buf[i - 2] : 0; }
    let pred;
    if (NW >= Math.max(W, N)) pred = Math.min(W, N);
    else if (NW <= Math.min(W, N)) pred = Math.max(W, N);
    else pred = W + N - NW;
    this.pred = pred;
    const g = Math.abs(W - NW) + Math.abs(N - NW) + Math.abs(N - NE);
    const e = ((rW + 1) >> 1) + ((rN + 1) >> 1) + ((((rNW + 1) >> 1) + ((rNE + 1) >> 1)) >> 1);
    const e2 = e + ((R1 + 1) >> 1);
    const qe = QE[e < 1023 ? e : 1023], qe2 = QE[e2 < 1023 ? e2 : 1023];
    const bs = i - k;
    let Wp = 0, Np, Cp;
    if (hasW) { const f = leFold(buf, bs - bpp, bpp); Wp = (f[0] ^ f[1]) >>> 0; }
    if (r) { const f = leFold(buf, bs - rb, bpp); Np = (f[0] ^ f[1]) >>> 0; } else Np = Wp;
    Cp = leFold(buf, bs, k)[0];            // python uses the low 32 bits only
    return [[H(0, k), H(1, k, rW, rN), H(2, k, R1, rW), H(3, k, W, N, NW),
      H(4, k, pred), H(5, k, Math.min(g, 255) >> 2, qz(rW), qz(rN)),
      H(6, k, N, NE), H(7, k, P1, P2, W), H(8, k, rW, rN, rNW, rNE),
      H(9, k, qe, qz(R1)), H(10, k, cl(W - pred, 12), cl(N - pred, 12)),
      H(11, k, Wp, Cp), H(12, k, Wp, Np, Cp), H(13, k, qe2, pred >> 4)], k, qe2 >> 1];
  }
  toSym(a) { let r = (a - this.pred) & 255; if (r >= 128) r -= 256; return r >= 0 ? 2 * r : -2 * r - 1; }
  push(sym) {
    const v = (this.pred + ((sym & 1) === 0 ? (sym >> 1) : -((sym + 1) >> 1))) & 255;
    this.buf[this.i] = v; this.res[this.i] = sym; this.i++;
    return v;
  }
}
function runEnc(state, data, image) {
  const coder = new Enc(), cm = new CM(state.NCTX, state.NSEL, state.NSEL2, bitsFor(data.length));
  for (const a of data) {
    const [ctxs, ms, ms2] = state.ctx();
    const sym = image ? state.toSym(a) : a;
    cm.codeByte(coder, sym, ctxs, ms, ms2); state.push(sym);
  }
  return coder.finish();
}
function runDec(state, blob, n) {
  const coder = new Dec(blob), cm = new CM(state.NCTX, state.NSEL, state.NSEL2, bitsFor(n));
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) {
    const [ctxs, ms, ms2] = state.ctx();
    out[i] = state.push(cm.codeByte(coder, null, ctxs, ms, ms2));
  }
  return out;
}
export const cmEnc = (d) => runEnc(new GenState(), d, false);
export const cmDec = (b, n) => runDec(new GenState(), b, n);
export const imgDec = (b, n, rb, bpp) => runDec(new ImgState(rb, bpp, n), b, n);

// ---------------------------------------------------------------- varint, filters
function vput(n) { const o = []; for (;;) { const b = n & 127; n = Math.floor(n / 128); if (n) o.push(b | 128); else { o.push(b); return Buffer.from(o); } } }
function vget(d, p) { let n = 0, sh = 0; for (;;) { const b = d[p++]; n += (b & 127) * 2 ** sh; sh += 7; if (!(b & 128)) return [n, p]; } }
function paeth(a, b, c) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); return pa <= pb && pa <= pc ? a : (pb <= pc ? b : c); }
function refilter(pix, ft, h, rb, bpp) {
  const out = Buffer.alloc(h * (rb + 1)); let prev = Buffer.alloc(rb);
  for (let r = 0; r < h; r++) {
    const cur = pix.subarray(r * rb, (r + 1) * rb), t = ft[r], o = r * (rb + 1);
    out[o] = t;
    for (let i = 0; i < rb; i++) {
      const a = i >= bpp ? cur[i - bpp] : 0, b = prev[i], c = i >= bpp ? prev[i - bpp] : 0;
      let pr = 0;
      if (t === 1) pr = a; else if (t === 2) pr = b; else if (t === 3) pr = (a + b) >> 1; else if (t === 4) pr = paeth(a, b, c);
      out[o + 1 + i] = (cur[i] - pr) & 255;
    }
    prev = cur;
  }
  return out;
}
function pngDecode(pl) {
  const level = pl[0] & 15, mem = pl[0] >> 4, strat = pl[1], wb = pl[2];
  let p = 3, ml, mcl, fcl;
  [ml, p] = vget(pl, p); [mcl, p] = vget(pl, p);
  const meta = cmDec(pl.subarray(p, p + mcl), ml); p += mcl;
  [fcl, p] = vget(pl, p); const fc = pl.subarray(p, p + fcl); p += fcl; const pc = pl.subarray(p);
  let q = 0; const ents = [];
  for (;;) {
    const typ = meta.subarray(q, q + 4).toString('latin1'); let ln; [ln, q] = vget(meta, q + 4);
    if (typ === 'IDAT') ents.push([typ, ln, null]); else { ents.push([typ, ln, meta.subarray(q, q + ln)]); q += ln; }
    if (typ === 'IEND') break;
  }
  let tl; [tl, q] = vget(meta, q); const tail = meta.subarray(q, q + tl);
  const hd = ents[0][2], w = hd.readUInt32BE(0), h = hd.readUInt32BE(4), depth = hd[8], ct = hd[9];
  const bpp = CH[ct] * depth / 8, rb = w * bpp;
  const ft = cmDec(fc, h), pix = imgDec(pc, h * rb, rb, bpp);
  const stream = Buffer.from(pako.deflate(refilter(pix, ft, h, rb, bpp), { level, memLevel: mem, strategy: strat, windowBits: wb }));
  const parts = [PNG_SIG]; let sp = 0;
  for (const [typ, ln, d0] of ents) {
    let data = d0; if (typ === 'IDAT') { data = stream.subarray(sp, sp + ln); sp += ln; }
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const tb = Buffer.from(typ, 'latin1'), crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(Buffer.concat([tb, data])) >>> 0);
    parts.push(len, tb, data, crc);
  }
  parts.push(tail);
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- container
const sha4 = (b) => crypto.createHash('sha256').update(b).digest().subarray(0, 4);
export function decode(blob) {
  const mode = blob[0], chk = blob.subarray(1, 5); const [n, p] = vget(blob, 5); const pl = blob.subarray(p);
  let out;
  if (mode === 0) out = pl; else if (mode === 1) out = cmDec(pl, n); else if (mode === 2) out = pngDecode(pl); else throw new Error('unknown mode');
  if (out.length !== n || !sha4(out).equals(chk)) throw new Error('integrity check failed');
  return out;
}
export function encodeGeneric(orig) {   // JS encoder: stored or generic CM (PNG re-deflate path lives in the Python/native encoder)
  const wrap = (m, pl) => Buffer.concat([Buffer.from([m]), sha4(orig), vput(orig.length), pl]);
  let best = wrap(0, orig);
  const c = wrap(1, cmEnc(orig));
  if (c.length < best.length && decode(c).equals(orig)) best = c;
  return best;
}

// ---------------------------------------------------------------- base85 (JSON-safe alphabet)
const A = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%()*+,-./:;=?@[]^_{|';
const R = {}; for (let i = 0; i < 85; i++) R[A[i]] = i;
export function toText(b) {
  let out = '';
  for (let i = 0; i < b.length; i += 4) {
    const m = Math.min(4, b.length - i); let v = 0;
    for (let j = 0; j < 4; j++) v = v * 256 + (j < m ? b[i + j] : 0);
    const d = []; for (let j = 0; j < 5; j++) { d.push(A[v % 85]); v = Math.floor(v / 85); }
    d.reverse(); out += m < 4 ? d.join('').slice(0, m + 1) : d.join('');
  }
  return out;
}
export function fromText(s) {
  const out = [];
  for (let i = 0; i < s.length; i += 5) {
    const g = s.slice(i, i + 5), m = g.length; let v = 0;
    const padded = g + A[84].repeat(5 - m);
    for (const ch of padded) v = v * 85 + R[ch];
    const bytes = [Math.floor(v / 16777216) & 255, Math.floor(v / 65536) & 255, Math.floor(v / 256) & 255, v & 255];
    out.push(...(m < 5 ? bytes.slice(0, m - 1) : bytes));
  }
  return Buffer.from(out);
}
export const decompressFromJson = (s) => decode(fromText(JSON.parse(s).d));
export const compressToJson = (data) => JSON.stringify({ cmx: 1, d: toText(encodeGeneric(data)) });

// CLI: node cmx.mjs dec in.json out.bin | enc in.bin out.json
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, a, b] = process.argv.slice(2);
  if (mode === 'dec') fs.writeFileSync(b, decompressFromJson(fs.readFileSync(a, 'utf8')));
  else if (mode === 'enc') fs.writeFileSync(b, compressToJson(fs.readFileSync(a)));
}
