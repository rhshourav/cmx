/* cmxc.c - native core for .cmx : modes 0 (stored), 1 (generic CM, profile 1), 3 (lossless JPEG).
 * Bit-exact with cmx.py / cmx.mjs (integer-only model).  Single file, no dependencies.
 *   build:  gcc -O2 -o cmxc cmxc.c        (or: cl /O2 cmxc.c /Fe:cmxc.exe)
 *   use:    cmxc pack in out.cmx | cmxc unpack in.cmx out
 *   exit:   0 ok, 1 error/corrupt, 2 unsupported here (PNG, progressive JPEG, ...) -> use cmx.py
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int16_t i16; typedef int32_t i32; typedef int64_t i64;

static void die(const char *m) { fprintf(stderr, "cmxc: %s\n", m); exit(1); }
static void unsup(const char *m) { fprintf(stderr, "cmxc: unsupported (%s) -> use cmx.py\n", m); exit(2); }
static void *xcalloc(size_t n, size_t s) { void *p = calloc(n ? n : 1, s ? s : 1); if (!p) die("out of memory"); return p; }

/* ---------------------------------------------------------------- byte buffer + varint */
typedef struct { u8 *p; size_t n, cap; } Buf;
static void bput(Buf *b, u8 v) {
  if (b->n == b->cap) { b->cap = b->cap ? b->cap * 2 : 4096; b->p = (u8 *)realloc(b->p, b->cap); if (!b->p) die("out of memory"); }
  b->p[b->n++] = v;
}
static void bcat(Buf *b, const u8 *d, size_t n) { for (size_t i = 0; i < n; i++) bput(b, d[i]); }
static void vput(Buf *b, u64 n) { for (;;) { u8 v = n & 127; n >>= 7; if (n) bput(b, v | 128); else { bput(b, v); return; } } }
static u64 vget(const u8 *d, size_t len, size_t *p) {
  u64 n = 0; int sh = 0;
  for (;;) { if (*p >= len || sh > 56) die("corrupt varint"); u8 b = d[(*p)++]; n |= (u64)(b & 127) << sh; sh += 7; if (!(b & 128)) return n; }
}

/* ---------------------------------------------------------------- SHA-256 (integrity check) */
static const u32 K256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(u32 *h, const u8 *p) {
  u32 w[64], a, b, c, d, e, f, g, hh;
  for (int i = 0; i < 16; i++) w[i] = ((u32)p[4 * i] << 24) | ((u32)p[4 * i + 1] << 16) | ((u32)p[4 * i + 2] << 8) | p[4 * i + 3];
  for (int i = 16; i < 64; i++) {
    u32 s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3), s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
  for (int i = 0; i < 64; i++) {
    u32 S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25), ch = (e & f) ^ (~e & g), t1 = hh + S1 + ch + K256[i] + w[i];
    u32 S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = S0 + mj;
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}
static void sha4(const u8 *d, size_t n, u8 out[4]) {
  u32 h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  size_t i = 0;
  for (; i + 64 <= n; i += 64) sha_block(h, d + i);
  u8 tail[128]; size_t r = n - i; memset(tail, 0, sizeof tail); memcpy(tail, d + i, r); tail[r] = 0x80;
  size_t tl = (r < 56) ? 64 : 128; u64 bits = (u64)n * 8;
  for (int k = 0; k < 8; k++) tail[tl - 1 - k] = (u8)(bits >> (8 * k));
  sha_block(h, tail); if (tl == 128) sha_block(h, tail + 64);
  for (int k = 0; k < 4; k++) out[k] = (u8)(h[0] >> (24 - 8 * k));
}

/* ---------------------------------------------------------------- tables (integer only) */
static const int T33[33] = {1, 2, 3, 6, 10, 16, 27, 45, 73, 120, 194, 310, 488, 747, 1101, 1546, 2047, 2549,
                            2994, 3348, 3607, 3785, 3901, 3975, 4022, 4050, 4068, 4079, 4085, 4089, 4092, 4093, 4094};
static int squash_(int d) {
  if (d > 2047) return 4095;
  if (d < -2047) return 0;
  int w = d & 127; d = (d >> 7) + 16;
  return (T33[d] * (128 - w) + T33[d + 1] * w + 64) >> 7;
}
static int STRETCH[4096], SQ[4095], RT[256], QE[1024], QN[64], QM[2048], QR[64];
static const int ZZ[64] = {0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27,
                           20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
                           58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63};
static int ZZINV[64];
static const i64 DM[8][8] = {
  {5793, 8035, 7568, 6811, 5793, 4551, 3135, 1598}, {5793, 6811, 3135, -1598, -5793, -8035, -7568, -4551},
  {5793, 4551, -3135, -8035, -5793, 1598, 7568, 6811}, {5793, 1598, -7568, -4551, 5793, 6811, -3135, -8035},
  {5793, -1598, -7568, 4551, 5793, -6811, -3135, 8035}, {5793, -4551, -3135, 8035, -5793, -1598, 7568, -6811},
  {5793, -6811, 3135, 1598, -5793, 8035, -7568, 4551}, {5793, -8035, 7568, -6811, 5793, -4551, 3135, -1598}};
static void mkq(int *out, const int *th, int nth, int n) {
  for (int v = 0; v < n; v++) { int k = 0; for (int t = 0; t < nth; t++) if (v >= th[t]) k++; out[v] = k ? k - 1 : 0; }
}
static void init_tables(void) {
  int pi = 0;
  for (int x = -2047; x < 2048; x++) { int v = squash_(x); for (int i = pi; i <= v; i++) STRETCH[i] = x; pi = v + 1; }
  for (int i = pi; i < 4096; i++) STRETCH[i] = 2047;
  for (int d = -2047; d <= 2047; d++) SQ[d + 2047] = squash_(d);
  for (int n = 0; n < 256; n++) RT[n] = 8192 / (2 * n + 3);
  static const int qt[] = {0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128};
  mkq(QE, qt, 15, 1024);
  static const int qn[] = {0, 1, 2, 3, 4, 5, 7, 9, 13, 19, 29, 43}; mkq(QN, qn, 12, 64);
  static const int qm[] = {0, 1, 2, 3, 4, 5, 7, 10, 15, 25, 50, 100}; mkq(QM, qm, 12, 2048);
  static const int qr[] = {1, 2, 3, 4, 6, 9, 14, 22, 35, 50}; mkq(QR, qr, 10, 64);
  for (int i = 0; i < 64; i++) ZZINV[ZZ[i]] = i;
}

/* hash: FNV-style fold, identical to Python H() / JS H() */
static inline u32 hs_(u32 h, u32 a) { h = (h ^ a) * 0x01000193u; return h ^ (h >> 15); }
#define HB 0x811C9DC5u
static inline u32 H0(void) { return HB; }
static inline u32 H1(int a) { return hs_(HB, (u32)a); }
static inline u32 H2(int a, int b) { return hs_(H1(a), (u32)b); }
static inline u32 H3(int a, int b, int c) { return hs_(H2(a, b), (u32)c); }
static inline u32 H4(int a, int b, int c, int d) { return hs_(H3(a, b, c), (u32)d); }
static inline u32 H5(int a, int b, int c, int d, int e) { return hs_(H4(a, b, c, d), (u32)e); }
static inline u32 H6(int a, int b, int c, int d, int e, int f) { return hs_(H5(a, b, c, d, e), (u32)f); }
static inline u32 H3u(u32 a, int b, int c) { return hs_(hs_(hs_(HB, a), (u32)b), (u32)c); }

/* ---------------------------------------------------------------- arithmetic coder */
typedef struct { u32 x1, x2, x; Buf out; const u8 *d; size_t pos, len; int dec; } Coder;
static u8 nextbyte(Coder *c) { return c->pos < c->len ? c->d[c->pos++] : (c->pos++, 0); }
static void enc_init(Coder *c) { memset(c, 0, sizeof *c); c->x2 = 0xFFFFFFFFu; }
static void dec_init(Coder *c, const u8 *d, size_t n) {
  memset(c, 0, sizeof *c); c->x2 = 0xFFFFFFFFu; c->dec = 1; c->d = d; c->len = n;
  for (int i = 0; i < 4; i++) c->x = (c->x << 8) | nextbyte(c);
}
static int coder_code(Coder *c, int bit, int p) {
  u32 xmid = c->x1 + ((c->x2 - c->x1) >> 12) * (u32)p;
  if (c->dec) bit = c->x <= xmid;
  if (bit) c->x2 = xmid; else c->x1 = xmid + 1;
  while (((c->x1 ^ c->x2) & 0xFF000000u) == 0) {
    if (!c->dec) bput(&c->out, (u8)(c->x2 >> 24));
    c->x1 <<= 8; c->x2 = (c->x2 << 8) | 255;
    if (c->dec) c->x = (c->x << 8) | nextbyte(c);
  }
  return bit;
}
static void enc_finish(Coder *c) {
  for (int nb = 1; nb <= 4; nb++) {
    int sh = 32 - 8 * nb; u64 unit = 1ULL << sh, v = (((u64)c->x1 + unit - 1) / unit) * unit;
    if (v <= c->x2 && v <= 0xFFFFFFFFULL) { for (int i = 0; i < nb; i++) bput(&c->out, (u8)(v >> (24 - 8 * i))); break; }
  }
  while (c->out.n > 0 && c->out.p[c->out.n - 1] == 0) c->out.n--;
}

/* ---------------------------------------------------------------- context-mixing engine */
#define LR_ 2
#define SH_ 10
#define LIMIT_ 250
#define WI_ (65536 * 12 / 100)
typedef struct { int n, nin, shift; u16 **pt; u8 **ct; i64 *w1, *w2; i32 *apm; } CM;
static CM *cm_new(int nctx, int nsel, int nsel2, int bits) {
  CM *m = (CM *)xcalloc(1, sizeof *m); size_t size = (size_t)1 << bits;
  m->n = nctx; m->nin = nctx + 1; m->shift = 32 - bits;
  m->pt = (u16 **)xcalloc(nctx, sizeof(u16 *)); m->ct = (u8 **)xcalloc(nctx, sizeof(u8 *));
  for (int j = 0; j < nctx; j++) { m->pt[j] = (u16 *)xcalloc(size, 2); for (size_t i = 0; i < size; i++) m->pt[j][i] = 32768; m->ct[j] = (u8 *)xcalloc(size, 1); }
  m->w1 = (i64 *)xcalloc((size_t)nsel * 8 * m->nin, 8); m->w2 = (i64 *)xcalloc((size_t)nsel2 * 8 * m->nin, 8);
  for (size_t i = 0; i < (size_t)nsel * 8 * m->nin; i++) m->w1[i] = WI_;
  for (size_t i = 0; i < (size_t)nsel2 * 8 * m->nin; i++) m->w2[i] = WI_;
  m->apm = (i32 *)xcalloc(256 * 33, 4);
  for (int c = 0; c < 256; c++) for (int i = 0; i < 33; i++) m->apm[c * 33 + i] = squash_((i - 16) * 128) * 16;
  return m;
}
static void cm_free(CM *m) {
  for (int j = 0; j < m->n; j++) { free(m->pt[j]); free(m->ct[j]); }
  free(m->pt); free(m->ct); free(m->w1); free(m->w2); free(m->apm); free(m);
}
/* shared tail: mix two weight sets, APM, code the bit, update everything */
static int mix_code(CM *m, Coder *cd, int bitin, i64 *w1, i64 *w2, i32 *a, const int *x, const int *idx) {
  int n = m->n, nin = m->nin; i64 dot1 = 0, dot2 = 0;
  for (int j = 0; j < nin; j++) { dot1 += (i64)x[j] * w1[j]; dot2 += (i64)x[j] * w2[j]; }
  i64 t1 = dot1 >> 16, t2 = dot2 >> 16;
  int d1 = t1 > 2047 ? 2047 : (t1 < -2047 ? -2047 : (int)t1), d2 = t2 > 2047 ? 2047 : (t2 < -2047 ? -2047 : (int)t2);
  int p1 = SQ[d1 + 2047], p2 = SQ[d2 + 2047], dm = (d1 + d2) >> 1, pm = SQ[dm + 2047];
  int pos = (dm + 2048) * 32, lo = pos >> 12, wt = pos & 4095;
  int pa = (int)(((i64)a[lo] * (4096 - wt) + (i64)a[lo + 1] * wt) >> 16);
  int p = (pm + 3 * pa + 2) >> 2; if (p < 1) p = 1; else if (p > 4095) p = 4095;
  int bit = coder_code(cd, bitin, p), tg = bit << 16;
  a[lo] += (tg - a[lo]) >> 6; a[lo + 1] += (tg - a[lo + 1]) >> 6;
  int e1 = ((bit << 12) - p1) * LR_, e2 = ((bit << 12) - p2) * LR_;
  for (int j = 0; j < nin; j++) { w1[j] += (x[j] * e1) >> SH_; w2[j] += (x[j] * e2) >> SH_; }
  for (int j = 0; j < n; j++) {
    u16 *t = m->pt[j]; int ix = idx[j]; u8 *c = m->ct[j]; int k = c[ix];
    t[ix] = (u16)(t[ix] + (((tg - (int)t[ix]) * RT[k]) >> 12));
    if (k < LIMIT_) c[ix] = (u8)(k + 1);
  }
  return bit;
}
static int cm_bit(CM *m, Coder *cd, int bit, const u32 *hs, int msel, int msel2, int ai) {
  int idx[8], x[9];
  for (int j = 0; j < m->n; j++) { int ix = (int)((hs[j] * 0x85EBCA6Bu) >> m->shift); idx[j] = ix; x[j] = STRETCH[m->pt[j][ix] >> 4]; }
  x[m->n] = 256;
  return mix_code(m, cd, bit, m->w1 + (size_t)msel * m->nin, m->w2 + (size_t)msel2 * m->nin, m->apm + ai * 33, x, idx);
}
static int cm_byte(CM *m, Coder *cd, int sym, const u32 *ctxs, int msel, int msel2) { /* sym<0 when decoding */
  int idx[8], x[9], c0 = 1; x[m->n] = 256;
  for (int bi = 7; bi >= 0; bi--) {
    u32 cmx = (u32)c0 * 0x9E3779B1u;
    for (int j = 0; j < m->n; j++) { int ix = (int)(((ctxs[j] ^ cmx) * 0x85EBCA6Bu) >> m->shift); idx[j] = ix; x[j] = STRETCH[m->pt[j][ix] >> 4]; }
    int bit = mix_code(m, cd, sym < 0 ? 0 : (sym >> bi) & 1, m->w1 + (size_t)(msel * 8 + bi) * m->nin,
                       m->w2 + (size_t)(msel2 * 8 + bi) * m->nin, m->apm + c0 * 33, x, idx);
    c0 = (c0 << 1) | bit;
  }
  return c0 & 255;
}
static int bits_for(size_t n) { int bl = 0; while (n >> bl) bl++; bl += 5; return bl < 16 ? 16 : (bl > 22 ? 22 : bl); }

/* generic byte model (profile 1) */
static void gen_ctx(u64 v, u32 *c, int *ms2) {
  c[0] = H0(); c[1] = H2(1, (int)(v & 0xFF)); c[2] = H2(2, (int)(v & 0xFFFF)); c[3] = H2(3, (int)(v & 0xFFFFFF));
  c[4] = H2(4, (int)(u32)v); c[5] = H3(5, (int)(u32)v, (int)((v >> 32) & 0xFFFF));
  c[6] = H2(6, (int)((v >> 8) & 0xFF)); c[7] = H2(7, (int)((v >> 16) & 0xFFFF)); *ms2 = (int)((v & 0xFF) >> 5);
}
static Buf cm_enc_bytes(const u8 *d, size_t n) {
  Coder cd; enc_init(&cd); CM *m = cm_new(8, 1, 8, bits_for(n)); u64 v = 0; u32 c[8]; int ms2;
  for (size_t i = 0; i < n; i++) { gen_ctx(v, c, &ms2); cm_byte(m, &cd, d[i], c, 0, ms2); v = (v << 8) | d[i]; }
  enc_finish(&cd); cm_free(m); return cd.out;
}
static void cm_dec_bytes(const u8 *blob, size_t bl, size_t n, u8 *out) {
  Coder cd; dec_init(&cd, blob, bl); CM *m = cm_new(8, 1, 8, bits_for(n)); u64 v = 0; u32 c[8]; int ms2;
  for (size_t i = 0; i < n; i++) { gen_ctx(v, c, &ms2); int s = cm_byte(m, &cd, -1, c, 0, ms2); out[i] = (u8)s; v = (v << 8) | (u8)s; }
  cm_free(m);
}

/* ---------------------------------------------------------------- JPEG: structures */
typedef struct { int counts[16], nsym; u8 syms[256]; int present, mincode[17], maxcode[17], valptr[17]; u32 ecode[256]; u8 elen[256]; } Huff;
typedef struct {
  int W, H, nc, dri, end, ph, pv;
  int cid[3], ch[3], cv[3], ctq[3];
  int qt[4][64], qpresent[4];
  Huff dht[2][4];
  int scan_td[3], scan_ta[3];
  int bw[3], bh[3], mx, my;
} Hdr;

static void huff_build(Huff *t) {
  int code = 0, k = 0;
  for (int l = 1; l <= 16; l++) {
    int c = t->counts[l - 1]; t->valptr[l] = k; t->mincode[l] = code; t->maxcode[l] = c ? code + c - 1 : -1;
    for (int i = 0; i < c; i++) { int s = t->syms[k + i]; t->ecode[s] = (u32)(code + i); t->elen[s] = (u8)l; }
    code += c; k += c; code <<= 1;
  }
}
/* returns 0 on success, 2 on unsupported/invalid */
static int parse_hdr(const u8 *d, size_t n, Hdr *h) {
  memset(h, 0, sizeof *h);
  if (n < 4 || d[0] != 0xFF || d[1] != 0xD8) return 2;
  size_t p = 2; int have_sof = 0;
  for (;;) {
    if (p + 4 > n || d[p] != 0xFF) return 2;
    int m = d[p + 1]; if (m == 0xFF) { p++; continue; }
    size_t L = ((size_t)d[p + 2] << 8) | d[p + 3]; if (L < 2 || p + 2 + L > n) return 2;
    const u8 *seg = d + p + 4; size_t sl = L - 2;
    if (m == 0xC0 || m == 0xC1) {
      if (sl < 6 || seg[0] != 8) return 2;
      h->H = (seg[1] << 8) | seg[2]; h->W = (seg[3] << 8) | seg[4]; h->nc = seg[5];
      if ((h->nc != 1 && h->nc != 3) || sl < (size_t)(6 + 3 * h->nc) || !h->W || !h->H) return 2;
      for (int i = 0; i < h->nc; i++) { h->cid[i] = seg[6 + 3 * i]; h->ch[i] = seg[7 + 3 * i] >> 4; h->cv[i] = seg[7 + 3 * i] & 15; h->ctq[i] = seg[8 + 3 * i];
        if (!h->ch[i] || !h->cv[i] || h->ctq[i] > 3) return 2; }
      have_sof = 1;
    } else if (m >= 0xC2 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC) return 2;
    else if (m == 0xC4) {
      size_t q = 0;
      while (q < sl) {
        if (q + 17 > sl) return 2;
        int tc = seg[q] >> 4, th = seg[q] & 15; if (tc > 1 || th > 3) return 2;
        Huff *t = &h->dht[tc][th]; memset(t, 0, sizeof *t); int ns = 0;
        for (int i = 0; i < 16; i++) { t->counts[i] = seg[q + 1 + i]; ns += t->counts[i]; }
        if (ns > 256 || q + 17 + ns > sl) return 2;
        memcpy(t->syms, seg + q + 17, ns); t->nsym = ns; t->present = 1; huff_build(t); q += 17 + ns;
      }
    } else if (m == 0xDB) {
      size_t q = 0;
      while (q < sl) {
        int pq = seg[q] >> 4, tq = seg[q] & 15; q++; if (tq > 3) return 2;
        if (pq) { if (q + 128 > sl) return 2; for (int i = 0; i < 64; i++) h->qt[tq][i] = (seg[q + 2 * i] << 8) | seg[q + 2 * i + 1]; q += 128; }
        else { if (q + 64 > sl) return 2; for (int i = 0; i < 64; i++) h->qt[tq][i] = seg[q + i]; q += 64; }
        h->qpresent[tq] = 1;
      }
    } else if (m == 0xDD) { if (sl < 2) return 2; h->dri = (seg[0] << 8) | seg[1]; }
    else if (m == 0xDA) {
      if (!have_sof || sl < 1) return 2; int ns = seg[0];
      if (ns != h->nc || sl < (size_t)(4 + 2 * ns)) return 2;
      for (int i = 0; i < ns; i++) { h->scan_td[i] = seg[2 + 2 * i] >> 4; h->scan_ta[i] = seg[2 + 2 * i] & 15; if (h->scan_td[i] > 3 || h->scan_ta[i] > 3) return 2; }
      if (seg[1 + 2 * ns] != 0 || seg[2 + 2 * ns] != 63 || seg[3 + 2 * ns] != 0) return 2;
      h->end = (int)(p + 2 + L);
      for (int i = 0; i < h->nc; i++) {
        if (!h->qpresent[h->ctq[i]] || !h->dht[0][h->scan_td[i]].present || !h->dht[1][h->scan_ta[i]].present) return 2;
      }
      /* layout */
      if (h->nc == 1) { h->bw[0] = (h->W + 7) / 8; h->bh[0] = (h->H + 7) / 8; h->ph = h->pv = 1; h->mx = h->bw[0]; h->my = h->bh[0]; h->ch[0] = h->cv[0] = 1; }
      else {
        int hm = 0, vm = 0; for (int i = 0; i < 3; i++) { if (h->ch[i] > hm) hm = h->ch[i]; if (h->cv[i] > vm) vm = h->cv[i]; }
        h->mx = (h->W + 8 * hm - 1) / (8 * hm); h->my = (h->H + 8 * vm - 1) / (8 * vm);
        for (int i = 0; i < 3; i++) { h->bw[i] = h->mx * h->ch[i]; h->bh[i] = h->my * h->cv[i]; }
      }
      return 0;
    }
    p += 2 + L;
  }
}

/* ---------------------------------------------------------------- JPEG: Huffman scan decode / encode */
typedef struct { const u8 *d; size_t len, p; u64 acc; int n, over; } BitR;
static int br_get(BitR *r, int k) {
  while (r->n < k) { u8 b; if (r->p < r->len) b = r->d[r->p]; else { b = 0; r->over = 1; } r->p++; r->acc = ((r->acc << 8) | b) & 0xFFFFFFFFFFFFULL; r->n += 8; }
  r->n -= k; return (int)((r->acc >> r->n) & ((1u << k) - 1));
}
static int huff_dec(BitR *r, const Huff *t) {
  int code = 0;
  for (int l = 1; l <= 16; l++) {
    code = (code << 1) | br_get(r, 1);
    if (t->maxcode[l] >= 0 && code >= t->mincode[l] && code <= t->maxcode[l]) return t->syms[t->valptr[l] + code - t->mincode[l]];
  }
  return -1;
}
static inline int extend_(int v, int s) { return v >= (1 << (s - 1)) ? v : v - (1 << s) + 1; }

/* decode scan -> blocks[c][(by*bw+bx)*64 + zigzag].  returns 0 ok, 2 non-canonical/unsupported. split data into tail start */
static int scan_decode(const u8 *d, size_t n, Hdr *h, i16 **blocks, size_t *tail_start) {
  /* split entropy data into restart segments (unstuffed) */
  Buf all = {0}; size_t *segoff = NULL, nseg = 0, segcap = 0; size_t i = (size_t)h->end; int expect = 0, found = 0;
  #define NEWSEG() do { if (nseg == segcap) { segcap = segcap ? segcap * 2 : 16; segoff = (size_t *)realloc(segoff, segcap * sizeof(size_t)); } segoff[nseg++] = all.n; } while (0)
  NEWSEG();
  while (i + 1 < n) {
    u8 b = d[i];
    if (b == 0xFF) {
      u8 nx = d[i + 1];
      if (nx == 0) { bput(&all, 0xFF); i += 2; continue; }
      if (nx >= 0xD0 && nx <= 0xD7) { if (nx != 0xD0 + (expect & 7)) { free(all.p); free(segoff); return 2; } expect++; NEWSEG(); i += 2; continue; }
      if (nx == 0xFF) { free(all.p); free(segoff); return 2; }
      found = 1; break;
    }
    bput(&all, b); i++;
  }
  if (!found) { free(all.p); free(segoff); return 2; }
  *tail_start = i;
  size_t total = (size_t)h->mx * h->my, dri = (size_t)h->dri, want = dri ? (total + dri - 1) / dri : 1;
  if (want != nseg) { free(all.p); free(segoff); return 2; }
  size_t mcu = 0; int rc = 0;
  for (size_t si = 0; si < nseg && !rc; si++) {
    size_t s0 = segoff[si], s1 = (si + 1 < nseg) ? segoff[si + 1] : all.n;
    BitR br = {all.p + s0, s1 - s0, 0, 0, 0, 0}; int pred[3] = {0, 0, 0};
    size_t cnt = dri ? dri : total;
    for (size_t k = 0; k < cnt && mcu < total && !rc; k++, mcu++) {
      size_t my_ = mcu / h->mx, mx_ = mcu % h->mx;
      for (int ci = 0; ci < h->nc && !rc; ci++) {
        const Huff *dct = &h->dht[0][h->scan_td[ci]], *act = &h->dht[1][h->scan_ta[ci]];
        for (int yy = 0; yy < h->cv[ci] && !rc; yy++) for (int xx = 0; xx < h->ch[ci]; xx++) {
          i16 *blk = blocks[ci] + (((my_ * h->cv[ci] + yy) * h->bw[ci]) + mx_ * h->ch[ci] + xx) * 64;
          int sy = huff_dec(&br, dct); if (sy < 0 || sy > 15) { rc = 2; break; }
          int diff = 0; if (sy) diff = extend_(br_get(&br, sy), sy);
          pred[ci] += diff; blk[0] = (i16)pred[ci];
          int kk = 1;
          while (kk < 64) {
            int rs = huff_dec(&br, act); if (rs < 0) { rc = 2; break; }
            int r = rs >> 4, sz = rs & 15;
            if (sz == 0) { if (r == 15) { kk += 16; continue; } break; }
            kk += r; if (kk > 63) { rc = 2; break; }
            blk[kk] = (i16)extend_(br_get(&br, sz), sz); kk++;
          }
          if (rc) break;
          if (kk > 64) { rc = 2; break; }
        }
      }
    }
    if (rc) break;
    if (br.over) { rc = 2; break; }
    size_t used = br.p * 8 - br.n; if ((used + 7) / 8 != br.len) { rc = 2; break; }
    int pad = (int)((8 - used % 8) % 8);
    if (pad && (br.d[br.len - 1] & ((1 << pad) - 1)) != (1 << pad) - 1) { rc = 2; break; }
  }
  if (!rc && mcu != total) rc = 2;
  free(all.p); free(segoff); return rc;
}

typedef struct { Buf out; u64 acc; int n; } BitW;
static void bw_put(BitW *w, u32 code, int ln) {
  w->acc = (w->acc << ln) | code; w->n += ln;
  while (w->n >= 8) { w->n -= 8; u8 b = (u8)((w->acc >> w->n) & 255); bput(&w->out, b); if (b == 255) bput(&w->out, 0); }
  w->acc &= (1ULL << w->n) - 1;
}
static void bw_flush(BitW *w) { if (w->n) bw_put(w, (1u << (8 - w->n)) - 1, 8 - w->n); }
static inline int bl_(int v) { v = v < 0 ? -v : v; int b = 0; while (v) { b++; v >>= 1; } return b; }
static int put_sym(BitW *w, const Huff *t, int s) { if (!t->elen[s] && !(t->nsym && t->syms[0] == s && 0)) { /* verify present */ int ok = 0; for (int i = 0; i < t->nsym; i++) if (t->syms[i] == s) { ok = 1; break; } if (!ok) return 0; } bw_put(w, t->ecode[s], t->elen[s]); return 1; }

static int scan_encode(i16 **blocks, const Hdr *h, Buf *out) {
  size_t total = (size_t)h->mx * h->my, dri = (size_t)h->dri; int rst = 0, pred[3] = {0, 0, 0};
  BitW w; memset(&w, 0, sizeof w);
  for (size_t mcu = 0; mcu < total; mcu++) {
    if (dri && mcu && mcu % dri == 0) {
      bw_flush(&w); bcat(out, w.out.p, w.out.n); bput(out, 0xFF); bput(out, (u8)(0xD0 + (rst & 7))); rst++;
      free(w.out.p); memset(&w, 0, sizeof w); pred[0] = pred[1] = pred[2] = 0;
    }
    size_t my_ = mcu / h->mx, mx_ = mcu % h->mx;
    for (int ci = 0; ci < h->nc; ci++) {
      const Huff *dct = &h->dht[0][h->scan_td[ci]], *act = &h->dht[1][h->scan_ta[ci]];
      for (int yy = 0; yy < h->cv[ci]; yy++) for (int xx = 0; xx < h->ch[ci]; xx++) {
        const i16 *blk = blocks[ci] + (((my_ * h->cv[ci] + yy) * h->bw[ci]) + mx_ * h->ch[ci] + xx) * 64;
        int diff = blk[0] - pred[ci]; pred[ci] = blk[0]; int s_ = bl_(diff);
        if (!put_sym(&w, dct, s_)) return 2;
        if (s_) bw_put(&w, (u32)(diff >= 0 ? diff : diff + (1 << s_) - 1), s_);
        int last = 0; for (int k = 63; k > 0; k--) if (blk[k]) { last = k; break; }
        int run = 0;
        for (int k = 1; k <= last; k++) {
          int v = blk[k]; if (!v) { run++; continue; }
          while (run >= 16) { if (!put_sym(&w, act, 0xF0)) return 2; run -= 16; }
          s_ = bl_(v); if (s_ > 15 || !put_sym(&w, act, (run << 4) | s_)) return 2;
          bw_put(&w, (u32)(v > 0 ? v : v + (1 << s_) - 1), s_); run = 0;
        }
        if (last < 63 && !put_sym(&w, act, 0x00)) return 2;
      }
    }
  }
  bw_flush(&w); bcat(out, w.out.p, w.out.n); free(w.out.p); return 0;
}

/* ---------------------------------------------------------------- JPEG coefficient model */
typedef struct { CM *cm; int nc; int bw[3], bh[3]; int q[3][64]; } JM;
static inline int am_(int v) { v = v < 0 ? -v : v; return v < 2047 ? v : 2047; }
static inline int sg_(int v) { return v == 0 ? 0 : (v > 0 ? 1 : 2); }
static inline i64 fdiv_(i64 a, i64 b) { i64 q = a / b; if ((a % b != 0) && ((a < 0) != (b < 0))) q--; return q; }

static int jm_bit(JM *m, Coder *cd, int b, const u32 *bases, int kind, int c, int aux, int step) {
  u32 hs[6]; for (int j = 0; j < 6; j++) hs[j] = H3u(bases[j], kind, step);
  if (aux > 15) aux = 15;
  return cm_bit(m->cm, cd, b, hs, kind * 2 + (c ? 1 : 0), aux, kind * 16 + aux);
}
static int jm_uint(JM *m, Coder *cd, int enc, int mval, const u32 *bases, int kind, int c, int emax) {
  u32 lo[6] = {bases[0], bases[1], 0, 0, 0, 0};
  int e = 0; if (enc) { int v = mval; while (v) { e++; v >>= 1; } }
  int j = 0;
  while (j < emax) { if (!jm_bit(m, cd, (enc && e > j) ? 1 : 0, bases, kind, c, j, j)) break; j++; }
  e = j; if (e <= 1) return e;
  int val = 1;
  for (int t = e - 2; t >= 0; t--) {
    int idx = e - 2 - t, top = idx < 2;
    int b = jm_bit(m, cd, enc ? ((mval >> t) & 1) : 0, top ? bases : lo, kind, c, top ? 12 + idx : 14, 1000 + e * 100 + t * 4 + (top ? val : 0));
    val = (val << 1) | b;
  }
  return val;
}
/* AC-only edge lines: out[0..3] rows 0,1,6,7 ; out[4..7] cols 0,1,6,7 */
static void lines_(const int *nv, const int *nu, const i64 *nval, int cnt, i64 out[8][8]) {
  if (!cnt) { memset(out, 0, 8 * 8 * sizeof(i64)); return; }
  static const int sel[4] = {0, 1, 6, 7};
  for (int s = 0; s < 4; s++) {
    const i64 *My = DM[sel[s]]; i64 G[8] = {0};
    for (int k = 0; k < cnt; k++) G[nu[k]] += My[nv[k]] * nval[k];
    for (int u = 0; u < 8; u++) G[u] = (G[u] + 64) >> 7;
    for (int x = 0; x < 8; x++) { i64 sm = 0; for (int u = 0; u < 8; u++) sm += DM[x][u] * G[u]; out[s][x] = (sm + 1048576) >> 21; }
  }
  for (int s = 0; s < 4; s++) {
    const i64 *Mx = DM[sel[s]]; i64 G[8] = {0};
    for (int k = 0; k < cnt; k++) G[nv[k]] += Mx[nu[k]] * nval[k];
    for (int v = 0; v < 8; v++) G[v] = (G[v] + 64) >> 7;
    for (int y = 0; y < 8; y++) { i64 sm = 0; for (int v = 0; v < 8; v++) sm += DM[y][v] * G[v]; out[4 + s][y] = (sm + 1048576) >> 21; }
  }
}

static void jm_run(JM *m, Coder *cd, int enc, i16 **blocks) {
  for (int c = 0; c < m->nc; c++) {
    int bw = m->bw[c], bh = m->bh[c]; const int *q = m->q[c]; int q00 = q[0]; size_t n = (size_t)bw * bh;
    int *nzl = (int *)xcalloc(n, 4), *resid = (int *)xcalloc(n, 4); i64 *edges = (i64 *)xcalloc(n * 32, 8);
    for (int by = 0; by < bh; by++) for (int bx = 0; bx < bw; bx++) {
      size_t idx = (size_t)by * bw + bx; i16 *blk = blocks[c] + idx * 64; size_t A = idx - bw, Lf = idx - 1;
      int nA, nL;
      if (by && bx) { nA = nzl[A]; nL = nzl[Lf]; } else if (by) nA = nL = nzl[A]; else if (bx) nA = nL = nzl[Lf]; else nA = nL = 0;
      int avg = (nA + nL + 1) >> 1;
      u32 nb[6] = {H3(c, QN[nA], QN[nL]), H3(c, QN[avg], (by == 0) * 2 + (bx == 0)), H2(c, avg), H2(c, 0), H2(c, nA), H2(c, nL)};
      int nz = 0; if (enc) for (int i = 1; i < 64; i++) if (blk[i]) nz++;
      nz = jm_uint(m, cd, enc, nz, nb, 0, c, 6); nzl[idx] = nz;
      const i16 *Aa = by ? blocks[c] + A * 64 : NULL, *La = bx ? blocks[c] + Lf * 64 : NULL;
      int rem = nz, i = 1;
      while (rem > 0 && i < 64) {
        int a = Aa ? Aa[i] : 0, l = La ? La[i] : 0, nn = ZZ[i], j;
        j = nn >= 8 ? ZZINV[nn - 8] : 0; int Uv = j ? blk[j] : 0;
        j = (nn & 7) ? ZZINV[nn - 1] : 0; int Lu = j ? blk[j] : 0;
        int pb = i >= 2 ? blk[i - 1] : 0, pb2 = i >= 3 ? blk[i - 2] : 0;
        int aa = abs(a), al = abs(l), au = abs(Uv), alu = abs(Lu);
        int qa = QM[am_(a)], ql = QM[am_(l)], qu = QM[am_(Uv)], qlu = QM[am_(Lu)], qp = QM[am_(pb)];
        int t = (aa + al + au + alu + 2) >> 2; int qsum = QM[t < 2047 ? t : 2047];
        int rb = QR[rem], nzf;
        if (64 - i == rem) nzf = 1;
        else {
          u32 fb[6] = {H3(c, i, rb), H4(c, i, qa, ql), H4(c, i, qu, qlu), H4(c, i, rb, qp), H4(c, qsum, rb, i >> 3), H5(c, i, qp, QM[am_(pb2)], qu)};
          nzf = jm_bit(m, cd, (enc && blk[i]) ? 1 : 0, fb, 1, c, i >> 2, 0);
        }
        if (nzf) {
          int v = enc ? blk[i] : 0; int t2 = (aa + al + 1) >> 1;
          u32 mb[6] = {H4(c, i, qa, ql), H3(c, i, QM[t2 < 2047 ? t2 : 2047]), H4(c, i, qu, qlu), H3(c, qsum, rb), H3(c, i, qp), H2(c, i)};
          int mag = jm_uint(m, cd, enc, enc ? abs(v) - 1 : 0, mb, 2, c, 11) + 1;
          int sa = sg_(a), sl = sg_(l), su = sg_(Uv), slu = sg_(Lu);
          u32 sb[6] = {H4(c, i, sa, sl), H4(c, i, su, slu), H3(c, i, sa), H3(c, i, sl), H6(c, i, sa, sl, su, slu), H2(c, i)};
          int neg = jm_bit(m, cd, (enc && v < 0) ? 1 : 0, sb, 3, c, 0, 0);
          blk[i] = (i16)(neg ? -mag : mag); rem--;
        }
        i++;
      }
      /* DC from pixel-domain edge continuity */
      int nv[63], nu[63]; i64 nval[63]; int cnt = 0;
      for (int k = 1; k < 64; k++) if (blk[k]) { nv[cnt] = ZZ[k] >> 3; nu[cnt] = ZZ[k] & 7; nval[cnt] = (i64)blk[k] * q[k]; cnt++; }
      i64 ln[8][8]; lines_(nv, nu, nval, cnt, ln);
      int havea = 0, havel = 0; i64 pa = 0, pl = 0;
      if (by) { const i64 *b6 = edges + A * 32, *b7 = b6 + 8; i64 N = 0; for (int x = 0; x < 8; x++) N += 3 * b7[x] - b6[x] + ln[1][x] - 3 * ln[0][x]; pa = fdiv_(N + q00, 2 * q00); havea = 1; }
      if (bx) { const i64 *r6 = edges + Lf * 32 + 16, *r7 = r6 + 8; i64 N = 0; for (int y = 0; y < 8; y++) N += 3 * r7[y] - r6[y] + ln[5][y] - 3 * ln[4][y]; pl = fdiv_(N + q00, 2 * q00); havel = 1; }
      i64 p; int qd, sd;
      if (havea && havel) { p = (pa + pl + 1) >> 1; i64 d = pa - pl; if (d < 0) d = -d; int di = d < 1023 ? (int)d : 1023; qd = QE[di] < 12 ? QE[di] : 12; sd = pa == pl ? 0 : (pa > pl ? 1 : 2); }
      else if (havea) { p = pa; qd = 14; sd = 3; } else if (havel) { p = pl; qd = 15; sd = 3; } else { p = 0; qd = 13; sd = 3; }
      int ra = by ? resid[A] : 0, rl = bx ? resid[Lf] : 0; int qra = QM[am_(ra)], qrl = QM[am_(rl)];
      int t3 = (abs(ra) + abs(rl) + 1) >> 1;
      u32 db[6] = {H1(c) * 0 + H2(c, qd), H3(c, qd, QN[nz]), H2(c, qra), H2(c, qrl), H3(c, qd, QM[t3 < 2047 ? t3 : 2047]), H2(c, 0)};
      int r = enc ? (int)(blk[0] - p) : 0;
      int mag = jm_uint(m, cd, enc, enc ? abs(r) : 0, db, 4, c, 13);
      if (mag) {
        u32 sdb[6] = {H3(c, sd, qd), H2(c, sd), H3(c, sg_(ra), sg_(rl)), H2(c, sg_(ra)), H2(c, sg_(rl)), H2(c, 0)};
        int neg = jm_bit(m, cd, (enc && r < 0) ? 1 : 0, sdb, 5, c, 0, 0); r = neg ? -mag : mag;
      } else r = 0;
      i64 dc = p + r; blk[0] = (i16)dc; resid[idx] = r;
      i64 dco = (dc * q00 + 4) >> 3, *e = edges + idx * 32;
      for (int x = 0; x < 8; x++) { e[x] = ln[2][x] + dco; e[8 + x] = ln[3][x] + dco; e[16 + x] = ln[6][x] + dco; e[24 + x] = ln[7][x] + dco; }
    }
    free(nzl); free(resid); free(edges);
  }
}
static JM *jm_new(const Hdr *h) {
  JM *m = (JM *)xcalloc(1, sizeof *m); size_t nb = 0; m->nc = h->nc;
  for (int c = 0; c < h->nc; c++) {
    m->bw[c] = h->bw[c]; m->bh[c] = h->bh[c]; nb += (size_t)h->bw[c] * h->bh[c];
    for (int i = 0; i < 64; i++) { int v = h->qt[h->ctq[c]][i]; m->q[c][i] = v < 1 ? 1 : v; }
  }
  int bl = 0; while (nb >> bl) bl++; bl += 8; bl = bl < 16 ? 16 : (bl > 22 ? 22 : bl);
  m->cm = cm_new(6, 12, 16, bl); return m;
}
static i16 **alloc_blocks(const Hdr *h) { i16 **b = (i16 **)xcalloc(3, sizeof(i16 *)); for (int c = 0; c < h->nc; c++) b[c] = (i16 *)xcalloc((size_t)h->bw[c] * h->bh[c] * 64, 2); return b; }
static void free_blocks(i16 **b) { for (int c = 0; c < 3; c++) free(b[c]); free(b); }

/* ---------------------------------------------------------------- container */
static void wrap_blob(Buf *out, int modebyte, const u8 *orig, size_t n, const u8 *payload, size_t pn) {
  u8 c4[4]; sha4(orig, n, c4); bput(out, (u8)modebyte); bcat(out, c4, 4); vput(out, n); bcat(out, payload, pn);
}
/* mode-3 payload decode -> original bytes */
static Buf jpeg_payload_decode(const u8 *pl, size_t pn) {
  size_t p = 0; size_t hl = (size_t)vget(pl, pn, &p), hcl = (size_t)vget(pl, pn, &p);
  if (p + hcl > pn) die("corrupt jpeg payload");
  u8 *hdr = (u8 *)xcalloc(hl + 1, 1); cm_dec_bytes(pl + p, hcl, hl, hdr); p += hcl;
  size_t tl = (size_t)vget(pl, pn, &p); if (p + tl > pn) die("corrupt jpeg payload");
  const u8 *tail = pl + p; p += tl; const u8 *stream = pl + p; size_t sn = pn - p;
  Hdr h; if (parse_hdr(hdr, hl, &h) != 0 || (size_t)h.end != hl) die("corrupt jpeg header");
  i16 **blocks = alloc_blocks(&h); JM *m = jm_new(&h); Coder cd; dec_init(&cd, stream, sn);
  jm_run(m, &cd, 0, blocks);
  Buf out = {0}; bcat(&out, hdr, hl);
  if (scan_encode(blocks, &h, &out)) die("corrupt jpeg coefficients");
  bcat(&out, tail, tl);
  cm_free(m->cm); free(m); free_blocks(blocks); free(hdr); return out;
}
static Buf decode_blob(const u8 *b, size_t n);
static Buf decode_blob(const u8 *b, size_t n) {
  if (n < 6) die("truncated"); int mode = b[0] & 15, profile = b[0] >> 4; u8 chk[4]; memcpy(chk, b + 1, 4);
  size_t p = 5; size_t len = (size_t)vget(b, n, &p); const u8 *pl = b + p; size_t pn = n - p; Buf out = {0};
  if (mode == 0) { bcat(&out, pl, pn); }
  else if (mode == 1 && profile == 1) { out.p = (u8 *)xcalloc(len + 1, 1); out.n = out.cap = len; cm_dec_bytes(pl, pn, len, out.p); }
  else if (mode == 3) out = jpeg_payload_decode(pl, pn);
  else if (mode == 4) {                                   /* lossy tier: kind | w | h | bytes | fidelity | codec | body */
    size_t q = 0; if (pn < 1) die("corrupt lossy payload"); int kind = pl[q++];
    vget(pl, pn, &q); vget(pl, pn, &q); vget(pl, pn, &q); q += 2; if (q > pn) die("corrupt lossy payload");
    if (kind == 0) bcat(&out, pl + q, pn - q); else if (kind == 1) out = decode_blob(pl + q, pn - q); else unsup("lossy kind");
  }
  else unsup("mode/profile");
  u8 c2[4]; sha4(out.p, out.n, c2);
  if (out.n != len || memcmp(c2, chk, 4)) die("integrity check failed (corrupt or truncated file)");
  return out;
}
static int encode_jpeg(const u8 *orig, size_t n, Buf *blob) {
  Hdr h; if (parse_hdr(orig, n, &h)) return 2;
  i16 **blocks = alloc_blocks(&h); size_t tail_start = 0;
  if (scan_decode(orig, n, &h, blocks, &tail_start)) { free_blocks(blocks); return 2; }
  Buf re = {0}; int rc = scan_encode(blocks, &h, &re);
  if (rc || re.n != tail_start - (size_t)h.end || memcmp(re.p, orig + h.end, re.n)) { free(re.p); free_blocks(blocks); return 2; }
  free(re.p);
  JM *m = jm_new(&h); Coder cd; enc_init(&cd); jm_run(m, &cd, 1, blocks); enc_finish(&cd);
  Buf hc = cm_enc_bytes(orig, (size_t)h.end); Buf pl = {0};
  vput(&pl, (u64)h.end); vput(&pl, hc.n); bcat(&pl, hc.p, hc.n); vput(&pl, n - tail_start); bcat(&pl, orig + tail_start, n - tail_start); bcat(&pl, cd.out.p, cd.out.n);
  wrap_blob(blob, 3 | (1 << 4), orig, n, pl.p, pl.n);
  free(pl.p); free(hc.p); free(cd.out.p); cm_free(m->cm); free(m); free_blocks(blocks); return 0;
}
static int encode_best(const u8 *orig, size_t n, Buf *best) {
  Buf stored = {0}; wrap_blob(&stored, 0, orig, n, orig, n);
  Buf jb = {0}; int rc = (n > 2 && orig[0] == 0xFF && orig[1] == 0xD8) ? encode_jpeg(orig, n, &jb) : 2;
  if (rc == 0 && jb.n < stored.n) {
    Buf chk = decode_blob(jb.p, jb.n);                         /* verify-after-encode */
    if (chk.n == n && !memcmp(chk.p, orig, n)) { free(chk.p); free(stored.p); *best = jb; return 0; }
    free(chk.p); fprintf(stderr, "cmxc: verification failed, falling back\n"); free(jb.p); free(stored.p); return 2;
  }
  free(jb.p);
  if (rc == 2 && !(n > 2 && orig[0] == 0xFF && orig[1] == 0xD8) ) { free(stored.p); return 2; }  /* PNG/other: Python handles */
  if (rc == 2) { free(stored.p); return 2; }                                                      /* unsupported JPEG variant */
  *best = stored; return 0;
}

static u8 *readfile(const char *path, size_t *n) {
  FILE *f = fopen(path, "rb"); if (!f) die("cannot open input"); fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
  u8 *d = (u8 *)xcalloc((size_t)sz + 1, 1); if (fread(d, 1, (size_t)sz, f) != (size_t)sz) die("read failed"); fclose(f); *n = (size_t)sz; return d;
}
static void writefile(const char *path, const u8 *a, size_t an, const u8 *b, size_t bn) {
  FILE *f = fopen(path, "wb"); if (!f) die("cannot write output"); if (an) fwrite(a, 1, an, f); if (bn) fwrite(b, 1, bn, f); fclose(f);
}
int main(int argc, char **argv) {
  if (argc != 4) { fprintf(stderr, "usage: cmxc pack <in> <out.cmx> | cmxc unpack <in.cmx> <out>\n"); return 1; }
  init_tables(); size_t n; u8 *in = readfile(argv[2], &n); clock_t t0 = clock();
  if (!strcmp(argv[1], "pack")) {
    Buf blob = {0}; int rc = encode_best(in, n, &blob); if (rc) return rc;
    writefile(argv[3], (const u8 *)"CMX\x01", 4, blob.p, blob.n);
    fprintf(stderr, "cmxc: %zu -> %zu bytes (%.1f%%) in %.2fs\n", n, blob.n + 4, 100.0 * (1.0 - (double)(blob.n + 4) / (double)n), (double)(clock() - t0) / CLOCKS_PER_SEC);
  } else if (!strcmp(argv[1], "unpack")) {
    if (n < 5 || memcmp(in, "CMX", 3)) die("not a .cmx file"); if (in[3] != 1) die("unsupported .cmx version");
    Buf out = decode_blob(in + 4, n - 4); writefile(argv[3], out.p, out.n, NULL, 0);
    fprintf(stderr, "cmxc: %zu -> %zu bytes in %.2fs\n", n, out.n, (double)(clock() - t0) / CLOCKS_PER_SEC);
  } else die("unknown command");
  return 0;
}
