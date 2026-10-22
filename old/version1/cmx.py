"""
CMX - byte-exact, integer-only context-mixing compressor with a JSON-safe string form.

Modes
  0 STORED  : original bytes (never expands more than the header)
  1 GENERIC : context-mixing byte coder (any file)
  2 PNG     : PNG is re-deflated bit-exactly from pixels (params found by search),
              pixels are coded with a 2D image model (MED residual + mixed contexts)

Every encode is verified by running the decoder; on any mismatch it falls back.
All model arithmetic is integer-only (32-bit hashes, 12-bit probabilities) so a JS /
Rust / C port reproduces identical predictions.
"""
import zlib, hashlib, struct, json
from array import array

M32 = 0xFFFFFFFF

# ---------------------------------------------------------------- tables (integer only)
_T = [1, 2, 3, 6, 10, 16, 27, 45, 73, 120, 194, 310, 488, 747, 1101, 1546, 2047, 2549,
      2994, 3348, 3607, 3785, 3901, 3975, 4022, 4050, 4068, 4079, 4085, 4089, 4092, 4093, 4094]


def _squash(d):
    if d > 2047: return 4095
    if d < -2047: return 0
    w = d & 127
    d = (d >> 7) + 16
    return (_T[d] * (128 - w) + _T[d + 1] * w + 64) >> 7


STRETCH = [0] * 4096
_pi = 0
for _x in range(-2047, 2048):
    _v = _squash(_x)
    for _i in range(_pi, _v + 1):
        STRETCH[_i] = _x
    _pi = _v + 1
for _i in range(_pi, 4096):
    STRETCH[_i] = 2047
SQ = [_squash(d) for d in range(-2047, 2048)]       # index d + 2047
RT = [(4096 * 2) // (2 * n + 3) for n in range(256)]  # adaptive counter rates (12-bit)


def H(*v):
    h = 0x811C9DC5
    for a in v:
        h = ((h ^ (a & M32)) * 0x01000193) & M32
        h ^= h >> 15
    return h


# ---------------------------------------------------------------- arithmetic coder
class Enc:
    def __init__(s):
        s.x1 = 0; s.x2 = M32; s.out = bytearray()

    def code(s, bit, p):
        xmid = s.x1 + ((s.x2 - s.x1) >> 12) * p
        if bit: s.x2 = xmid
        else: s.x1 = xmid + 1
        while ((s.x1 ^ s.x2) & 0xFF000000) == 0:
            s.out.append(s.x2 >> 24)
            s.x1 = (s.x1 << 8) & M32
            s.x2 = ((s.x2 << 8) & M32) | 255
        return bit

    def finish(s):
        for nb in (1, 2, 3, 4):           # shortest tail; decoder pads zeros
            sh = 32 - 8 * nb
            v = ((s.x1 + (1 << sh) - 1) >> sh) << sh
            if v <= s.x2 and v <= M32:
                s.out += v.to_bytes(4, 'big')[:nb]
                break
        return bytes(s.out).rstrip(b'\0')


class Dec:
    def __init__(s, data):
        s.d = data; s.pos = 0; s.x1 = 0; s.x2 = M32; s.x = 0
        for _ in range(4): s.x = (s.x << 8) | s._nb()

    def _nb(s):
        b = s.d[s.pos] if s.pos < len(s.d) else 0
        s.pos += 1
        return b

    def code(s, _bit, p):
        xmid = s.x1 + ((s.x2 - s.x1) >> 12) * p
        bit = 1 if s.x <= xmid else 0
        if bit: s.x2 = xmid
        else: s.x1 = xmid + 1
        while ((s.x1 ^ s.x2) & 0xFF000000) == 0:
            s.x1 = (s.x1 << 8) & M32
            s.x2 = ((s.x2 << 8) & M32) | 255
            s.x = ((s.x << 8) & M32) | s._nb()
        return bit


# ---------------------------------------------------------------- context-mixing engine
class CM:
    LR = 2        # mixer learning rate
    SH = 10       # mixer shift
    LIMIT = 250   # counter adaptation limit
    WI = 65536 * 12 // 100   # initial mixer weight

    def __init__(s, nctx, nsel, nsel2, bits):
        s.n = nctx; s.nin = nctx + 1; s.shift = 32 - bits
        size = 1 << bits
        s.pt = [array('H', [32768]) * size for _ in range(nctx)]
        s.ct = [array('B', bytes(size)) for _ in range(nctx)]
        s.w1 = [[s.WI] * s.nin for _ in range(nsel * 8)]
        s.w2 = [[s.WI] * s.nin for _ in range(nsel2 * 8)]
        # APM / SSE: 33 interpolation bins per context (c0 x 256)
        s.apm = [[(_squash((i - 16) * 128) * 16) for i in range(33)] for _ in range(256)]

    def code_byte(s, coder, sym, ctxs, msel, msel2):
        n = s.n; nin = s.nin; shift = s.shift; pt = s.pt; ct = s.ct
        LR = s.LR; SH = s.SH; LIM = s.LIMIT
        c0 = 1
        idx = [0] * n
        x = [0] * nin
        x[n] = 256
        rn = range(n); rnin = range(nin)
        for bi in range(7, -1, -1):
            cm = (c0 * 0x9E3779B1) & M32
            for j in rn:
                ix = (((ctxs[j] ^ cm) * 0x85EBCA6B) & M32) >> shift
                idx[j] = ix
                x[j] = STRETCH[pt[j][ix] >> 4]
            w1 = s.w1[msel * 8 + bi]; w2 = s.w2[msel2 * 8 + bi]
            dot1 = 0; dot2 = 0
            for j in rnin:
                xj = x[j]
                dot1 += xj * w1[j]; dot2 += xj * w2[j]
            d1 = dot1 >> 16; d2 = dot2 >> 16
            if d1 > 2047: d1 = 2047
            elif d1 < -2047: d1 = -2047
            if d2 > 2047: d2 = 2047
            elif d2 < -2047: d2 = -2047
            p1 = SQ[d1 + 2047]; p2 = SQ[d2 + 2047]
            dm = (d1 + d2) >> 1
            pm = SQ[dm + 2047]
            # APM refine, selected by c0 (partial byte) and bit position
            a = s.apm[c0]
            pos = (dm + 2048) * 32
            lo = pos >> 12; wt = pos & 4095
            pa = (a[lo] * (4096 - wt) + a[lo + 1] * wt) >> 16
            p = (pm + 3 * pa + 2) >> 2
            if p < 1: p = 1
            elif p > 4095: p = 4095
            bit = coder.code(((sym >> bi) & 1) if sym is not None else 0, p)
            # update APM (nearest bin pair)
            tg = bit << 16
            a[lo] += (tg - a[lo]) >> 6
            a[lo + 1] += (tg - a[lo + 1]) >> 6
            e1 = ((bit << 12) - p1) * LR; e2 = ((bit << 12) - p2) * LR
            for j in rnin:
                xj = x[j]
                w1[j] += (xj * e1) >> SH; w2[j] += (xj * e2) >> SH
            for j in rn:
                t = pt[j]; ix = idx[j]; c = ct[j]; k = c[ix]
                t[ix] += ((tg - t[ix]) * RT[k]) >> 12
                if k < LIM: c[ix] = k + 1
            c0 = (c0 << 1) | bit
        return c0 & 255


BITS_ADD = 5


def _bits_for(n):
    return max(16, min(22, n.bit_length() + BITS_ADD))


# ---------------------------------------------------------------- model states
class GenState:
    NCTX = 8
    NSEL = 1
    NSEL2 = 8

    def __init__(s):
        s.buf = bytearray(); s.v = 0

    def ctx(s):
        v = s.v
        return [H(0), H(1, v & 0xFF), H(2, v & 0xFFFF), H(3, v & 0xFFFFFF), H(4, v & M32),
                H(5, v & M32, (v >> 32) & 0xFFFF), H(6, (v >> 8) & 0xFF),
                H(7, (v >> 16) & 0xFFFF)], 0, (v & 0xFF) >> 5

    def to_sym(s, a): return a

    def push(s, sym):
        s.buf.append(sym); s.v = ((s.v << 8) | sym) & 0xFFFFFFFFFFFFFFFF
        return sym


_QT = (0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128)
QE = []
for _e in range(1024):
    _k = 0
    for _t in _QT:
        if _e >= _t: _k += 1
    QE.append(_k - 1)


def _cl(v, m):
    return m if v > m else (-m if v < -m else v)


def _q(v):                      # v is a zigzag residual
    if v < 3: return v
    if v < 5: return 3
    if v < 9: return 4
    if v < 17: return 5
    if v < 33: return 6
    return 7


class ImgState:
    NCTX = 14
    NSEL2 = 8

    def __init__(s, rb, bpp):
        s.rb = rb; s.bpp = bpp; s.NSEL = bpp
        s.buf = bytearray(); s.res = bytearray(); s.i = 0; s.pred = 0

    def ctx(s):
        i = s.i; rb = s.rb; bpp = s.bpp; buf = s.buf; res = s.res
        r, cb = divmod(i, rb)
        k = cb % bpp
        hasW = cb >= bpp
        if r:
            N = buf[i - rb]; rN = res[i - rb]
            W = buf[i - bpp] if hasW else N
            rW = res[i - bpp] if hasW else 0
            NW = buf[i - rb - bpp] if hasW else N
            rNW = res[i - rb - bpp] if hasW else 0
            if cb + bpp < rb:
                NE = buf[i - rb + bpp]; rNE = res[i - rb + bpp]
            else:
                NE = N; rNE = rN
        else:
            W = buf[i - bpp] if hasW else 0
            rW = res[i - bpp] if hasW else 0
            N = NW = NE = W; rN = rNW = rNE = 0
        if k > 0:
            P1 = buf[i - 1]; R1 = res[i - 1]
            P2 = buf[i - 2] if k > 1 else 0
        else:
            P1 = R1 = P2 = 0
        # MED predictor
        if NW >= (W if W > N else N): pred = W if W < N else N
        elif NW <= (W if W < N else N): pred = W if W > N else N
        else: pred = W + N - NW
        s.pred = pred
        g = abs(W - NW) + abs(N - NW) + abs(N - NE)
        e = ((rW + 1) >> 1) + ((rN + 1) >> 1) + ((((rNW + 1) >> 1) + ((rNE + 1) >> 1)) >> 1)
        e2 = e + ((R1 + 1) >> 1)
        qe = QE[e if e < 1023 else 1023]; qe2 = QE[e2 if e2 < 1023 else 1023]
        # whole-pixel neighbourhood (palette / graphics): all channels of W and N pixels + current prefix
        bs = i - k
        if hasW: Wp = int.from_bytes(buf[bs - bpp:bs], 'little')
        else: Wp = 0
        Np = int.from_bytes(buf[bs - rb:bs - rb + bpp], 'little') if r else Wp
        Cp = int.from_bytes(buf[bs:i], 'little')
        Wp = (Wp ^ (Wp >> 32)) & M32; Np = (Np ^ (Np >> 32)) & M32
        return [H(0, k), H(1, k, rW, rN), H(2, k, R1, rW), H(3, k, W, N, NW),
                H(4, k, pred), H(5, k, min(g, 255) >> 2, _q(rW), _q(rN)),
                H(6, k, N, NE), H(7, k, P1, P2, W), H(8, k, rW, rN, rNW, rNE),
                H(9, k, qe, _q(R1)), H(10, k, _cl(W - pred, 12), _cl(N - pred, 12)),
                H(11, k, Wp, Cp), H(12, k, Wp, Np, Cp), H(13, k, qe2, pred >> 4)], k, qe2 >> 1

    def push(s, sym):            # sym is the zigzag residual
        v = (s.pred + ((sym >> 1) if not sym & 1 else -((sym + 1) >> 1))) & 255
        s.buf.append(v); s.res.append(sym); s.i += 1
        return v

    def to_sym(s, a):
        r = (a - s.pred) & 255
        if r >= 128: r -= 256
        return 2 * r if r >= 0 else -2 * r - 1


def _run_enc(state, data, image):
    coder = Enc(); cm = CM(state.NCTX, state.NSEL, state.NSEL2, _bits_for(len(data)))
    for a in data:
        ctxs, ms, ms2 = state.ctx()
        sym = state.to_sym(a) if image else a
        cm.code_byte(coder, sym, ctxs, ms, ms2)
        state.push(sym)
    return coder.finish()


def _run_dec(state, blob, n, image):
    coder = Dec(blob); cm = CM(state.NCTX, state.NSEL, state.NSEL2, _bits_for(n))
    out = bytearray()
    for _ in range(n):
        ctxs, ms, ms2 = state.ctx()
        out.append(state.push(cm.code_byte(coder, None, ctxs, ms, ms2)))
    return bytes(out)


def cm_enc(data): return _run_enc(GenState(), data, False)
def cm_dec(blob, n): return _run_dec(GenState(), blob, n, False)
def img_enc(pix, rb, bpp): return _run_enc(ImgState(rb, bpp), pix, True)
def img_dec(blob, n, rb, bpp): return _run_dec(ImgState(rb, bpp), blob, n, True)


# ---------------------------------------------------------------- varints
def vput(n):
    o = bytearray()
    while True:
        b = n & 127; n >>= 7
        if n: o.append(b | 128)
        else:
            o.append(b); return bytes(o)


def vget(d, p):
    n = 0; sh = 0
    while True:
        b = d[p]; p += 1
        n |= (b & 127) << sh; sh += 7
        if not b & 128: return n, p


# ---------------------------------------------------------------- PNG transcoder
PNG_SIG = b'\x89PNG\r\n\x1a\n'
CH = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def _paeth(a, b, c):
    p = a + b - c; pa = abs(p - a); pb = abs(p - b); pc = abs(p - c)
    return a if pa <= pb and pa <= pc else (b if pb <= pc else c)


def _unfilter(raw, h, rb, bpp):
    out = bytearray(); ft = bytearray(); prev = bytes(rb)
    for r in range(h):
        o = r * (rb + 1); t = raw[o]; cur = bytearray(raw[o + 1:o + 1 + rb])
        if t == 0: pass
        elif t == 1:
            for i in range(bpp, rb): cur[i] = (cur[i] + cur[i - bpp]) & 255
        elif t == 2:
            for i in range(rb): cur[i] = (cur[i] + prev[i]) & 255
        elif t == 3:
            for i in range(rb):
                a = cur[i - bpp] if i >= bpp else 0
                cur[i] = (cur[i] + ((a + prev[i]) >> 1)) & 255
        elif t == 4:
            for i in range(rb):
                a = cur[i - bpp] if i >= bpp else 0
                c = prev[i - bpp] if i >= bpp else 0
                cur[i] = (cur[i] + _paeth(a, prev[i], c)) & 255
        else:
            raise ValueError('bad filter')
        ft.append(t); out += cur; prev = cur
    return bytes(out), bytes(ft)


def _refilter(pix, ft, h, rb, bpp):
    out = bytearray(); prev = bytes(rb)
    for r in range(h):
        cur = pix[r * rb:(r + 1) * rb]; t = ft[r]
        out.append(t)
        if t == 0: out += cur
        elif t == 1:
            out += bytes((cur[i] - (cur[i - bpp] if i >= bpp else 0)) & 255 for i in range(rb))
        elif t == 2:
            out += bytes((cur[i] - prev[i]) & 255 for i in range(rb))
        elif t == 3:
            out += bytes((cur[i] - (((cur[i - bpp] if i >= bpp else 0) + prev[i]) >> 1)) & 255
                         for i in range(rb))
        else:
            out += bytes((cur[i] - _paeth(cur[i - bpp] if i >= bpp else 0, prev[i],
                                          prev[i - bpp] if i >= bpp else 0)) & 255
                         for i in range(rb))
        prev = cur
    return bytes(out)


def _deflate(raw, p):
    level, mem, strat, wb = p
    co = zlib.compressobj(level, zlib.DEFLATED, wb, mem, strat)
    return co.compress(raw) + co.flush()


def _find_deflate(raw, target):
    wb = (target[0] >> 4) + 8
    cls = target[1] >> 6
    levels = {0: [0, 1], 1: [2, 3, 4, 5], 2: [6], 3: [7, 8, 9]}[cls]
    for strat in (0, 1, 2, 3, 4):
        for mem in (8, 9, 7, 6, 5, 4, 3, 2, 1):
            for level in levels:
                p = (level, mem, strat, wb)
                if _deflate(raw, p) == target:
                    return p
    return None


def _png_parse(d):
    if d[:8] != PNG_SIG: raise ValueError
    p = 8; chunks = []
    while True:
        ln = struct.unpack('>I', d[p:p + 4])[0]; typ = d[p + 4:p + 8]
        data = d[p + 8:p + 8 + ln]
        crc = struct.unpack('>I', d[p + 8 + ln:p + 12 + ln])[0]
        if zlib.crc32(typ + data) & M32 != crc: raise ValueError('crc')
        chunks.append((typ, data)); p += 12 + ln
        if typ == b'IEND': break
    return chunks, d[p:]


def _png_encode(orig):
    chunks, tail = _png_parse(orig)
    if chunks[0][0] != b'IHDR': raise ValueError
    w, h, depth, ct, comp, flt, il = struct.unpack('>IIBBBBB', chunks[0][1])
    if il or comp or flt or depth not in (8, 16) or ct not in CH: raise ValueError
    bpp = CH[ct] * depth // 8; rb = w * bpp
    idat = b''.join(c[1] for c in chunks if c[0] == b'IDAT')
    raw = zlib.decompress(idat)
    if len(raw) != h * (rb + 1): raise ValueError
    params = _find_deflate(raw, idat)
    if params is None: raise ValueError('deflate stream not reproducible')
    pix, ft = _unfilter(raw, h, rb, bpp)
    meta = bytearray()
    for typ, data in chunks:
        meta += typ
        if typ == b'IDAT': meta += vput(len(data))
        else: meta += vput(len(data)) + data
    meta += vput(len(tail)) + tail
    meta = bytes(meta)
    mc = cm_enc(meta); fc = cm_enc(ft); pc = img_enc(pix, rb, bpp)
    out = bytes([params[0] | (params[1] << 4), params[2], params[3]])
    out += vput(len(meta)) + vput(len(mc)) + mc + vput(len(fc)) + fc + pc
    return out


def _png_decode(pl):
    level = pl[0] & 15; mem = pl[0] >> 4; strat = pl[1]; wb = pl[2]
    p = 3
    ml, p = vget(pl, p); mcl, p = vget(pl, p); meta = cm_dec(pl[p:p + mcl], ml); p += mcl
    fcl, p = vget(pl, p); fc = pl[p:p + fcl]; p += fcl; pc = pl[p:]
    # parse meta
    q = 0; ents = []
    while True:
        typ = meta[q:q + 4]; ln, q = vget(meta, q + 4)
        if typ == b'IDAT': ents.append((typ, ln, None))
        else: ents.append((typ, ln, meta[q:q + ln])); q += ln
        if typ == b'IEND': break
    tl, q = vget(meta, q); tail = meta[q:q + tl]
    w, h, depth, ct = struct.unpack('>IIBB', ents[0][2][:10])
    bpp = CH[ct] * depth // 8; rb = w * bpp
    ft = cm_dec(fc, h); pix = img_dec(pc, h * rb, rb, bpp)
    stream = _deflate(_refilter(pix, ft, h, rb, bpp), (level, mem, strat, wb))
    out = bytearray(PNG_SIG); sp = 0
    for typ, ln, data in ents:
        if typ == b'IDAT': data = stream[sp:sp + ln]; sp += ln
        out += struct.pack('>I', len(data)) + typ + data
        out += struct.pack('>I', zlib.crc32(typ + data) & M32)
    return bytes(out) + tail


# ---------------------------------------------------------------- container
def _wrap(mode, orig, payload):
    return bytes([mode]) + hashlib.sha256(orig).digest()[:4] + vput(len(orig)) + payload


def decode(blob):
    mode = blob[0]; chk = blob[1:5]; n, p = vget(blob, 5); pl = blob[p:]
    if mode == 0: out = pl
    elif mode == 1: out = cm_dec(pl, n)
    elif mode == 2: out = _png_decode(pl)
    else: raise ValueError('unknown mode')
    if len(out) != n or hashlib.sha256(out).digest()[:4] != chk:
        raise ValueError('integrity check failed')
    return out


def encode(orig, verbose=False):
    best = _wrap(0, orig, orig)
    cands = []
    if orig[:8] == PNG_SIG:
        try: cands.append(_wrap(2, orig, _png_encode(orig)))
        except Exception as e:
            if verbose: print('  png path unavailable:', e)
    if not cands:
        cands.append(_wrap(1, orig, cm_enc(orig)))
    for c in cands:
        try:
            if len(c) < len(best) and decode(c) == orig:     # verify-after-encode
                best = c
        except Exception as e:
            if verbose: print('  candidate failed verification:', e)
    return best


# ---------------------------------------------------------------- JSON-safe text form
_A = ('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
      '!#$%()*+,-./:;=?@[]^_{|')
assert len(_A) == 85 and '"' not in _A and '\\' not in _A
_R = {c: i for i, c in enumerate(_A)}


def to_text(b):
    out = []
    for i in range(0, len(b), 4):
        g = b[i:i + 4]; m = len(g)
        v = int.from_bytes(g + bytes(4 - m), 'big'); d = []
        for _ in range(5): d.append(_A[v % 85]); v //= 85
        d.reverse(); out.append(''.join(d)[:m + 1] if m < 4 else ''.join(d))
    return ''.join(out)


def from_text(s):
    out = bytearray()
    for i in range(0, len(s), 5):
        g = s[i:i + 5]; m = len(g)
        v = 0
        for ch in g + _A[84] * (5 - m): v = v * 85 + _R[ch]
        out += v.to_bytes(4, 'big')[:m - 1] if m < 5 else v.to_bytes(4, 'big')
    return bytes(out)


def compress_to_json(data): return json.dumps({'cmx': 1, 'd': to_text(encode(data))})
def decompress_from_json(s): return decode(from_text(json.loads(s)['d']))
