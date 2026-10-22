"""
CMX - byte-exact, integer-only context-mixing compressor, JSON-safe string form, and the .cmx file format.

Modes (low nibble of the first blob byte; high nibble = profile 0 light / 1 max)
  0 STORED  : original bytes (never grows by more than the header)
  1 GENERIC : context-mixing byte coder (any file)
  2 PNG     : pixels coded with a 2D image model; the original deflate stream is rebuilt bit-exactly
  3 JPEG    : lossless recompression of baseline JPEG: Huffman -> DCT coefficients -> context-mixed,
              DC predicted from pixel-domain edge continuity (integer IDCT), exact Huffman rebuild

Every encode is verified by running the decoder; on any mismatch it falls back to a safer mode.
All model arithmetic is integer-only (32-bit hashes, 12-bit probabilities, fixed-point IDCT) so a
JS / Rust / C port reproduces identical predictions.
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

    def __init__(s, nctx, nsel, nsel2, bits, light=False):
        s.light = light
        s.n = nctx; s.nin = nctx + 1; s.shift = 32 - bits
        size = 1 << bits
        s.pt = [array('H', [32768]) * size for _ in range(nctx)]
        s.ct = [array('B', bytes(size)) for _ in range(nctx)]
        s.w1 = [[s.WI] * s.nin for _ in range(nsel * 8)]
        if light: return
        s.w2 = [[s.WI] * s.nin for _ in range(nsel2 * 8)]
        # APM / SSE: 33 interpolation bins per context (c0 x 256)
        s.apm = [[(_squash((i - 16) * 128) * 16) for i in range(33)] for _ in range(256)]

    def code_byte_light(s, coder, sym, ctxs, msel):
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
            w = s.w1[msel * 8 + bi]
            dot = 0
            for j in rnin:
                dot += x[j] * w[j]
            d = dot >> 16
            if d > 2047: d = 2047
            elif d < -2047: d = -2047
            p = SQ[d + 2047]
            if p < 1: p = 1
            elif p > 4095: p = 4095
            bit = coder.code(((sym >> bi) & 1) if sym is not None else 0, p)
            err = ((bit << 12) - p) * LR
            for j in rnin:
                w[j] += (x[j] * err) >> SH
            tg = bit << 16
            for j in rn:
                t = pt[j]; ix = idx[j]; c = ct[j]; k = c[ix]
                t[ix] += ((tg - t[ix]) * RT[k]) >> 12
                if k < LIM: c[ix] = k + 1
            c0 = (c0 << 1) | bit
        return c0 & 255

    def code_bit(s, coder, bit, hs, msel, msel2, ai):
        """One binary decision from 6 caller-supplied context hashes (used by the JPEG model)."""
        n = s.n; nin = s.nin; shift = s.shift; pt = s.pt; ct = s.ct
        idx = [0] * n; x = [0] * nin; x[n] = 256
        for j in range(n):
            ix = ((hs[j] * 0x85EBCA6B) & M32) >> shift
            idx[j] = ix; x[j] = STRETCH[pt[j][ix] >> 4]
        w1 = s.w1[msel]; w2 = s.w2[msel2]
        dot1 = 0; dot2 = 0
        for j in range(nin):
            xj = x[j]; dot1 += xj * w1[j]; dot2 += xj * w2[j]
        d1 = dot1 >> 16; d2 = dot2 >> 16
        if d1 > 2047: d1 = 2047
        elif d1 < -2047: d1 = -2047
        if d2 > 2047: d2 = 2047
        elif d2 < -2047: d2 = -2047
        p1 = SQ[d1 + 2047]; p2 = SQ[d2 + 2047]
        dm = (d1 + d2) >> 1; pm = SQ[dm + 2047]
        a = s.apm[ai]
        pos = (dm + 2048) * 32; lo = pos >> 12; wt = pos & 4095
        pa = (a[lo] * (4096 - wt) + a[lo + 1] * wt) >> 16
        p = (pm + 3 * pa + 2) >> 2
        if p < 1: p = 1
        elif p > 4095: p = 4095
        bit = coder.code(bit, p)
        tg = bit << 16
        a[lo] += (tg - a[lo]) >> 6; a[lo + 1] += (tg - a[lo + 1]) >> 6
        e1 = ((bit << 12) - p1) * s.LR; e2 = ((bit << 12) - p2) * s.LR
        SH = s.SH; LIM = s.LIMIT
        for j in range(nin):
            xj = x[j]; w1[j] += (xj * e1) >> SH; w2[j] += (xj * e2) >> SH
        for j in range(n):
            t = pt[j]; ix = idx[j]; c = ct[j]; k = c[ix]
            t[ix] += ((tg - t[ix]) * RT[k]) >> 12
            if k < LIM: c[ix] = k + 1
        return bit


    def code_byte(s, coder, sym, ctxs, msel, msel2):
        if s.light: return s.code_byte_light(coder, sym, ctxs, msel)
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
    NSEL = 1

    def __init__(s, profile=1):
        s.buf = bytearray(); s.v = 0
        s.LIGHT = profile == 0
        s.NCTX = 4 if s.LIGHT else 8
        s.NSEL2 = 1 if s.LIGHT else 8

    def ctx(s):
        v = s.v
        if s.LIGHT:
            return [H(1, v & 0xFF), H(2, v & 0xFFFF), H(3, v & 0xFFFFFF), H(4, v & M32)], 0, 0
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
    def __init__(s, rb, bpp, profile=1):
        s.LIGHT = profile == 0
        s.NCTX = 5 if s.LIGHT else 14
        s.NSEL2 = 1 if s.LIGHT else 8
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
        if s.LIGHT:
            return [H(1, k, rW, rN), H(2, k, R1, rW), H(3, k, W, N, NW),
                    H(8, k, rW, rN, rNW, rNE), H(9, k, qe, _q(R1))], k, 0
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
    coder = Enc(); cm = CM(state.NCTX, state.NSEL, state.NSEL2, _bits_for(len(data)), state.LIGHT)
    for a in data:
        ctxs, ms, ms2 = state.ctx()
        sym = state.to_sym(a) if image else a
        cm.code_byte(coder, sym, ctxs, ms, ms2)
        state.push(sym)
    return coder.finish()


def _run_dec(state, blob, n, image):
    coder = Dec(blob); cm = CM(state.NCTX, state.NSEL, state.NSEL2, _bits_for(n), state.LIGHT)
    out = bytearray()
    for _ in range(n):
        ctxs, ms, ms2 = state.ctx()
        out.append(state.push(cm.code_byte(coder, None, ctxs, ms, ms2)))
    return bytes(out)


def cm_enc(data, profile=1): return _run_enc(GenState(profile), data, False)
def cm_dec(blob, n, profile=1): return _run_dec(GenState(profile), blob, n, False)
def img_enc(pix, rb, bpp, profile=1): return _run_enc(ImgState(rb, bpp, profile), pix, True)
def img_dec(blob, n, rb, bpp, profile=1): return _run_dec(ImgState(rb, bpp, profile), blob, n, True)


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


def _png_encode(orig, profile=1):
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
    mc = cm_enc(meta); fc = cm_enc(ft); pc = img_enc(pix, rb, bpp, profile)
    out = bytes([params[0] | (params[1] << 4), params[2], params[3]])
    out += vput(len(meta)) + vput(len(mc)) + mc + vput(len(fc)) + fc + pc
    return out


def _png_decode(pl, profile=1):
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
    ft = cm_dec(fc, h); pix = img_dec(pc, h * rb, rb, bpp, profile)
    stream = _deflate(_refilter(pix, ft, h, rb, bpp), (level, mem, strat, wb))
    out = bytearray(PNG_SIG); sp = 0
    for typ, ln, data in ents:
        if typ == b'IDAT': data = stream[sp:sp + ln]; sp += ln
        out += struct.pack('>I', len(data)) + typ + data
        out += struct.pack('>I', zlib.crc32(typ + data) & M32)
    return bytes(out) + tail


# ---------------------------------------------------------------- JPEG lossless transcoder
ZZ = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27,
      20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
      58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63]
ZZINV = [0] * 64
for _i, _n in enumerate(ZZ):
    ZZINV[_n] = _i

# fixed-point (2^14) orthonormal DCT basis /2 -- literal so every platform agrees bit for bit
DM = [[5793, 8035, 7568, 6811, 5793, 4551, 3135, 1598], [5793, 6811, 3135, -1598, -5793, -8035, -7568, -4551],
      [5793, 4551, -3135, -8035, -5793, 1598, 7568, 6811], [5793, 1598, -7568, -4551, 5793, 6811, -3135, -8035],
      [5793, -1598, -7568, 4551, 5793, -6811, -3135, 8035], [5793, -4551, -3135, 8035, -5793, -1598, 7568, -6811],
      [5793, -6811, 3135, 1598, -5793, 8035, -7568, 4551], [5793, -8035, 7568, -6811, 5793, -4551, 3135, -1598]]


def _mkq(th, n):
    out = []
    for v in range(n):
        k = 0
        for t in th:
            if v >= t: k += 1
        out.append(k - 1 if k else 0)
    return out


QN = _mkq((0, 1, 2, 3, 4, 5, 7, 9, 13, 19, 29, 43), 64)
QM = _mkq((0, 1, 2, 3, 4, 5, 7, 10, 15, 25, 50, 100), 2048)
QR = _mkq((1, 2, 3, 4, 6, 9, 14, 22, 35, 50), 64)


def _lines(nzf):
    """AC-only edge lines of a block: rows 0,1,6,7 then columns 0,1,6,7 (integer IDCT, no DC)."""
    if not nzf:
        z = [0] * 8
        return [z] * 8
    res = []
    for y in (0, 1, 6, 7):
        My = DM[y]; G = [0] * 8
        for v, u, val in nzf: G[u] += My[v] * val
        G = [(g + 64) >> 7 for g in G]
        res.append([(sum(DM[x][u] * G[u] for u in range(8)) + 1048576) >> 21 for x in range(8)])
    for x in (0, 1, 6, 7):
        Mx = DM[x]; G = [0] * 8
        for v, u, val in nzf: G[v] += Mx[u] * val
        G = [(g + 64) >> 7 for g in G]
        res.append([(sum(DM[y][v] * G[v] for v in range(8)) + 1048576) >> 21 for y in range(8)])
    return res


def _sg(v):
    return 0 if v == 0 else (1 if v > 0 else 2)


class JM:
    """Coefficient model. Same code path encodes (enc=True) and decodes (enc=False)."""
    def __init__(s, grids, qts, nblocks):
        s.grids = grids; s.q = qts
        s.cm = CM(6, 12, 16, max(16, min(22, nblocks.bit_length() + 8)))

    def bit(s, coder, b, bases, kind, c, aux, step):
        hs = [H(x, kind, step) for x in bases]
        if aux > 15: aux = 15
        return s.cm.code_bit(coder, b, hs, kind * 2 + (1 if c else 0), aux, kind * 16 + aux)

    def uint(s, coder, enc, m, bases, kind, c, emax):
        lo = [bases[0], bases[1], 0, 0, 0, 0]
        e = m.bit_length() if enc else 0
        j = 0
        while j < emax:
            if not s.bit(coder, 1 if (enc and e > j) else 0, bases, kind, c, j, j): break
            j += 1
        e = j
        if e <= 1: return e
        val = 1
        for t in range(e - 2, -1, -1):
            idx = e - 2 - t
            top = idx < 2
            b = s.bit(coder, ((m >> t) & 1) if enc else 0, bases if top else lo, kind, c,
                      12 + idx if top else 14, 1000 + e * 100 + t * 4 + (val if top else 0))
            val = (val << 1) | b
        return val

    def run(s, coder, enc, blocks):
        for c in range(len(blocks)):
            bw, bh = s.grids[c]; B = blocks[c]; q = s.q[c]; q00 = q[0]
            n = bw * bh
            nzl = [0] * n; resid = [0] * n; edges = [None] * n
            for by in range(bh):
                for bx in range(bw):
                    idx = by * bw + bx; blk = B[idx]
                    A = idx - bw; Lf = idx - 1
                    # ---- number of nonzero AC coefficients
                    if by and bx: nA = nzl[A]; nL = nzl[Lf]
                    elif by: nA = nL = nzl[A]
                    elif bx: nA = nL = nzl[Lf]
                    else: nA = nL = 0
                    avg = (nA + nL + 1) >> 1
                    bases = [H(c, QN[nA], QN[nL]), H(c, QN[avg], (by == 0) * 2 + (bx == 0)),
                             H(c, avg), H(c, 0), H(c, nA), H(c, nL)]
                    nz = sum(1 for i in range(1, 64) if blk[i]) if enc else None
                    nz = s.uint(coder, enc, nz, bases, 0, c, 6)
                    nzl[idx] = nz
                    # ---- AC coefficients in zigzag order
                    Aa = B[A] if by else None; La = B[Lf] if bx else None
                    rem = nz; i = 1
                    while rem > 0 and i < 64:
                        a = Aa[i] if Aa else 0; l = La[i] if La else 0
                        nn = ZZ[i]
                        j = ZZINV[nn - 8] if nn >= 8 else 0
                        Uv = blk[j] if j else 0
                        j = ZZINV[nn - 1] if (nn & 7) else 0
                        Lu = blk[j] if j else 0
                        pb = blk[i - 1] if i >= 2 else 0
                        pb2 = blk[i - 2] if i >= 3 else 0
                        aa = abs(a); al = abs(l); au = abs(Uv); alu = abs(Lu); ap = abs(pb)
                        qa = QM[aa if aa < 2047 else 2047]; ql = QM[al if al < 2047 else 2047]
                        qu = QM[au if au < 2047 else 2047]; qlu = QM[alu if alu < 2047 else 2047]
                        qp = QM[ap if ap < 2047 else 2047]
                        qsum = QM[min(2047, (aa + al + au + alu + 2) >> 2)]
                        rb = QR[rem]
                        if 64 - i == rem:
                            nzf = 1
                        else:
                            fb = [H(c, i, rb), H(c, i, qa, ql), H(c, i, qu, qlu), H(c, i, rb, qp),
                                  H(c, qsum, rb, i >> 3), H(c, i, qp, QM[min(2047, abs(pb2))], qu)]
                            nzf = s.bit(coder, 1 if (enc and blk[i]) else 0, fb, 1, c, i >> 2, 0)
                        if nzf:
                            v = blk[i] if enc else 0
                            mb = [H(c, i, qa, ql), H(c, i, QM[min(2047, (aa + al + 1) >> 1)]),
                                  H(c, i, qu, qlu), H(c, qsum, rb), H(c, i, qp), H(c, i)]
                            mag = s.uint(coder, enc, (abs(v) - 1) if enc else None, mb, 2, c, 11) + 1
                            sa = _sg(a); sl = _sg(l); su = _sg(Uv); slu = _sg(Lu)
                            sb = [H(c, i, sa, sl), H(c, i, su, slu), H(c, i, sa), H(c, i, sl),
                                  H(c, i, sa, sl, su, slu), H(c, i)]
                            neg = s.bit(coder, 1 if (enc and v < 0) else 0, sb, 3, c, 0, 0)
                            blk[i] = -mag if neg else mag
                            rem -= 1
                        i += 1
                    # ---- DC: predicted from pixel-domain edge continuity with neighbours
                    nzf = [(ZZ[i] >> 3, ZZ[i] & 7, blk[i] * q[i]) for i in range(1, 64) if blk[i]]
                    ln = _lines(nzf)
                    t0, t1, c0, c1 = ln[0], ln[1], ln[4], ln[5]
                    pa = pl = None
                    if by:
                        b6, b7 = edges[A][0], edges[A][1]
                        N = 0
                        for x in range(8): N += 3 * b7[x] - b6[x] + t1[x] - 3 * t0[x]
                        pa = (N + q00) // (2 * q00)
                    if bx:
                        r6, r7 = edges[Lf][2], edges[Lf][3]
                        N = 0
                        for y in range(8): N += 3 * r7[y] - r6[y] + c1[y] - 3 * c0[y]
                        pl = (N + q00) // (2 * q00)
                    if pa is not None and pl is not None:
                        p = (pa + pl + 1) >> 1; d = abs(pa - pl)
                        qd = min(QE[d if d < 1023 else 1023], 12); sd = _sg(pa - pl)
                    elif pa is not None: p = pa; qd = 14; sd = 3
                    elif pl is not None: p = pl; qd = 15; sd = 3
                    else: p = 0; qd = 13; sd = 3
                    ra = resid[A] if by else 0; rl = resid[Lf] if bx else 0
                    qra = QM[min(2047, abs(ra))]; qrl = QM[min(2047, abs(rl))]
                    r = (blk[0] - p) if enc else 0
                    db = [H(c, qd), H(c, qd, QN[nz]), H(c, qra), H(c, qrl),
                          H(c, qd, QM[min(2047, (abs(ra) + abs(rl) + 1) >> 1)]), H(c, 0)]
                    mag = s.uint(coder, enc, abs(r) if enc else None, db, 4, c, 13)
                    if mag:
                        sdb = [H(c, sd, qd), H(c, sd), H(c, _sg(ra), _sg(rl)), H(c, _sg(ra)), H(c, _sg(rl)), H(c, 0)]
                        neg = s.bit(coder, 1 if (enc and r < 0) else 0, sdb, 5, c, 0, 0)
                        r = -mag if neg else mag
                    else:
                        r = 0
                    dc = p + r
                    blk[0] = dc; resid[idx] = r
                    dco = (dc * q00 + 4) >> 3
                    edges[idx] = ([v + dco for v in ln[2]], [v + dco for v in ln[3]],
                                  [v + dco for v in ln[6]], [v + dco for v in ln[7]])


# ---- JPEG container parsing / Huffman
class BitR:
    def __init__(s, data):
        s.d = data; s.p = 0; s.acc = 0; s.n = 0; s.over = False

    def get(s, k):
        while s.n < k:
            if s.p < len(s.d): b = s.d[s.p]
            else: b = 0; s.over = True
            s.p += 1; s.acc = ((s.acc << 8) | b) & 0xFFFFFFFFFFFF; s.n += 8
        s.n -= k
        return (s.acc >> s.n) & ((1 << k) - 1)

    def bits_consumed(s): return s.p * 8 - s.n


def _huff_dec_table(counts, syms):
    t = {}; code = 0; k = 0
    for l in range(1, 17):
        for _ in range(counts[l - 1]):
            t[(l, code)] = syms[k]; k += 1; code += 1
        code <<= 1
    return t


def _huff_enc_table(counts, syms):
    t = {}; code = 0; k = 0
    for l in range(1, 17):
        for _ in range(counts[l - 1]):
            t[syms[k]] = (code, l); k += 1; code += 1
        code <<= 1
    return t


def _jpeg_hdr(d):
    if d[:2] != b'\xff\xd8': raise ValueError('not jpeg')
    p = 2; qt = {}; dht = {}; sof = None; dri = 0
    while True:
        if d[p] != 0xFF: raise ValueError('marker')
        m = d[p + 1]
        if m == 0xFF: p += 1; continue
        L = struct.unpack('>H', d[p + 2:p + 4])[0]; seg = d[p + 4:p + 2 + L]
        if m in (0xC0, 0xC1):
            prec, H_, W_, nc = struct.unpack('>BHHB', seg[:6])
            if prec != 8 or nc not in (1, 3): raise ValueError('unsupported sof')
            comps = [(seg[6 + 3 * i], seg[7 + 3 * i] >> 4, seg[7 + 3 * i] & 15, seg[8 + 3 * i]) for i in range(nc)]
            sof = (W_, H_, comps)
        elif 0xC2 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC): raise ValueError('unsupported coding')
        elif m == 0xC4:
            q = 0
            while q < len(seg):
                tc = seg[q] >> 4; th = seg[q] & 15; counts = list(seg[q + 1:q + 17]); n = sum(counts)
                dht[(tc, th)] = (counts, list(seg[q + 17:q + 17 + n])); q += 17 + n
        elif m == 0xDB:
            q = 0
            while q < len(seg):
                pq = seg[q] >> 4; tq = seg[q] & 15; q += 1
                if pq: vals = list(struct.unpack('>64H', seg[q:q + 128])); q += 128
                else: vals = list(seg[q:q + 64]); q += 64
                qt[tq] = vals
        elif m == 0xDD: dri = struct.unpack('>H', seg[:2])[0]
        elif m == 0xDA:
            ns = seg[0]; sc = [(seg[1 + 2 * i], seg[2 + 2 * i] >> 4, seg[2 + 2 * i] & 15) for i in range(ns)]
            ss, se, ah = seg[1 + 2 * ns], seg[2 + 2 * ns], seg[3 + 2 * ns]
            if sof is None or ns != len(sof[2]) or ss != 0 or se != 63 or ah != 0: raise ValueError('scan')
            return dict(W=sof[0], H=sof[1], comps=sof[2], qt=qt, dht=dht, dri=dri, scan=sc, end=p + 2 + L)
        p += 2 + L


def _jpeg_layout(h):
    comps = h['comps']; nc = len(comps)
    if nc == 1:
        bw = (h['W'] + 7) // 8; bh = (h['H'] + 7) // 8
        return [(bw, bh)], [(1, 1)], bw, bh
    hm = max(c[1] for c in comps); vm = max(c[2] for c in comps)
    mx = (h['W'] + 8 * hm - 1) // (8 * hm); my = (h['H'] + 8 * vm - 1) // (8 * vm)
    return [(mx * c[1], my * c[2]) for c in comps], [(c[1], c[2]) for c in comps], mx, my


def _jpeg_qts(h):
    out = []
    for cid, hh, vv, tq in h['comps']:
        qz = h['qt'][tq]
        out.append([max(1, v) for v in qz])      # stored in zigzag order already
    return out


def _jpeg_split(d, h):
    i = h['end']; n = len(d); segs = []; cur = bytearray(); expect = 0
    while i < n - 1:
        b = d[i]
        if b == 0xFF:
            nx = d[i + 1]
            if nx == 0: cur.append(0xFF); i += 2; continue
            if 0xD0 <= nx <= 0xD7:
                if nx != 0xD0 + (expect & 7): raise ValueError('rst order')
                expect += 1; segs.append(bytes(cur)); cur = bytearray(); i += 2; continue
            if nx == 0xFF: raise ValueError('fill')
            segs.append(bytes(cur)); return segs, d[i:]
        cur.append(b); i += 1
    raise ValueError('no end marker')


def _jpeg_scan_decode(segs, h):
    grids, hv, mx, my = _jpeg_layout(h); nc = len(grids); total = mx * my; dri = h['dri']
    nseg = ((total + dri - 1) // dri) if dri else 1
    if nseg != len(segs): raise ValueError('segment count')
    blocks = [[[0] * 64 for _ in range(g[0] * g[1])] for g in grids]
    tabs = []
    for (cid, td, ta) in h['scan']:
        tabs.append((_huff_dec_table(*h['dht'][(0, td)]), _huff_dec_table(*h['dht'][(1, ta)])))
    mcu = 0
    for si, seg in enumerate(segs):
        br = BitR(seg); pred = [0] * nc
        cnt = dri if dri else total
        for _ in range(cnt):
            if mcu >= total: break
            my_, mx_ = divmod(mcu, mx)
            for ci in range(nc):
                hh, vv = hv[ci]; bw = grids[ci][0]; dct, act = tabs[ci]
                for yy in range(vv):
                    for xx in range(hh):
                        blk = blocks[ci][(my_ * vv + yy) * bw + mx_ * hh + xx]
                        code = 0; l = 0
                        while True:
                            code = (code << 1) | br.get(1); l += 1
                            sy = dct.get((l, code))
                            if sy is not None: break
                            if l > 16: raise ValueError('huff')
                        diff = 0
                        if sy:
                            v = br.get(sy); diff = v if v >= (1 << (sy - 1)) else v - (1 << sy) + 1
                        pred[ci] += diff; blk[0] = pred[ci]
                        k = 1
                        while k < 64:
                            code = 0; l = 0
                            while True:
                                code = (code << 1) | br.get(1); l += 1
                                rs = act.get((l, code))
                                if rs is not None: break
                                if l > 16: raise ValueError('huff')
                            r = rs >> 4; sz = rs & 15
                            if sz == 0:
                                if r == 15: k += 16; continue
                                break
                            k += r
                            if k > 63: raise ValueError('run')
                            v = br.get(sz); blk[k] = v if v >= (1 << (sz - 1)) else v - (1 << sz) + 1
                            k += 1
                        if k > 64: raise ValueError('run')
            mcu += 1
        if br.over: raise ValueError('overrun')
        used = br.bits_consumed()
        if (used + 7) // 8 != len(seg): raise ValueError('trailing bytes in scan')
        pad = (8 - used % 8) % 8
        if pad and (seg[-1] & ((1 << pad) - 1)) != (1 << pad) - 1: raise ValueError('pad bits')
    if mcu != total: raise ValueError('short scan')
    return blocks


class BitW:
    def __init__(s): s.out = bytearray(); s.acc = 0; s.n = 0

    def put(s, code, ln):
        s.acc = (s.acc << ln) | code; s.n += ln
        while s.n >= 8:
            s.n -= 8; b = (s.acc >> s.n) & 255; s.out.append(b)
            if b == 255: s.out.append(0)
        s.acc &= (1 << s.n) - 1

    def flush(s):
        if s.n: s.put((1 << (8 - s.n)) - 1, 8 - s.n)


def _bl(v): return abs(v).bit_length()


def _jpeg_scan_encode(blocks, h):
    grids, hv, mx, my = _jpeg_layout(h); nc = len(grids); total = mx * my; dri = h['dri']
    tabs = []
    for (cid, td, ta) in h['scan']:
        tabs.append((_huff_enc_table(*h['dht'][(0, td)]), _huff_enc_table(*h['dht'][(1, ta)])))
    out = bytearray(); w = BitW(); pred = [0] * nc; rst = 0
    for mcu in range(total):
        if dri and mcu and mcu % dri == 0:
            w.flush(); out += w.out; out += bytes([0xFF, 0xD0 + (rst & 7)]); rst += 1
            w = BitW(); pred = [0] * nc
        my_, mx_ = divmod(mcu, mx)
        for ci in range(nc):
            hh, vv = hv[ci]; bw = grids[ci][0]; dct, act = tabs[ci]
            for yy in range(vv):
                for xx in range(hh):
                    blk = blocks[ci][(my_ * vv + yy) * bw + mx_ * hh + xx]
                    diff = blk[0] - pred[ci]; pred[ci] = blk[0]; s_ = _bl(diff)
                    w.put(*dct[s_])
                    if s_: w.put(diff if diff >= 0 else diff + (1 << s_) - 1, s_)
                    last = 0
                    for k in range(63, 0, -1):
                        if blk[k]: last = k; break
                    run = 0
                    for k in range(1, last + 1):
                        v = blk[k]
                        if v == 0: run += 1; continue
                        while run >= 16: w.put(*act[0xF0]); run -= 16
                        s_ = _bl(v); w.put(*act[(run << 4) | s_])
                        w.put(v if v > 0 else v + (1 << s_) - 1, s_); run = 0
                    if last < 63: w.put(*act[0x00])
    w.flush(); out += w.out
    return bytes(out)


def _jpeg_encode(orig):
    h = _jpeg_hdr(orig)
    segs, tail = _jpeg_split(orig, h)
    blocks = _jpeg_scan_decode(segs, h)
    if _jpeg_scan_encode(blocks, h) != orig[h['end']:len(orig) - len(tail)]:
        raise ValueError('scan not canonical')
    grids = _jpeg_layout(h)[0]
    coder = Enc(); jm = JM(grids, _jpeg_qts(h), sum(g[0] * g[1] for g in grids))
    jm.run(coder, True, blocks)
    hdr = orig[:h['end']]; hc = cm_enc(hdr)
    return vput(len(hdr)) + vput(len(hc)) + hc + vput(len(tail)) + tail + coder.finish()


def _jpeg_decode(pl):
    hl, p = vget(pl, 0); hcl, p = vget(pl, p); hdr = cm_dec(pl[p:p + hcl], hl); p += hcl
    tl, p = vget(pl, p); tail = pl[p:p + tl]; p += tl; stream = pl[p:]
    h = _jpeg_hdr(hdr + b'\xff\xd9')
    grids = _jpeg_layout(h)[0]
    blocks = [[[0] * 64 for _ in range(g[0] * g[1])] for g in grids]
    jm = JM(grids, _jpeg_qts(h), sum(g[0] * g[1] for g in grids))
    jm.run(Dec(stream), False, blocks)
    return hdr + _jpeg_scan_encode(blocks, h) + tail


# ---------------------------------------------------------------- container
def _wrap(mode, orig, payload, profile=1):
    return bytes([mode | (profile << 4)]) + hashlib.sha256(orig).digest()[:4] + vput(len(orig)) + payload


def decode(blob):
    mode = blob[0] & 15; profile = blob[0] >> 4
    chk = blob[1:5]; n, p = vget(blob, 5); pl = blob[p:]
    if mode == 0: out = pl
    elif mode == 1: out = cm_dec(pl, n, profile)
    elif mode == 2: out = _png_decode(pl, profile)
    elif mode == 3: out = _jpeg_decode(pl)
    else: raise ValueError('unknown mode')
    if len(out) != n or hashlib.sha256(out).digest()[:4] != chk:
        raise ValueError('integrity check failed')
    return out


def encode(orig, verbose=False, profile=1):
    best = _wrap(0, orig, orig, 0)
    cands = []
    if orig[:2] == b'\xff\xd8':
        try: cands.append(_wrap(3, orig, _jpeg_encode(orig), profile))
        except Exception as e:
            if verbose: print('  jpeg path unavailable:', e)
    if orig[:8] == PNG_SIG:
        try: cands.append(_wrap(2, orig, _png_encode(orig, profile), profile))
        except Exception as e:
            if verbose: print('  png path unavailable:', e)
    if not cands:
        cands.append(_wrap(1, orig, cm_enc(orig, profile), profile))
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


# ---------------------------------------------------------------- .cmx file
CMX_MAGIC = b'CMX\x01'
def to_file(data, profile=1): return CMX_MAGIC + encode(data, profile=profile)
def from_file(f):
    if f[:4] != CMX_MAGIC: raise ValueError('not a .cmx file')
    return decode(f[4:])


if __name__ == '__main__':
    import sys
    if len(sys.argv) in (4, 5) and sys.argv[1] in ('pack', 'unpack'):
        src = open(sys.argv[2], 'rb').read()
        if sys.argv[1] == 'pack':
            out = to_file(src, profile=int(sys.argv[4]) if len(sys.argv) == 5 else 1)
        else:
            out = from_file(src)
        open(sys.argv[3], 'wb').write(out)
        print(len(src), '->', len(out), 'bytes')
    else:
        print('usage: python3 cmx.py pack <in> <out.cmx> [profile 0=light|1=max] | unpack <in.cmx> <out>')
