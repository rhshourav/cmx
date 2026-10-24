"""
cmx_lossy - the "Compressed" tier of .cmx (mode 4), chosen automatically per image.

What it does
  * auto-rotates from EXIF, strips location/camera metadata (privacy), keeps the colour profile
  * classifies the image: photos may be compressed; screenshots / graphics / tiny files stay lossless
  * resizes to a sane chat size (default long edge 1600 px) - never upscales
  * for every available codec (JPEG, WebP, AVIF) searches the lowest quality that still meets a
    fidelity floor (luma SSIM measured at the size actually sent), then keeps the smallest result
  * JPEG candidates are additionally recompressed losslessly with the .cmx JPEG model (kind 1)
  * optional byte budget: shrinks the picture step by step until it fits
The file is always marked lossy (mode 4); decoding returns the compressed image, never pretends to
be the original.  Needs: pip install pillow numpy
"""
import io, os, subprocess, tempfile, time
import cmx

CODEC_ID = {'jpeg': 0, 'webp': 1, 'avif': 2}
CODEC_NAME = {v: k for k, v in CODEC_ID.items()}


def _deps():
    try:
        import numpy as np
        from PIL import Image, ImageOps, features
    except ImportError:
        raise SystemExit('The compressed tier needs Pillow and numpy:  pip install pillow numpy')
    return np, Image, ImageOps, features


def capabilities():
    out = {'native_core': cmx._native()}
    try:
        np, Image, ImageOps, features = _deps()
        import PIL
        out.update(pillow=PIL.__version__, numpy=np.__version__, webp=bool(features.check('webp')),
                   avif=bool(features.check('avif')))
    except SystemExit:
        out.update(pillow=None, numpy=None, webp=False, avif=False)
    return out


# ------------------------------------------------------------------ metrics / classification
def ssim_luma(np, a, b, win=7):
    """Mean SSIM of the luma channel (uniform 7x7 window, like skimage's default)."""
    def luma(x): return (0.299 * x[..., 0] + 0.587 * x[..., 1] + 0.114 * x[..., 2]).astype(np.float64)
    x = luma(a); y = luma(b)
    if min(x.shape) < win: return 1.0 if np.array_equal(x, y) else 0.0

    def box(z):
        c = np.cumsum(np.cumsum(np.pad(z, ((1, 0), (1, 0))), 0), 1)
        return (c[win:, win:] - c[:-win, win:] - c[win:, :-win] + c[:-win, :-win]) / (win * win)
    ux, uy = box(x), box(y); n = win * win; k = n / (n - 1)
    vx = k * (box(x * x) - ux * ux); vy = k * (box(y * y) - uy * uy); vxy = k * (box(x * y) - ux * uy)
    c1 = (0.01 * 255) ** 2; c2 = (0.03 * 255) ** 2
    s = ((2 * ux * uy + c1) * (2 * vxy + c2)) / ((ux * ux + uy * uy + c1) * (vx + vy + c2))
    return float(s.mean())


def classify(np, im):
    """'photo' or 'graphic' (screenshots, UI, text, flat art): graphics have few distinct colours."""
    small = im.convert('RGB'); small.thumbnail((256, 256))
    a = np.asarray(small).reshape(-1, 3).astype(np.uint32)
    packed = (a[:, 0] << 16) | (a[:, 1] << 8) | a[:, 2]
    ratio = len(np.unique(packed)) / len(packed)
    return ('graphic' if ratio < 0.12 else 'photo'), ratio


# ------------------------------------------------------------------ encoders
def _encode(Image, im, codec, q, icc, cpu):
    b = io.BytesIO(); kw = {}
    if icc: kw['icc_profile'] = icc
    if codec == 'jpeg':
        im.convert('RGB').save(b, 'JPEG', quality=q, optimize=True, progressive=False, **kw)   # baseline: stackable with mode 3
    elif codec == 'webp':
        im.save(b, 'WEBP', quality=q, method=2 if cpu == 'weak' else 4, **kw)
    else:
        im.save(b, 'AVIF', quality=q, speed=9 if cpu == 'weak' else 7, **kw)
    return b.getvalue()


def _fidelity(np, Image, data, ref_arr):
    dec = Image.open(io.BytesIO(data)).convert('RGB')
    return ssim_luma(np, ref_arr, np.asarray(dec))


def _search(np, Image, im, ref_arr, codec, floor, icc, cpu, lo, hi, iters):
    """Binary search of the lowest quality whose fidelity >= floor. Returns (bytes, quality, ssim)."""
    best = None; last = None
    for _ in range(iters):
        if lo > hi: break
        mid = (lo + hi) // 2
        data = _encode(Image, im, codec, mid, icc, cpu); s = _fidelity(np, Image, data, ref_arr)
        last = (data, mid, s)
        if s >= floor: best = last; hi = mid - 1
        else: lo = mid + 1
    if best is None:                                   # even the top quality missed the floor: take the top
        data = _encode(Image, im, codec, hi if hi >= 1 else 95, icc, cpu)
        best = (data, hi, _fidelity(np, Image, data, ref_arr))
    return best


def stack_jpeg(jpeg_bytes):
    """Losslessly recompress a baseline JPEG with the .cmx JPEG model; returns the mode-3 blob or None."""
    nat = cmx._native()
    if nat:
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, 'a.jpg'); b = os.path.join(d, 'a.cmx'); open(a, 'wb').write(jpeg_bytes)
            if subprocess.run([nat, 'pack', a, b], capture_output=True).returncode == 0:
                f = open(b, 'rb').read(); blob = f[4:]
                return blob if (blob[0] & 15) == 3 else None
        return None
    if len(jpeg_bytes) <= 60_000:                      # pure Python is only sensible for small files
        blob = cmx.encode(jpeg_bytes)
        return blob if (blob[0] & 15) == 3 else None
    return None



def _exact(data, say):
    """Exact-tier blob for `data`, warning about the time when only the slow Python model is available."""
    import struct
    if data[:2] == b'\xff\xd8':
        blob = stack_jpeg(data) if cmx._native() else None
        if blob is not None: return blob
        try:
            h = cmx._jpeg_hdr(data); mp = h['W'] * h['H'] / 1e6
            if mp > 0.3 and not cmx._native(): say('note: exact JPEG path in pure Python: about %.0f min (build cmxc for ~100x speed)' % (mp * 138 / 60))
        except Exception: pass
    elif data[:8] == cmx.PNG_SIG:
        try:
            w, h, depth, ct = struct.unpack('>IIBB', data[16:26]); raw = w * h * cmx.CH.get(ct, 3) * max(1, depth // 8)
            if raw > 150_000: say('note: exact PNG path runs the Python model (~4 KB/s): about %.0f s for this image' % (raw / 4000))
        except Exception: pass
    return cmx.encode(data)


def _exact_estimate(data):
    """Cheap estimate of the exact-tier size, used only for the 'is lossy worth it' safety check."""
    if data[:2] == b'\xff\xd8':
        blob = stack_jpeg(data) if cmx._native() else None
        return len(blob) if blob is not None else int(len(data) * 0.82)
    return int(len(data) * 0.9)


# ------------------------------------------------------------------ the smart packer
def smart_pack(data, tier='auto', ssim=0.92, max_edge=1600, target_kb=None, cpu='normal', log=None):
    """Return (cmx_blob, report). tier: 'original' | 'compressed' | 'auto'."""
    t0 = time.time(); say = log or (lambda s: None); rep = {'reasons': []}
    why = rep['reasons'].append
    if tier == 'original':
        blob = _exact(data, say); rep.update(tier='original', lossy=False, out=len(blob), src=len(data)); why('requested lossless')
        return blob, rep
    try:
        np, Image, ImageOps, features = _deps()
        im0 = Image.open(io.BytesIO(data)); fmt0 = im0.format; true_size = im0.size
        if fmt0 == 'JPEG': im0.draft('RGB', (max_edge * 2, max_edge * 2))      # decode big JPEGs at reduced size (fast)
        im0.load()
    except SystemExit:
        if tier == 'compressed': raise
        why('Pillow/numpy not installed -> lossless only'); blob = _exact(data, say)
        rep.update(tier='original', lossy=False, out=len(blob), src=len(data)); return blob, rep
    except Exception:
        if tier == 'compressed': raise SystemExit('not a readable image file; cannot use the compressed tier')
        why('not a recognised image -> lossless'); blob = _exact(data, say)
        rep.update(tier='original', lossy=False, out=len(blob), src=len(data)); return blob, rep

    icc = im0.info.get('icc_profile')
    im = ImageOps.exif_transpose(im0)                                  # apply phone rotation, then metadata is dropped
    has_alpha = im.mode in ('RGBA', 'LA', 'PA') or 'transparency' in im.info
    ow, oh = im.size; kind, ratio = classify(np, im)
    k = true_size[0] / im0.size[0]; tw, th = round(ow * k), round(oh * k)           # true dimensions of the original
    rep.update(src=len(data), src_dims=(tw, th), content=kind, colour_ratio=round(ratio, 3), format=fmt0)
    say('image %dx%d %s, looks like a %s (colour variety %.2f)' % (tw, th, fmt0, kind, ratio))

    if tier == 'auto':
        if kind == 'graphic': why('screenshot/graphic: lossy would blur text and edges -> keep exact')
        elif len(data) < 60_000: why('already small (<60 KB): not worth degrading -> keep exact')
        elif target_kb is None and max(ow, oh) <= 600 and len(data) < 150_000: why('small photo -> keep exact')
        if rep['reasons']:
            blob = _exact(data, say); rep.update(tier='original', lossy=False, out=len(blob)); return blob, rep
        why('photo, large enough to benefit -> compressed tier')

    # ---- candidate generation
    work = im.convert('RGBA') if has_alpha else im.convert('RGB')
    codecs = ['jpeg', 'webp', 'avif'] if not has_alpha else ['webp', 'avif']
    cap = capabilities()
    if not cap['webp']: codecs = [c for c in codecs if c != 'webp']
    if not cap['avif'] or cpu == 'weak': codecs = [c for c in codecs if c != 'avif']
    if cpu == 'weak': why('weak-device mode: AVIF skipped (slow to encode)')
    if has_alpha: why('has transparency: JPEG excluded')
    budget = int(target_kb * 1024) if target_kb else None
    scales = [1.0] if budget is None else [1.0, 0.8, 0.65, 0.5, 0.4, 0.3, 0.22]
    base_scale = min(1.0, max_edge / max(ow, oh))
    best_overall = None
    for sc in scales:
        s = base_scale * sc
        size = (max(16, round(ow * s)), max(16, round(oh * s)))
        img = work if size == work.size else work.resize(size, Image.LANCZOS)
        ref = np.asarray(img.convert('RGB'))
        cands = []
        for codec in codecs:
            lo, hi, it = {'jpeg': (25, 95, 6), 'webp': (25, 95, 6), 'avif': (15, 90, 5)}[codec]
            if cpu == 'weak': it = max(4, it - 1)
            data_c, q, sc_ssim = _search(np, Image, img, ref, codec, ssim, icc, cpu, lo, hi, it)
            cands.append(dict(codec=codec, q=q, ssim=sc_ssim, data=data_c, size=len(data_c), stacked=None))
            say('  %.2fx %dx%d  %-4s q%-3d ssim %.3f  %8d bytes' % (sc, size[0], size[1], codec, q, sc_ssim, len(data_c)))
        for c in cands:                                   # lossless JPEG model on top of the lossy JPEG
            if c['codec'] == 'jpeg':
                blob = stack_jpeg(c['data'])
                if blob is not None and len(blob) < c['size']: c['stacked'] = blob; c['size'] = len(blob)
        cands.sort(key=lambda c: c['size'])
        best = cands[0]; best.update(dims=size, scale=sc)
        if best_overall is None or best['size'] < best_overall['size']: best_overall = best
        if budget is None or best['size'] <= budget: best_overall = best; break
    best = best_overall
    if budget is not None and best['size'] > budget: why('byte budget %d KB not reachable at the smallest size tried' % target_kb)
    elif budget is not None: why('shrunk to %.2fx to fit the %d KB budget' % (best['scale'], target_kb))

    # ---- safety: never return something bigger than the exact tier would
    if not budget and best['size'] + 12 >= _exact_estimate(data):
        exact = _exact(data, say)
        if best['size'] + 12 >= len(exact):
            why('lossy result not smaller than lossless -> keep exact'); rep.update(tier='original', lossy=False, out=len(exact)); return exact, rep

    body = best['stacked'] if best['stacked'] is not None else best['data']
    kindb = 1 if best['stacked'] is not None else 0
    payload = bytes([kindb]) + cmx.vput(tw) + cmx.vput(th) + cmx.vput(len(data)) + bytes([int(round(best['ssim'] * 100)), CODEC_ID[best['codec']]]) + body
    blob = cmx._wrap(4, best['data'], payload)
    assert cmx.decode(blob) == best['data']                              # verify-after-encode, same guarantee as the exact tier
    rep.update(tier='compressed', lossy=True, codec=best['codec'], quality=best['q'], ssim=round(best['ssim'], 3),
               dims=best['dims'], scale=best['scale'], stacked=best['stacked'] is not None, out=len(blob),
               seconds=round(time.time() - t0, 2))
    return blob, rep


def describe(blob):
    """Facts about a blob (no decoding of pixels needed)."""
    mode = blob[0] & 15
    d = {'mode': mode, 'lossy': mode == 4}
    n, p = cmx.vget(blob, 5); d['bytes_after_decode'] = n
    if mode == 4:
        pl = blob[p:]; kind = pl[0]; q = 1
        w, q = cmx.vget(pl, q); h, q = cmx.vget(pl, q); ob, q = cmx.vget(pl, q)
        d.update(kind=kind, original_dims=(w, h), original_bytes=ob, fidelity=pl[q] / 100.0, codec=CODEC_NAME.get(pl[q + 1], '?'),
                 stacked=kind == 1)
    return d
