# CMX 0.3 — smart image files for a low-bandwidth messenger

Two tiers, chosen per image (or forced):

| tier | what you get | typical saving | decode result |
|---|---|---|---|
| **original** | lossless recompression (JPEG model, PNG model, generic) | 19–26 % | the *identical bytes* |
| **compressed** | smart lossy (AVIF / WebP / JPEG+lossless model), auto-picked | 80–97 % on photos | the compressed image (clearly marked lossy) |

`auto` (default) keeps screenshots, graphics, text, tiny files and small photos **exact**, and compresses
large photos. Nothing is ever lossy silently: mode 4 in the header, `cmx.py info`, and a notice on unpack.

## Install / use
    pip install pillow numpy                  # only needed for the compressed tier
    gcc -O2 -o cmxc cmxc.c                    # optional native core, ~100x faster for JPEG (see below)
    python cmx.py doctor                      # what this machine supports
    python cmx.py pack  photo.jpg photo.cmx                  # auto
    python cmx.py pack  photo.jpg photo.cmx --tier original  # byte-exact
    python cmx.py pack  photo.jpg photo.cmx --tier compressed --ssim 0.92 --max-edge 1600
    python cmx.py pack  photo.jpg photo.cmx --net slow       # fit in 150 KB (or --target-kb N)
    python cmx.py pack  photo.jpg photo.cmx --cpu weak       # skip slow AVIF encoder (weak phones)
    python cmx.py info  photo.cmx | python cmx.py unpack photo.cmx out.jpg
Windows without a compiler: `pip install ziglang` then `python -m ziglang cc -O2 -o cmxc.exe cmxc.c`.
The included `cmxc.exe` was cross-compiled on Linux and NOT run on Windows by the author; rebuild if in doubt.

## What "smart" does (cmx_lossy.py)
* auto-rotates from EXIF, then drops EXIF/GPS (privacy); keeps the colour profile
* classifies photo vs graphic (colour variety); graphics / <60 KB / small photos stay exact
* resizes to max 1600 px (never upscales); big JPEGs are decoded at reduced size for speed
* per codec, binary-searches the lowest quality whose luma-SSIM (measured at the size sent) >= floor (0.92),
  then keeps the smallest of JPEG(+.cmx lossless model on top) / WebP / AVIF; JPEG is baseline so it stacks
* byte budget: steps the picture size down (1.0, .8, .65, .5, .4, .3, .22) until it fits
* verify-after-encode, same as the exact tier; refuses a lossy result that is not smaller than exact

Measured, real photos (phone-quality JPEG in, SSIM floor 0.92): astronaut 91 %, cat 80 %, coffee 82 %
(avg 84 %) in 1–2 s each; 12 MP synthetic photo -> 98 % in 13 s. Exact tier on the same files: 19–22 %.
The 12 MP image is a smooth upscale, so real camera photos will compress less than that figure.

## File format
    file   = "CMX" 0x01 | blob                 (relay/transport may drop the 4-byte magic)
    blob   = mode|profile<<4 | SHA-256(decoded bytes)[0:4] | varint(len) | payload
    mode 0 stored | 1 generic | 2 png | 3 jpeg (lossless)            (see 0.2 notes in cmx.py)
    mode 4 lossy   payload = kind | varint origW | varint origH | varint origBytes | fidelity x100 | codec | body
                   kind 0: body = image file (jpeg/webp/avif)   kind 1: body = a complete mode-3 blob
                   decode returns the image file; codec 0 jpeg, 1 webp, 2 avif
    text form      {"cmx":1,"d":"<base85, JSON-safe, blob without magic>"}
Checksum covers the decoded image bytes. The informational fields (origW/H, origBytes, fidelity) are not
checksummed. Bad checksum / truncation -> decoder raises, never returns wrong data.

## Platforms
Python: everything. Native (cmxc): modes 0, 1, 3, 4 decode; JPEG encode (PNG, lossy encode stay in Python).
JS (cmx.mjs, needs `npm i pako`): decode modes 0-4; encode generic only. AVIF/WebP bytes are displayed with the
platform decoder (Android 12+, current browsers; WebP is the universal fallback — use --cpu weak on old devices).
Conformance: `python verify_vectors.py && node verify_vectors.mjs && python verify_native.py` (14 vectors).
Tests: `python test_smart.py`, `python fuzz.py`.

## Limits
* Compressed tier needs Pillow+numpy and an AVIF-capable Pillow (this was built on Pillow 12.1; `doctor` tells you).
* PNG exact path runs only in pure Python (~4 KB/s of pixels) — large PNG screenshots in tier original are slow.
* Progressive/arithmetic JPEG and zopfli PNG fall back to generic (~5 %).
* SSIM is a proxy; look at results for your content. Lossless recompression of an already-compressed file
  (zip etc.) gains nothing — tested.
