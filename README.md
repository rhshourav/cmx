# CMX — byte-exact image codec + `.cmx` file format (prototype 0.2)

Lossless: the decoder returns the **identical bytes** you put in. Integer-only math, so every
platform computes the same predictions. Every encode is verified by decoding before it is accepted.

## Use
    python3 cmx.py pack photo.jpg photo.cmx [profile]   # profile 1 = smallest (default), 0 = light
    python3 cmx.py unpack photo.cmx photo.jpg
    npm i && node cmx.mjs unpack photo.cmx out.jpg      # JS decoder (JS encoder: generic modes only)
    python3 verify_vectors.py && node verify_vectors.mjs  # conformance vectors for any new port
    python3 fuzz.py                                       # edge-case + corruption tests (needs scikit-image, Pillow)

## Format
    file   = "CMX" 0x01 | blob                 (relay/transport may drop the 4-byte magic)
    blob   = mode|profile<<4 (1 byte) | SHA-256(original)[0:4] | varint(len) | payload
    mode 0 stored   payload = original bytes
    mode 1 generic  payload = context-mixing stream (any file)
    mode 2 png      payload = deflate params(3) | meta | filter types | pixel stream   (PNG rebuilt bit-exactly)
    mode 3 jpeg     payload = varint hdrLen | varint hdrCmLen | hdr(CM) | varint tailLen | tail | coefficient stream
    text form       {"cmx":1,"d":"<base85, JSON-safe alphabet, blob without magic>"}
    unknown mode / bad checksum / truncation  ->  decoder raises; it never returns wrong data.

## JPEG algorithm (mode 3)
1. Parse headers; Huffman-decode all MCUs into quantized DCT coefficients (baseline, 8-bit, 1 or 3 components,
   any sampling, restart intervals). Rebuild the scan and require it to equal the original, else fall back.
2. Per block: code #nonzero ACs, then ACs in zigzag order (zero flag, magnitude, sign) with contexts from the
   same coefficient in the above/left blocks, in-block neighbours and remaining count.
3. DC: dequantize the block's ACs, run an exact fixed-point IDCT for its top rows / left columns, compare with the
   neighbours' bottom rows / right columns (value + slope), and predict the DC that makes the edge continuous.
   Only the residual is coded, with the disagreement of the two predictions as context.
4. Binary decisions are mixed (2 mixer sets + APM) and arithmetic-coded. Decoder rebuilds the exact Huffman bits.

## Known limits
* Progressive / arithmetic-coded / 12-bit JPEG and zopfli-style PNGs fall back to generic (≈5%).
* Speed: Python ≈ 25 kpx/s, Node ≈ 0.2 MP/s. Fine for chat-sized images, too slow for 12 MP originals.
  Production plan: one C/Rust core (Android NDK, WASM, Python) validated against `vectors/`.
* PNG re-deflate relies on the zlib deflate algorithm: JS must use `pako`, not Node's built-in zlib.
