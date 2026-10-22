"""Conformance check: every vectors/*.cmx must decode to the exact original (use this to validate a native port)."""
import sys, glob, os, hashlib, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cmx
man = json.load(open('vectors/manifest.json')); bad = 0
for f in sorted(glob.glob('vectors/*.cmx')):
    name = os.path.basename(f).split('.p')[0] if '.p0.' in f or '.p1.' in f else os.path.basename(f)
    name = os.path.basename(f).rsplit('.p', 1)[0]
    out = cmx.from_file(open(f, 'rb').read())
    ok = hashlib.sha256(out).hexdigest() == man[name]['sha256']; bad += (not ok)
    print(('PASS ' if ok else 'FAIL '), f)
sys.exit(1 if bad else 0)
