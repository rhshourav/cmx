import time, glob, os, lzma, zlib, json
import cmx
print(f"{'file':14}{'orig':>7}{'xz':>7}{'cmx':>7}{'ratio':>7} {'str(b85)':>9} {'mode':>5} {'enc s':>6} {'dec s':>6}  ok")
for f in sorted(glob.glob('t/*'))+sorted(glob.glob('real/*')):
    d=open(f,'rb').read()
    t=time.time(); blob=cmx.encode(d,verbose=True); te=time.time()-t
    t=time.time(); back=cmx.decode(blob); td=time.time()-t
    s=cmx.compress_to_json(d); ok = back==d and cmx.decompress_from_json(s)==d
    print(f"{os.path.basename(f):14}{len(d):7}{len(lzma.compress(d)):7}{len(blob):7}{len(blob)/len(d):7.2f} {len(s):9} {blob[0]:5} {te:6.1f} {td:6.1f}  {ok}")
