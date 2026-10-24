import io, os, sys, random, subprocess
sys.path.insert(0,'/home/claude')
import numpy as np
from PIL import Image, ImageOps
import skimage.data as sd
import cmx, cmx_lossy
R=lambda p: open(p,'rb').read()
def run(data, **kw):
    blob,rep=cmx_lossy.smart_pack(data, **kw); return blob,rep
def line(name,data,blob,rep):
    tag='LOSSY '+rep['codec']+('+cmx' if rep.get('stacked') else '') if rep['lossy'] else 'EXACT'
    print(f"{name:34}{len(data):>9,} -> {len(blob)+4:>8,}  {100*(1-(len(blob)+4)/len(data)):>5.0f}%  {tag:<14}{'; '.join(rep['reasons'])[:70]}")
print(f"{'case':34}{'source':>9}    {'.cmx':>8}  {'saved':>5}  {'result':<14}why")
# 1 photo PNG, 2 screenshot, 3 tiny, 4 alpha sticker, 5 non-image
cases={}
cases['photo as PNG (256px)']=(R('x/s_photo.png'),{})
cases['screenshot PNG (graphic)']=(R('x/s_screenshot.png'),{})
cases['tiny JPEG 120x90']=(R('x/s_tiny.jpg'),{})
st=Image.new('RGBA',(300,300),(0,0,0,0)); 
a=np.asarray(Image.fromarray(sd.astronaut()).resize((300,300))); st=Image.fromarray(np.dstack([a,np.where(np.add.outer(np.arange(300),np.arange(300))%7<5,255,0).astype(np.uint8)]),'RGBA'); b=io.BytesIO(); st.save(b,'PNG'); cases['photo with transparency']=(b.getvalue(),{'tier':'compressed'})
cases['random bytes']=(bytes(random.Random(1).getrandbits(8) for _ in range(5000)),{})
for n,(d,kw) in cases.items():
    blob,rep=run(d,**kw); line(n,d,blob,rep); assert cmx.decode(blob) is not None
    if not rep['lossy']: assert cmx.decode(blob)==d, 'exact tier must be byte-exact'
# forced-JPEG-only => exercises kind 1 (lossy JPEG + lossless .cmx model)
real=cmx_lossy.capabilities
cmx_lossy.capabilities=lambda: {**real(),'webp':False,'avif':False}
d=R('x/s_coffee_rot.jpg'); blob,rep=run(d,tier='compressed'); line('JPEG-only (kind 1 stacking)',d,blob,rep)
assert rep['codec']=='jpeg' and rep['stacked'], rep
open('x/kind1.cmx','wb').write(cmx.CMX_MAGIC+blob); k1=cmx.decode(blob); open('x/kind1.ref','wb').write(k1)
cmx_lossy.capabilities=real
# budgets
d=R('x/s_coffee_rot.jpg')
for kb in (40,12,5):
    blob,rep=run(d,tier='compressed',target_kb=kb); line(f'budget {kb} KB',d,blob,rep)
    print(f"{'':34}scale {rep['scale']:.2f} -> {rep['dims']}, ssim {rep['ssim']}, within budget: {len(blob)<=kb*1024}")
# EXIF rotation correctness: lossy output must show the photo upright (same dims & high similarity to transposed original)
d=R('x/s_coffee_rot.jpg'); blob,rep=run(d,tier='compressed'); out=Image.open(io.BytesIO(cmx.decode(blob))).convert('RGB')
ref=ImageOps.exif_transpose(Image.open(io.BytesIO(d))).convert('RGB').resize(out.size)
print('\nEXIF rotation: original stored', Image.open(io.BytesIO(d)).size, 'orientation 6 -> displays', ImageOps.exif_transpose(Image.open(io.BytesIO(d))).size, '| compressed output', out.size,
      '| similarity to correctly rotated original: %.3f' % cmx_lossy.ssim_luma(np, np.asarray(ref), np.asarray(out)), '| metadata stripped:', 'exif' not in Image.open(io.BytesIO(cmx.decode(blob))).info)
# corruption on mode 4
blob,rep=run(R('x/s_astro.jpg'),tier='compressed'); bad=0; rej=0
for i in range(200):
    m=bytearray(cmx.CMX_MAGIC+blob)
    if i%3==0: m=m[:random.randint(5,len(m)-1)]
    else: m[random.randint(4,len(m)-1)]^=1<<random.randint(0,7)
    try:
        if cmx.from_file(bytes(m))!=cmx.decode(blob): bad+=1
    except Exception: rej+=1
print(f'corruption: 200 damaged lossy files -> {rej} rejected, {bad} silently wrong')
