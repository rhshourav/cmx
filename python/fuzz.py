import io, random, sys, time
sys.path.insert(0,'/home/claude')
from PIL import Image
import skimage.data as sd
import cmx
random.seed(11)
src=Image.fromarray(sd.astronaut())
cases=[]; t0=time.time()
def mk(w,h,mode,**kw):
    im=src.crop((random.randint(0,300),random.randint(0,300),0,0)) if False else src
    x=random.randint(0,512-w); y=random.randint(0,512-h)
    im=src.crop((x,y,x+w,y+h)).convert(mode)
    b=io.BytesIO(); im.save(b,'JPEG',**kw); return b.getvalue()
specs=[]
for _ in range(36):
    w=random.choice([1,2,7,8,9,15,16,17,31,33,50,63,64,65,100]); h=random.choice([1,3,8,9,16,23,32,47,64,77])
    mode=random.choice(['RGB','RGB','L'])
    kw=dict(quality=random.choice([1,5,20,50,75,90,95,100]))
    if mode=='RGB': kw['subsampling']=random.choice([0,1,2,-1])
    if random.random()<.3: kw['optimize']=True
    if random.random()<.25: kw['restart_marker_blocks']=random.choice([1,2,5])
    specs.append((w,h,mode,kw))
# flat + noise images
flat=io.BytesIO(); Image.new('RGB',(64,48),(200,30,30)).save(flat,'JPEG',quality=90)
noise=io.BytesIO(); Image.frombytes('RGB',(48,48),bytes(random.getrandbits(8) for _ in range(48*48*3))).save(noise,'JPEG',quality=95)
datas=[mk(*s[:3],**s[3]) for s in specs]+[flat.getvalue(),noise.getvalue()]
ok=0; modes={}; sv=[]
for d in datas:
    b=cmx.encode(d); modes[b[0]&15]=modes.get(b[0]&15,0)+1
    assert cmx.decode(b)==d; ok+=1; sv.append(len(b)/len(d))
print(f'{ok}/{len(datas)} JPEGs round-trip byte-exact; modes used: {modes}; mean size ratio {sum(sv)/len(sv):.3f}; {time.time()-t0:.0f}s')
# corruption: flip one random byte / truncate; decoder must raise, never return wrong bytes
d=datas[5]; blob=cmx.to_file(d); bad_silent=0; raised=0; N=300
for i in range(N):
    m=bytearray(blob)
    if i%3==0: m=m[:random.randint(5,len(m)-1)]
    else: m[random.randint(4,len(m)-1)]^=1<<random.randint(0,7)
    try:
        out=cmx.from_file(bytes(m))
        if out!=d: bad_silent+=1
    except Exception: raised+=1
print(f'corruption test: {N} corrupted files -> {raised} rejected with error, {bad_silent} silently returned WRONG data')
