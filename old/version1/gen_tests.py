import random, io, math, os
from PIL import Image, ImageDraw
random.seed(7)
os.makedirs('t', exist_ok=True)
W=H=56
# photo-like: smooth gradients + texture + noise
im=Image.new('RGB',(W,H))
px=im.load()
for y in range(H):
    for x in range(W):
        r=int(128+100*math.sin(x/9.0)*math.cos(y/13.0))+random.randint(-3,3)
        g=int(110+90*math.sin((x+y)/11.0))+random.randint(-3,3)
        b=int(90+x*1.5)+random.randint(-3,3)
        px[x,y]=tuple(max(0,min(255,v)) for v in (r,g,b))
im.save('t/photo.png')
# flat graphic w/ text, shapes
im=Image.new('RGB',(W,H),(255,255,255)); d=ImageDraw.Draw(im)
d.rectangle([4,4,30,30],fill=(20,80,200)); d.ellipse([20,20,50,50],fill=(220,40,40)); d.text((6,36),"CMX",fill=(0,0,0))
im.save('t/graphic.png')
# RGBA ui with alpha
im=Image.new('RGBA',(W,H),(0,0,0,0)); d=ImageDraw.Draw(im)
d.rounded_rectangle([6,6,50,50],8,fill=(30,160,90,255)); d.ellipse([16,16,40,40],fill=(255,255,255,180))
im.save('t/ui_rgba.png')
# pure noise (incompressible)
im=Image.frombytes('RGB',(W,H),bytes(random.getrandbits(8) for _ in range(W*H*3))); im.save('t/noise.png')
# optimized PNG (different deflate settings) and grayscale
Image.open('t/photo.png').convert('L').save('t/gray.png')
Image.open('t/photo.png').save('t/photo_opt.png',optimize=True)
# JPEG + random blob (non-PNG files)
Image.open('t/photo.png').save('t/photo.jpg',quality=85)
open('t/random.bin','wb').write(bytes(random.getrandbits(8) for _ in range(3000)))
