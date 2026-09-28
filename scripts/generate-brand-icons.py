"""Render the repository's geometric vector mark as browser PNG/ICO assets."""
from pathlib import Path
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parents[1]
svg = (root/'docs/brand/rime.svg').read_bytes()
for name in ('hy2bridge/web/rime.svg', 'hy2bridge/web/icons/rime.svg',
             'hy2bridge/web/icons/safari-pinned-tab.svg'):
    (root/name).write_bytes(svg)
image=Image.new('RGB',(512,512),'#111923')
draw=ImageDraw.Draw(image)
def polygon(points,color):
    draw.polygon([(x*8,y*8) for x,y in points],fill=color)
polygon([(17,48),(17,16),(34,16),(46,28),(34,40),(25,40),(25,48)],'#7dd3fc')
polygon([(25,24),(25,32),(31,32),(35,28),(31,24)],'#111923')
polygon([(33,38),(47,48),(34,48),(27,40)],'#e0f2fe')
folder=root/'hy2bridge/web/icons'
for name,size in [('favicon-16x16.png',16),('favicon-32x32.png',32),
                  ('apple-touch-icon.png',180),('android-chrome-192x192.png',192),
                  ('android-chrome-512x512.png',512),('mstile-150x150.png',150)]:
    image.resize((size,size),Image.Resampling.LANCZOS).save(folder/name)
image.save(folder/'favicon.ico',sizes=[(16,16),(32,32),(48,48)])
