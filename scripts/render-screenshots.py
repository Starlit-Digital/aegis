#!/usr/bin/env python3
"""Render captured output in the studio's established macOS terminal frame."""
import html, pathlib, subprocess
from PIL import Image, ImageDraw, ImageFont, ImageFilter
root=pathlib.Path(__file__).resolve().parents[1];out=root/'docs/screenshots';out.mkdir(parents=True,exist_ok=True)
font='/System/Library/Fonts/Menlo.ttc';ui='/System/Library/Fonts/Helvetica.ttc'
cases=[('aegis-selftest','Aegis · Local selftest',[('./build/aegis version',['./build/aegis','version']),('./build/aegis selftest',['./build/aegis','selftest'])]),('aegis-php-smoke','Aegis · PHP interoperability',[('python3 scripts/smoke.py',['python3','scripts/smoke.py'])])]
cases.append(('aegis-proxy-smoke','Aegis · Structural proxy and PHP FPM',[('python3 scripts/proxy-smoke.py',['python3','scripts/proxy-smoke.py'])]))
for slug,title,commands in cases:
    lines=[]
    for label,args in commands:
        result=subprocess.run(args,cwd=root,capture_output=True,text=True,check=True)
        if result.stderr:raise RuntimeError(result.stderr)
        lines.append(('> '+label,'#f2e7d4'));lines.extend((line,'#e8c58e' if line.startswith('Aegis 0.') else '#bacbd1') for line in result.stdout.splitlines());lines.append(('', '#bacbd1'))
    transcript='\n'.join(line for line,_ in lines).rstrip()+'\n';(out/(slug+'.txt')).write_text(transcript)
    scale=2;im=Image.new('RGB',(1280*scale,720*scale));px=im.load()
    for y in range(im.height):
        for x in range(im.width):
            f=(x/im.width+y/im.height)/2;px[x,y]=(int(25*(1-f)+8*f),int(53*(1-f)+18*f),int(61*(1-f)+25*f))
    draw=ImageDraw.Draw(im);box=(60*scale,40*scale,1220*scale,680*scale)
    draw.rounded_rectangle(box,radius=16*scale,fill='#0e1b22',outline='#526268',width=scale)
    draw.rounded_rectangle((60*scale,40*scale,1220*scale,95*scale),radius=16*scale,fill='#1b2c35');draw.rectangle((61*scale,68*scale,1219*scale,94*scale),fill='#1b2c35');draw.line((61*scale,94*scale,1219*scale,94*scale),fill='#3b5260',width=scale)
    for x,color in [(87,'#ff5f57'),(109,'#ffbd2e'),(131,'#28c840')]:draw.ellipse(((x-6)*scale,61*scale,(x+6)*scale,73*scale),fill=color)
    titlefont=ImageFont.truetype(ui,16*scale);draw.text((640*scale,67*scale),title,font=titlefont,fill='#bacbd1',anchor='mm')
    textsize=min(19, int(1100 / max(1,max(len(line) for line,_ in lines)) / .61));textfont=ImageFont.truetype(font,textsize*scale);y=123
    for line,color in lines:
        if line.startswith('> '):draw.text((90*scale,y*scale),'❯',font=textfont,fill='#79b7b5');line=line[2:];x=115
        else:x=90
        draw.text((x*scale,y*scale),line,font=textfont,fill=color);y+=30 if line else 14
    draw.text((90*scale,625*scale),'STARLIT DIGITAL · ACTUAL LOCAL COMMAND OUTPUT · SERVICE STOPPED AFTER TEST',font=ImageFont.truetype(ui,11*scale),fill='#bacbd1')
    im.resize((1280,720),Image.Resampling.LANCZOS).save(out/(slug+'.png'));im.resize((1280,720),Image.Resampling.LANCZOS).save(out/(slug+'.jpg'),quality=94)
    # Editable vector source preserves text and established palette.
    elements=['<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720">','<rect width="1280" height="720" fill="#102330"/>','<rect x="60" y="40" width="1160" height="640" rx="16" fill="#0e1b22" stroke="#526268"/>','<path d="M76 40H1204Q1220 40 1220 56V95H60V56Q60 40 76 40" fill="#1b2c35"/>']
    for x,col in [(87,'#ff5f57'),(109,'#ffbd2e'),(131,'#28c840')]:elements.append(f'<circle cx="{x}" cy="67" r="6" fill="{col}"/>')
    elements.append(f'<text x="640" y="73" text-anchor="middle" font-family="Helvetica,sans-serif" font-size="16" fill="#bacbd1">{html.escape(title)}</text>');y=142
    for line,color in lines:elements.append(f'<text x="90" y="{y}" font-family="Menlo,monospace" font-size="{textsize}" fill="{color}">{html.escape(line)}</text>');y+=30 if line else 14
    elements.append('</svg>');(out/(slug+'.svg')).write_text('\n'.join(elements)+'\n')
    print(f'Rendered {slug}.png from captured output')
