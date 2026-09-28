#!/usr/bin/env python3
"""Render assets/preview.png — the WebRecon social preview / README banner.

    pip install Pillow
    python assets/gen_preview.py

Outputs a 1280x640 PNG, the size GitHub recommends for a repository social
preview (Settings -> General -> Social preview). The version badge is read
from webrecon.sh so it cannot drift from the real VERSION.

Layout constants below are tuned for Consolas + Segoe UI (Windows). The
DejaVu/Liberation fallbacks used on Linux are slightly wider, so the chip
row and terminal lines sit a little tighter there; nudge M or the font
sizes if anything crowds.
"""
import os
import re
import sys

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "preview.png")

W, H = 1280, 640
M = 64  # page margin

FONT_DIRS = [
    "C:/Windows/Fonts",
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/truetype/liberation",
    "/usr/share/fonts/TTF",
    "/Library/Fonts",
    "/System/Library/Fonts",
]
# preferred first; each entry is a family fallback chain
MONO = ["consola.ttf", "DejaVuSansMono.ttf", "LiberationMono-Regular.ttf"]
MONO_B = ["consolab.ttf", "DejaVuSansMono-Bold.ttf", "LiberationMono-Bold.ttf"]
SANS = ["segoeui.ttf", "DejaVuSans.ttf", "LiberationSans-Regular.ttf"]
SANS_B = ["segoeuib.ttf", "DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf"]


def font(chain, size):
    for name in chain:
        for directory in FONT_DIRS:
            path = os.path.join(directory, name)
            if os.path.exists(path):
                return ImageFont.truetype(path, size)
    sys.exit("No usable font found for %s. Install fonts-dejavu." % chain[0])


def version():
    """Read VERSION="x.y.z" out of webrecon.sh."""
    try:
        with open(os.path.join(ROOT, "webrecon.sh"), encoding="utf-8") as fh:
            m = re.search(r'^VERSION="([^"]+)"', fh.read(), re.M)
        if m:
            return "v" + m.group(1)
    except OSError:
        pass
    return ""


mono_b = font(MONO_B, 68)
mono = font(MONO, 22)
mono_b2 = font(MONO_B, 22)
sans = font(SANS, 26)
sans_s = font(SANS, 17)
sans_sb = font(SANS_B, 17)

BG_TOP, BG_BOT = (14, 18, 26), (8, 10, 15)
CARD, BORDER = (1, 4, 9), (44, 50, 58)
CHIP = (21, 26, 34)
WHITE, MUTED, DIM = (233, 238, 245), (139, 148, 158), (105, 113, 124)
GREEN, CYAN, YELLOW = (63, 185, 80), (88, 166, 255), (214, 178, 96)

img = Image.new("RGB", (W, H), BG_TOP)
d = ImageDraw.Draw(img)

# vertical gradient
for y in range(H):
    t = y / (H - 1)
    d.line([(0, y), (W, y)],
           fill=tuple(int(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(3)))

# soft cyan glow, top-left, added as light rather than blended over
glow = Image.new("RGB", (W, H), (0, 0, 0))
gd = ImageDraw.Draw(glow)
for r in range(460, 0, -10):
    a = 1 - r / 460
    gd.ellipse([-320, -300, 300 + r, 250 + r],
               fill=(int(5 * a), int(11 * a), int(20 * a)))
img = ImageChops.add(img, glow.filter(ImageFilter.GaussianBlur(90)))
d = ImageDraw.Draw(img)


def segs(x, y, parts):
    """Draw a run of (text, font, colour) segments on one baseline."""
    for text, fnt, col in parts:
        d.text((x, y), text, font=fnt, fill=col)
        x += d.textlength(text, font=fnt)
    return x


# wordmark + accent rule
d.text((M, 40), "WebRecon", font=mono_b, fill=WHITE)
wm_w = d.textlength("WebRecon", font=mono_b)
d.rounded_rectangle([M, 128, M + wm_w, 133], radius=3, fill=CYAN)

# version pill, top-right
vtxt = version()
if vtxt:
    vw = d.textlength(vtxt, font=sans_sb)
    d.rounded_rectangle([W - M - vw - 30, 54, W - M, 90], radius=18,
                        fill=CHIP, outline=BORDER, width=1)
    d.text((W - M - vw - 15, 63), vtxt, font=sans_sb, fill=CYAN)

d.text((M, 150),
       "Fast web-interface discovery & fingerprinting for pentesting & CTFs",
       font=sans, fill=MUTED)

# terminal card
CX0, CY0, CX1, CY1 = M, 198, W - M, 534
d.rounded_rectangle([CX0, CY0, CX1, CY1], radius=12, fill=CARD,
                    outline=BORDER, width=1)
d.line([(CX0 + 1, CY0 + 38), (CX1 - 1, CY0 + 38)], fill=(28, 33, 40))
for i, c in enumerate([(237, 106, 94), (222, 184, 92), (105, 195, 110)]):
    cx = CX0 + 26 + i * 20
    d.ellipse([cx - 6, CY0 + 13, cx + 6, CY0 + 25], fill=c)
d.text((CX0 + 110, CY0 + 10), "WebRecon \u2014 triage", font=sans_s, fill=DIM)

K, V = MUTED, WHITE
lines = [
    [("$ ", mono_b2, GREEN), ("./webrecon.sh ", mono, WHITE),
     ("-t ", mono, CYAN), ("10.129.56.249 ", mono, WHITE),
     ("-p ", mono, CYAN), ("80,443,6600", mono, WHITE)],
    [],
    [("[+] ", mono_b2, GREEN), ("WEB SERVICE  ", mono_b2, WHITE),
     ("https://10.129.56.249:6600", mono, CYAN)],
    [("      Status        : ", mono, K), ("200", mono, GREEN)],
    [("      Server        : ", mono, K), ("Microsoft-HTTPAPI/2.0", mono, V)],
    [("      Page title    : ", mono, K), ("Windows Admin Center", mono, V)],
    [("      Tech guess    : ", mono, K), ("Windows-Admin-Center", mono, YELLOW)],
    [("      Cert SANs     : ", mono, K),
     ("dc.danglingtree.htb, danglingtree.htb", mono, V)],
    [("[-] ", mono_b2, DIM),
     ("Port 80 : no web interface (HTTP/HTTPS)", mono, DIM)],
]
y = CY0 + 54
for parts in lines:
    if parts:
        segs(CX0 + 26, y, parts)
    y += 29

# feature chips + repo url
chips = ["HTTP + HTTPS probing", "TLS cert & SAN inspection",
         "nmap -oG / -oN parsing", "JSON export"]
x = M
for c in chips:
    w = d.textlength(c, font=sans_s)
    d.rounded_rectangle([x, 556, x + w + 30, 594], radius=19,
                        fill=CHIP, outline=BORDER, width=1)
    d.text((x + 15, 566), c, font=sans_s, fill=MUTED)
    x += w + 41

url = "github.com/CyberAlp0/WebRecon"
d.text((W - M - d.textlength(url, font=sans_s), 566), url, font=sans_s, fill=DIM)

img.save(OUT, "PNG", optimize=True)
print("saved %s %dx%d" % (OUT, img.size[0], img.size[1]))
