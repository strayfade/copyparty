# coding: utf-8
from __future__ import division, print_function, unicode_literals

import argparse  # typechk
import colorsys
import hashlib
import re

from .__init__ import PY2
from .th_srv import HAVE_PIL, HAVE_PILF
from .util import BytesIO, html_escape  # type: ignore


class Ico(object):
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args

    def get(self, ext: str, as_thumb: bool, chrome: bool) -> tuple[str, bytes]:
        """placeholder to make thumbnails not break"""

        bext = ext.encode("ascii", "replace")
        ext = bext.decode("utf-8")
        zb = hashlib.sha1(bext).digest()[2:4]
        if PY2:
            zb = [ord(x) for x in zb]  # type: ignore

        c1 = colorsys.hsv_to_rgb(zb[0] / 256.0, 1, 0.3)
        c2 = colorsys.hsv_to_rgb(zb[0] / 256.0, 0.8 if HAVE_PILF else 1, 1)
        ci = [int(x * 255) for x in list(c1) + list(c2)]
        c = "".join(["%02x" % (x,) for x in ci])

        w = 100
        h = 30
        if as_thumb:
            sw, sh = self.args.th_size.split("x")
            h = int(100.0 / (float(sw) / float(sh)))

        folder_pts = [
            (10, 4),
            (4, 4),
            (2, 6),
            (2, 18),
            (4, 20),
            (20, 20),
            (22, 18),
            (22, 8),
            (20, 6),
            (12, 6),
        ]

        def _draw_folder(pb, w, h):
            ibox = min(w, h) * 0.5
            s = ibox / 24.0
            ox = (w - ibox) / 2
            oy = (h - ibox) / 2
            poly = [(ox + px * s, oy + py * s) for px, py in folder_pts]
            pb.polygon(poly, fill="#ffffff")

        if chrome:
            # cannot handle more than ~2000 unique SVGs
            if HAVE_PILF:
                # pillow 10.1 made this the default font;
                # svg: 3.7s, this: 36s
                try:
                    from PIL import Image, ImageDraw

                    # [.lt] are hard to see lowercase / unspaced
                    ext2 = re.sub("(.)", "\\1 ", "." + ext).upper()

                    h = int(128.0 * h / w)
                    w = 128
                    if ext == "folder":
                        img = Image.new("RGB", (w, h), "#888888")
                        pb = ImageDraw.Draw(img)
                        _draw_folder(pb, w, h)
                    else:
                        img = Image.new("RGB", (w, h), "#" + c[:6])
                        pb = ImageDraw.Draw(img)
                        _, _, tw, th = pb.textbbox((0, 0), ext2, font_size=16)
                        xy = (int((w - tw) / 2), int((h - th) / 2))
                        pb.text(xy, ext2, fill="#" + c[6:], font_size=16)

                    img = img.resize((w * 2, h * 2), Image.NEAREST)

                    buf = BytesIO()
                    img.save(buf, format="PNG", compress_level=1)
                    return "image/png", buf.getvalue()

                except:
                    pass

            if HAVE_PIL:
                # svg: 3s, cache: 6s, this: 8s
                from PIL import Image, ImageDraw

                h = int(64.0 * h / w)
                w = 64
                if ext == "folder":
                    img = Image.new("RGB", (w, h), "#888888")
                    pb = ImageDraw.Draw(img)
                    _draw_folder(pb, w, h)
                else:
                    dext = "." + ext
                    img = Image.new("RGB", (w, h), "#" + c[:6])
                    pb = ImageDraw.Draw(img)
                    try:
                        _, _, tw, th = pb.textbbox((0, 0), dext)
                    except:
                        tw, th = pb.textsize(dext)  # type: ignore

                    tw += len(dext)
                    cw = tw // len(dext)
                    x = ((w - tw) // 2) - (cw * 2) // 3
                    fill = "#" + c[6:]
                    for ch in dext:
                        pb.text((x, (h - th) // 2), " %s " % (ch,), fill=fill)
                        x += cw

                img = img.resize((w * 3, h * 3), Image.NEAREST)

                buf = BytesIO()
                img.save(buf, format="PNG", compress_level=1)
                return "image/png", buf.getvalue()

        if ext == "folder":
            ibox = h * 0.5
            iscale = ibox / 24.0
            itx = 50 - ibox / 2
            ity = h / 2 - ibox / 2
            svg = """\
<?xml version="1.0" encoding="UTF-8"?>
<svg version="1.1" viewBox="0 0 100 {0}" xmlns="http://www.w3.org/2000/svg"><g>
<rect width="100%" height="100%" fill="#888888" />
<path transform="translate({1},{2}) scale({3})" fill="#ffffff" d="M10 4H4c-1.11 0-2 .89-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/>
</g></svg>
"""
            svg = svg.format(h, itx, ity, iscale)
            return "image/svg+xml", svg.encode("utf-8")

        svg = """\
<?xml version="1.0" encoding="UTF-8"?>
<svg version="1.1" viewBox="0 0 100 {}" xmlns="http://www.w3.org/2000/svg"><g>
<rect width="100%" height="100%" fill="#{}" />
<text x="50%" y="{}" dominant-baseline="middle" text-anchor="middle" xml:space="preserve"
  fill="#{}" font-family="Geist, sans-serif" font-weight="bold" font-size="14px" style="letter-spacing:.5px">{}</text>
</g></svg>
"""

        txt = html_escape("." + ext, True)
        if "\n" in txt:
            lines = txt.split("\n")
            n = len(lines)
            y = "20%" if n == 2 else "10%" if n == 3 else "0"
            zs = '<tspan x="50%%" dy="1.2em">%s</tspan>'
            txt = "".join([zs % (x,) for x in lines])
        else:
            y = "50%"

        svg = svg.format(h, c[:6], y, c[6:], txt)

        return "image/svg+xml", svg.encode("utf-8")
