"""Generate windows/ConnectUnit.ico from hex-mesh geometry (matches windows/icon.svg)."""

from __future__ import annotations

import math
import struct
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
OUT_ICO = ROOT / "windows" / "ConnectUnit.ico"

R = 118.0
CX = CY = 200.0
BG = (13, 13, 13)

RING_EDGES = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 0)]
DIAGONALS = [(0, 2), (1, 3), (2, 4), (3, 5), (4, 0), (5, 1)]


def nodes() -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    for i in range(6):
        angle = math.radians(i * 60 - 90)
        out.append((CX + R * math.cos(angle), CY + R * math.sin(angle)))
    return out


def _draw_mesh(draw: ImageDraw.ImageDraw, size: int, *, diagonals: bool) -> None:
    scale = size / 400.0
    pts = nodes()

    def xy(i: int) -> tuple[float, float]:
        return (pts[i][0] * scale, pts[i][1] * scale)

    if diagonals:
        w = max(1, int(round(6 * scale)))
        for a, b in DIAGONALS:
            draw.line([*xy(a), *xy(b)], fill=(255, 255, 255, 71), width=w)

    w_ring = max(1, int(round(9 * scale)))
    for a, b in RING_EDGES:
        draw.line([*xy(a), *xy(b)], fill="white", width=w_ring)

    r_node = max(1, int(round(14 * scale)))
    for i in range(6):
        x, y = xy(i)
        draw.ellipse(
            [x - r_node, y - r_node, x + r_node, y + r_node],
            fill="white",
        )


def render(size: int, *, diagonals: bool) -> Image.Image:
    # Supersample before downscale — balance sharpness vs memory (4096 @ ss=3 ≈ 12k canvas).
    if size >= 2048:
        ss = 3
    elif size >= 512:
        ss = 4
    elif size >= 256:
        ss = 8
    else:
        ss = 6
    canvas = size * ss
    cx = cy = (canvas - 1) / 2.0
    # Slightly overscan so Windows does not paint a dark squircle matte in the corners.
    bleed = max(1.0, ss * 1.25)
    r_disk = canvas / 2.0 + bleed

    layer = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    draw.ellipse([cx - r_disk, cy - r_disk, cx + r_disk, cy + r_disk], fill=(*BG, 255))
    _draw_mesh(draw, canvas, diagonals=diagonals)

    mask = Image.new("L", (canvas, canvas), 0)
    md = ImageDraw.Draw(mask)
    r_mask = canvas / 2.0 + bleed * 0.5
    md.ellipse([cx - r_mask, cy - r_mask, cx + r_mask, cy + r_mask], fill=255)
    blur_r = min(0.45 * ss, 1.75)
    mask = mask.filter(ImageFilter.GaussianBlur(radius=blur_r))

    out = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    out.paste(layer, (0, 0), mask=mask)
    img = out.resize((size, size), Image.Resampling.LANCZOS)

    cx_f = cy_f = (size - 1) / 2.0
    r_out = size / 2.0
    feather = max(2.5, size / 1024.0)
    px = img.load()
    margin = int(math.ceil(r_out + feather)) + 1
    x0 = max(0, int(cx_f) - margin)
    x1 = min(size, int(cx_f) + margin + 1)
    y0 = max(0, int(cy_f) - margin)
    y1 = min(size, int(cy_f) + margin + 1)
    for y in range(y0, y1):
        for x in range(x0, x1):
            d = math.hypot(x - cx_f, y - cy_f)
            if d <= r_out:
                continue
            if d <= r_out + feather:
                t = (d - r_out) / feather
                r, g, b, a = px[x, y]
                if a > 0:
                    fade = int(a * (1.0 - t))
                    px[x, y] = (r, g, b, fade)
            else:
                px[x, y] = (0, 0, 0, 0)

    return img.convert("RGBA")


# High-res only: Windows downscales from the nearest embedded PNG.
ICO_SIZES = (4096, 1024, 512)


def _ico_dir_dim(px: int) -> int:
    """ICONDIRENTRY bWidth/bHeight: 0 encodes 256; larger PNGs use 0 as well (Vista+)."""
    return 0 if px >= 256 else px


def save_ico(path: Path) -> None:
    frames = [render(s, diagonals=True) for s in ICO_SIZES]
    pngs: list[bytes] = []
    for frame in frames:
        buf = BytesIO()
        frame.save(buf, format="PNG", optimize=True)
        pngs.append(buf.getvalue())

    # Smallest first — matches common ICO layout and Pillow's reader.
    order = sorted(range(len(frames)), key=lambda i: ICO_SIZES[i])
    count = len(frames)
    header = b"\x00\x00\x01\x00" + struct.pack("<H", count)
    offset = 6 + 16 * count
    entries = bytearray()
    blobs = bytearray()
    for idx in order:
        w, h = frames[idx].size
        png = pngs[idx]
        entries.extend(
            struct.pack(
                "<BBBBHHII",
                _ico_dir_dim(w),
                _ico_dir_dim(h),
                0,
                0,
                1,
                32,
                len(png),
                offset,
            )
        )
        blobs.extend(png)
        offset += len(png)

    path.write_bytes(header + bytes(entries) + bytes(blobs))


def main() -> None:
    OUT_ICO.parent.mkdir(parents=True, exist_ok=True)
    save_ico(OUT_ICO)
    data = OUT_ICO.read_bytes()
    if len(data) < 1024:
        raise SystemExit(f"ICO too small ({len(data)} bytes), likely corrupt")
    print(f"Wrote {OUT_ICO} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
