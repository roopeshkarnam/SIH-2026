"""Test pages and synthetic attacks for the watermark robustness tests and matrix.

Attacks use OpenCV (independent of the numpy code under test). Every attack takes and returns
a grey uint8 image and a numpy Generator, so trials are reproducible.
"""

from __future__ import annotations

import cv2
import numpy as np
import pymupdf

RENDER_DPI = 150

PARAGRAPH = (
    "The committee reviewed the proposal for secure distribution of confidential circulars across "
    "departments. Each recipient receives an individually sealed copy, and every opening is recorded "
    "with a signed provenance entry. Officers must verify the integrity of the document before acting "
    "on its contents, and any discrepancy should be reported to the security cell within twenty four "
    "hours of receipt. Copies must not be forwarded, printed or photographed without written approval. "
)


def _render(page: pymupdf.Page) -> np.ndarray:
    pix = page.get_pixmap(dpi=RENDER_DPI)
    return np.frombuffer(pix.samples, np.uint8).reshape(pix.h, pix.w, 3).copy()


def page_pdf(kind: str) -> bytes:
    """A one-page PDF of a given layout: dense, memo, table or figure."""
    doc = pymupdf.open()
    page = doc.new_page()
    if kind == "dense":
        page.insert_text((60, 56), "CONFIDENTIAL CIRCULAR 17/2026", fontsize=15, fontname="hebo")
        page.insert_textbox(pymupdf.Rect(60, 72, 540, 790), PARAGRAPH * 9, fontsize=10.5,
                            align=pymupdf.TEXT_ALIGN_JUSTIFY)
    elif kind == "memo":
        page.insert_text((60, 70), "Office Memorandum", fontsize=18, fontname="hebo")
        page.insert_text((60, 100), "Ref: SEC/2026/041        Date: 29 September 2026", fontsize=10)
        page.insert_textbox(pymupdf.Rect(60, 130, 540, 400), PARAGRAPH * 2, fontsize=11)
        page.insert_text((380, 500), "Joint Secretary (Security)", fontsize=11)
    elif kind == "table":
        page.insert_text((60, 60), "Quarterly allocation (in lakh)", fontsize=14, fontname="hebo")
        rng = np.random.default_rng(7)
        for row in range(24):
            y = 90 + row * 26
            page.draw_line((60, y), (540, y), color=(0.5, 0.5, 0.5), width=0.6)
            for col in range(5):
                text = "Department %d" % (row + 1) if col == 0 else f"{rng.uniform(10, 999):,.2f}"
                page.insert_text((66 + col * 96, y + 17), text, fontsize=9.5)
        for col in range(6):
            page.draw_line((60 + col * 96, 90), (60 + col * 96, 90 + 23 * 26), color=(0.5, 0.5, 0.5), width=0.6)
    elif kind == "figure":
        page.insert_text((60, 56), "Site survey: Annexure B", fontsize=15, fontname="hebo")
        rng = np.random.default_rng(3)
        smooth = cv2.GaussianBlur(rng.normal(0, 1, (300, 480, 3)), (0, 0), 18)
        smooth = (smooth - smooth.min()) / (smooth.max() - smooth.min())
        photo = (np.stack([smooth[..., 0] * 90 + 60, smooth[..., 1] * 120 + 80, smooth[..., 2] * 70 + 50], axis=2)
                 + rng.normal(0, 6, (300, 480, 3)))
        ok, png = cv2.imencode(".png", np.clip(photo, 0, 255).astype(np.uint8))
        page.insert_image(pymupdf.Rect(60, 72, 540, 372), stream=png.tobytes())
        page.insert_textbox(pymupdf.Rect(60, 390, 540, 790), PARAGRAPH * 4, fontsize=10.5)
    else:
        raise ValueError(kind)
    return doc.tobytes()


PAGE_KINDS = ("dense", "memo", "table", "figure")


def page_rgb(kind: str) -> np.ndarray:
    return _render(pymupdf.open(stream=page_pdf(kind), filetype="pdf")[0])


def to_gray(rgb: np.ndarray) -> np.ndarray:
    return cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)


# ---------------------------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------------------------

def jpeg(img, quality):
    ok, data = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, quality])
    return cv2.imdecode(data, cv2.IMREAD_GRAYSCALE)


def scale(img, factor):
    interpolation = cv2.INTER_AREA if factor < 1 else cv2.INTER_CUBIC
    return cv2.resize(img, None, fx=factor, fy=factor, interpolation=interpolation)


def rotate(img, degrees, background=235):
    h, w = img.shape
    matrix = cv2.getRotationMatrix2D((w / 2, h / 2), degrees, 1.0)
    cos, sin = abs(matrix[0, 0]), abs(matrix[0, 1])
    nw, nh = int(h * sin + w * cos), int(h * cos + w * sin)
    matrix[0, 2] += nw / 2 - w / 2
    matrix[1, 2] += nh / 2 - h / 2
    return cv2.warpAffine(img, matrix, (nw, nh), flags=cv2.INTER_LINEAR, borderValue=background)


def perspective(img, rng, strength, background=120, canvas=1.25):
    """Place the page on a larger background and warp it as if photographed at an angle."""
    h, w = img.shape
    ch, cw = int(h * canvas), int(w * canvas)
    src = np.float32([[0, 0], [w, 0], [w, h], [0, h]])
    offset = np.float32([(cw - w) / 2, (ch - h) / 2])
    dst = src + offset + rng.uniform(-strength, strength, (4, 2)).astype(np.float32) * np.float32([w, h])
    matrix = cv2.getPerspectiveTransform(src, dst)
    return cv2.warpPerspective(img, matrix, (cw, ch), flags=cv2.INTER_LINEAR, borderValue=background)


def blur(img, sigma):
    return cv2.GaussianBlur(img, (0, 0), sigma)


def noise(img, rng, sigma):
    return np.clip(img + rng.normal(0, sigma, img.shape), 0, 255).astype(np.uint8)


def tone(img, gamma=1.0, contrast=1.0, brightness=0.0):
    x = (img / 255.0) ** gamma
    x = (x - 0.5) * contrast + 0.5 + brightness / 255.0
    return np.clip(x * 255, 0, 255).astype(np.uint8)


def crop(img, rng, fraction):
    """Keep a random rectangle with `fraction` of the area (same aspect ratio)."""
    h, w = img.shape
    ch, cw = int(h * fraction ** 0.5), int(w * fraction ** 0.5)
    y, x = rng.integers(0, h - ch + 1), rng.integers(0, w - cw + 1)
    return img[y:y + ch, x:x + cw]


def phone_photo(img, rng):
    """Hand-held photo of the screen/page: tilt, perspective, lens blur, sensor noise, JPEG."""
    x = perspective(img, rng, 0.04)
    x = rotate(x, rng.uniform(-3, 3), background=120)
    x = scale(x, rng.uniform(1.2, 1.6))
    x = blur(x, 1.2)
    x = tone(x, gamma=rng.uniform(0.8, 1.2), contrast=0.85, brightness=rng.uniform(-15, 5))
    x = noise(x, rng, 3)
    return jpeg(x, 80)


def print_scan(img, rng):
    x = rotate(img, rng.uniform(-1, 1))
    x = blur(x, 1.0)
    x = tone(x, gamma=1.1, contrast=0.9)
    x = noise(x, rng, 4)
    return jpeg(x, 85)


ATTACKS = {
    "none (lossless copy)": lambda img, rng: img,
    "JPEG q90": lambda img, rng: jpeg(img, 90),
    "JPEG q75": lambda img, rng: jpeg(img, 75),
    "JPEG q50": lambda img, rng: jpeg(img, 50),
    "JPEG q30": lambda img, rng: jpeg(img, 30),
    "scale 0.5x (small screenshot)": lambda img, rng: scale(img, 0.5),
    "scale 0.75x": lambda img, rng: scale(img, 0.75),
    "scale 1.5x": lambda img, rng: scale(img, 1.5),
    "rotation 1 deg": lambda img, rng: rotate(img, 1),
    "rotation 5 deg": lambda img, rng: rotate(img, 5),
    "rotation 15 deg": lambda img, rng: rotate(img, 15),
    "rotation 90 deg": lambda img, rng: rotate(img, 90),
    "rotation 180 deg": lambda img, rng: rotate(img, 180),
    "perspective mild (3%)": lambda img, rng: perspective(img, rng, 0.03),
    "perspective strong (7%)": lambda img, rng: perspective(img, rng, 0.07),
    "blur sigma 1.0": lambda img, rng: blur(img, 1.0),
    "blur sigma 2.0": lambda img, rng: blur(img, 2.0),
    "noise sigma 8": lambda img, rng: noise(img, rng, 8),
    "gamma 0.6 + contrast 0.7": lambda img, rng: tone(img, gamma=0.6, contrast=0.7),
    "crop 50% area": lambda img, rng: crop(img, rng, 0.5),
    "crop 25% area": lambda img, rng: crop(img, rng, 0.25),
    "crop 12% area": lambda img, rng: crop(img, rng, 0.12),
    "screenshot 0.8x + JPEG 75": lambda img, rng: jpeg(scale(img, 0.8), 75),
    "crop 50% + rot 5 + JPEG 70": lambda img, rng: jpeg(rotate(crop(img, rng, 0.5), 5), 70),
    "print-and-scan simulation": print_scan,
    "phone photo simulation": phone_photo,
}
