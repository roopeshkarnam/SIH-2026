"""Layered forensic watermark: protect a decrypted copy, and trace a leaked one.

Layer 1 (watermark_spacing): word positions in the rendered page. Survives metadata clearing,
        deleting text, re-saving and print-to-PDF. Full pages only.
Layer 2 (watermark_unicode): zero-width characters in the copyable text. Survives plain
        copy-paste only; any sanitiser removes it.
Layer 3 (watermark_image): FFT-synchronised DCT watermark in the page image. Survives
        screenshots, crops, recompression, scans and phone photos.

The payload of every layer is derived from the session's watermark ID: its first 64 bits
(the "trace code"); Layer 1 carries the first 32 bits.
"""

from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass, field

import numpy as np
import pymupdf

from app.core.config import settings
from app.services import watermark_image as L3
from app.services import watermark_spacing as L1
from app.services import watermark_unicode as L2
from app.services.encryption import encryption_service

LEGACY_PATTERN = re.compile(r"WM-[0-9A-F]{32}")
IMAGE_TYPES = (".png", ".jpg", ".jpeg")
TEXT_TYPES = (".txt", ".md", ".csv")
MAX_TRACE_PAGES = 5


def watermark_key() -> bytes:
    """Secret watermark key, derived from the key-store master key (never stored)."""
    return encryption_service.derive_wrapping_key(base64.b64decode(settings.keystore_master_key), b"MUDRA-WATERMARK-KEY-v1")


def trace_code(watermark_id: str) -> int:
    return int(watermark_id[3:19], 16)


def _page_rgb(page: pymupdf.Page) -> np.ndarray:
    pix = page.get_pixmap(dpi=L3.RENDER_DPI, alpha=False, colorspace=pymupdf.csRGB)
    return np.frombuffer(pix.samples, np.uint8).reshape(pix.h, pix.w, 3).copy()


def _png(rgb: np.ndarray) -> bytes:
    h, w = rgb.shape[:2]
    return pymupdf.Pixmap(pymupdf.csRGB, w, h, np.ascontiguousarray(rgb).tobytes(), False).tobytes("png")


def _gray(rgb: np.ndarray) -> np.ndarray:
    return rgb.astype(np.float64) @ np.array([0.299, 0.587, 0.114])


@dataclass
class ProtectedCopy:
    kind: str                       # pdf | image | text | other
    pages: list[bytes] = field(default_factory=list)   # watermarked PNG per page (preview)
    text: str | None = None         # watermarked text (preview), text files only
    download: bytes = b""
    download_name: str = ""


class WatermarkService:
    @staticmethod
    def generate_watermark_id() -> str:
        return "WM-" + secrets.token_hex(16).upper()

    @staticmethod
    def protect(data: bytes, filename: str, watermark_id: str) -> ProtectedCopy:
        """Build the recipient's watermarked copy: preview pages and a download file."""
        key, code = watermark_key(), trace_code(watermark_id)
        name = filename.lower()
        if name.endswith(".pdf"):
            return WatermarkService._protect_pdf(data, filename, key, code)
        if name.endswith(IMAGE_TYPES):
            pix = pymupdf.Pixmap(data)
            if pix.alpha or pix.n != 3:
                pix = pymupdf.Pixmap(pymupdf.csRGB, pix, 0)
            rgb = np.frombuffer(pix.samples, np.uint8).reshape(pix.h, pix.w, 3).copy()
            page = _png(L3.embed(rgb, code, key))
            return ProtectedCopy("image", [page], None, page, filename.rsplit(".", 1)[0] + ".png")
        if name.endswith(TEXT_TYPES):
            text = L2.embed(data.decode("utf-8", errors="replace"), code)
            return ProtectedCopy("text", [], text, text.encode("utf-8"), filename)
        return ProtectedCopy("other", [], None, data, filename)

    @staticmethod
    def _protect_pdf(data: bytes, filename: str, key: bytes, code: int) -> ProtectedCopy:
        source = pymupdf.open(stream=data, filetype="pdf")
        out = pymupdf.open()
        font = pymupdf.Font("notos")               # has glyphs for the zero-width characters
        unicode_layer = L2.Embedder(code)
        pages = []
        for page in source:
            rgb = L3.embed(L1.embed(_page_rgb(page), code >> 32, key), code, key)
            png = _png(rgb)
            pages.append(png)
            target = out.new_page(width=page.rect.width, height=page.rect.height)
            target.insert_image(target.rect, stream=png)
            # Invisible, selectable text over the image (like a scanned PDF with OCR), so text
            # can still be copied; the copied text carries Layer 2.
            writer = pymupdf.TextWriter(target.rect)
            for block in page.get_text("dict")["blocks"]:
                for line in block.get("lines", []):
                    text = "".join(span["text"] for span in line["spans"])
                    if text.strip():
                        size = max(line["spans"][0]["size"], 1.0)
                        writer.append(line["spans"][0]["origin"], unicode_layer.embed(text), font=font, fontsize=size)
            writer.write_text(target, render_mode=3)
        out.subset_fonts()
        return ProtectedCopy("pdf", pages, None, out.tobytes(garbage=3, deflate=True), filename)

    @staticmethod
    def trace(data: bytes) -> list[dict]:
        """Look for every layer in a leaked file (PDF, image, or text). One result per layer."""
        key = watermark_key()
        results = []
        if data[:5] == b"%PDF-":
            doc = pymupdf.open(stream=data, filetype="pdf")
            text = "".join(page.get_text() for page in doc)
            legacy = LEGACY_PATTERN.search((doc.metadata.get("keywords") or "") + text)
            if legacy:
                results.append({"layer": 0, "name": "Legacy text marker (old copies only)", "found": True,
                                "code": legacy.group(0)[3:19], "confidence": 1.0})
            results.append(WatermarkService._unicode_result(text))
            pages = [_gray(_page_rgb(page)) for page in list(doc)[:MAX_TRACE_PAGES]]
            results.append(WatermarkService._spacing_result(pages, key))
            image = {"layer": 3, "name": "Image watermark", "found": False, "code": None, "confidence": 0.0}
            for gray in pages:
                found = L3.extract(gray, key)
                if found.confidence >= image["confidence"]:
                    image = WatermarkService._image_result(found)
                if found.detected:
                    break
            results.append(image)
            return results
        if data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff":
            pix = pymupdf.Pixmap(data)
            if pix.alpha or pix.n != 3:
                pix = pymupdf.Pixmap(pymupdf.csRGB, pix, 0)
            gray = _gray(np.frombuffer(pix.samples, np.uint8).reshape(pix.h, pix.w, 3))
            found = L3.extract(gray, key)
            spacing = {"layer": 1, "name": "Word-spacing watermark", "found": False, "code": None, "confidence": 0.0,
                       "note": "Needs a straight full-page image"}
            if found.detected and abs(found.rotation_deg or 0) < 0.5:
                # Layer 3 measured the scale, so a straight screenshot can be read for Layer 1 too.
                pix = pymupdf.Pixmap(pix, int(pix.w * found.scale), int(pix.h * found.scale), None)
                spacing = WatermarkService._spacing_result(
                    [_gray(np.frombuffer(pix.samples, np.uint8).reshape(pix.h, pix.w, pix.n)[..., :3])], key)
            return [spacing, WatermarkService._unicode_result(""), WatermarkService._image_result(found)]
        text = data.decode("utf-8", errors="replace")
        return [WatermarkService._unicode_result(text)]

    @staticmethod
    def _unicode_result(text: str) -> dict:
        found = L2.extract(text)
        return {"layer": 2, "name": "Copy-paste (zero-width) watermark", "found": found.detected,
                "code": f"{found.payload:016X}" if found.detected else None, "confidence": found.confidence,
                "copies": found.copies}

    @staticmethod
    def _spacing_result(pages: list[np.ndarray], key: bytes) -> dict:
        found = L1.extract(pages, key)
        return {"layer": 1, "name": "Word-spacing watermark", "found": found.detected,
                "code": f"{found.payload:08X}" if found.detected else None, "confidence": found.confidence,
                "carriers": found.carriers}

    @staticmethod
    def _image_result(found: L3.ImageDetection) -> dict:
        return {"layer": 3, "name": "Image watermark", "found": found.detected,
                "code": f"{found.payload:016X}" if found.detected else None, "confidence": found.confidence,
                "rotation_deg": found.rotation_deg, "scale": found.scale}


watermark_service = WatermarkService()
