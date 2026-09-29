"""Layer 1: word-spacing watermark in the rendered glyphs.

The payload lives in where the words are drawn, not in metadata, XMP or a hidden text layer,
so clearing metadata, deleting text objects, re-saving or "printing to PDF" keeps it.

In every text line, the words at odd positions (1, 3, 5, ...) are moved 1 pixel (1/150 inch,
0.17 mm) left or right. That makes the gap before such a word 2 px larger or smaller than the
gap after it, and the sign carries one bit. Natural gap asymmetry in rendered text is about
1 px (measured on justified and ragged text, 9-13 pt), so each bit is repeated across the page
and decoded by soft majority, with a CRC to reject misreads.

Extraction is blind: lines and words are found in the pixels with the same segmentation used
when embedding. It needs a full page at a known scale (a re-saved/flattened PDF, or a
screenshot whose scale Layer 3 has measured); crops and photos are Layer 3's job.

Payload: 32-bit prefix of the trace code + CRC-16 = 48 bits. The bit for the j-th carrier in
text line b is (7*b + j) mod 48, so a missed or extra line only affects that line.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

import numpy as np

from app.services import watermark_ecc as ecc

PAYLOAD_BITS = 32
MESSAGE_BITS = PAYLOAD_BITS + 16
SHIFT = 1                 # pixels at RENDER_DPI (150)
INK = 110                 # darker than this counts as ink (below the Layer 3 noise on paper)


def _key_signs(key: bytes) -> np.ndarray:
    digest = hmac.new(key, b"MUDRA-L1-v1", hashlib.sha256).digest()
    bits = np.unpackbits(np.frombuffer(digest, dtype=np.uint8))[:MESSAGE_BITS]
    return 1.0 - 2.0 * bits


def _runs(mask: np.ndarray) -> list[tuple[int, int]]:
    """[start, end) of each run of True values."""
    padded = np.concatenate([[False], mask, [False]])
    edges = np.flatnonzero(padded[1:] != padded[:-1])
    return list(zip(edges[0::2], edges[1::2]))


@dataclass
class _Carrier:
    index: int                # payload bit index
    y0: int
    y1: int
    x0: int                   # the word that moves
    x1: int
    left_gap: int
    right_gap: int
    threshold: float


def _carriers(gray: np.ndarray) -> list[_Carrier]:
    """Text lines -> words -> carriers (odd-position words with clear gaps on both sides)."""
    ink = gray < INK
    carriers = []
    for band, (y0, y1) in enumerate(_runs(ink.any(axis=1))):
        height = y1 - y0
        if not 6 <= height <= 60:          # not a line of body text (rules, images, titles)
            continue
        threshold = max(3.0, 0.2 * height)
        words = []
        for x0, x1 in _runs(ink[y0:y1].any(axis=0)):
            if words and x0 - words[-1][1] < threshold:
                words[-1] = (words[-1][0], x1)
            else:
                words.append((x0, x1))
        for i in range(1, len(words) - 1, 2):
            left, right = words[i][0] - words[i - 1][1], words[i + 1][0] - words[i][1]
            # The sum of both gaps and the word's width do not change when the word moves, so
            # embedder and extractor agree on which words are carriers. Narrow shapes (table
            # rules, "I") are skipped: moving a rule by a pixel would show.
            if left + right >= 2 * threshold + 4 and words[i][1] - words[i][0] >= max(4.0, 0.4 * height):
                carriers.append(_Carrier((7 * band + (i - 1) // 2) % MESSAGE_BITS, y0, y1,
                                         words[i][0], words[i][1], left, right, threshold))
    return carriers


def embed(rgb: np.ndarray, payload: int, key: bytes) -> np.ndarray:
    """Shift carrier words by +-1 px in an RGB page raster rendered at 150 dpi."""
    symbols = (1.0 - 2.0 * ecc.with_crc(payload, PAYLOAD_BITS)) * _key_signs(key)
    gray = rgb.mean(axis=2) if rgb.ndim == 3 else rgb
    out = rgb.copy()
    for c in _carriers(gray):
        if min(c.left_gap, c.right_gap) < c.threshold + 2:
            continue                           # moving it could merge/split words
        word = rgb[c.y0:c.y1, c.x0:c.x1].copy()
        if symbols[c.index] > 0:               # move right: left gap grows
            out[c.y0:c.y1, c.x0 + SHIFT:c.x1 + SHIFT] = word
            out[c.y0:c.y1, c.x0:c.x0 + SHIFT] = rgb[c.y0:c.y1, c.x0 - SHIFT:c.x0]
        else:                                  # move left: right gap grows
            out[c.y0:c.y1, c.x0 - SHIFT:c.x1 - SHIFT] = word
            out[c.y0:c.y1, c.x1 - SHIFT:c.x1] = rgb[c.y0:c.y1, c.x1:c.x1 + SHIFT]
    return out


@dataclass
class SpacingDetection:
    detected: bool
    payload: int | None       # 32-bit prefix of the trace code
    confidence: float         # share of carriers agreeing with the decoded bits, rescaled 0..1
    carriers: int


def extract(pages: list[np.ndarray], key: bytes) -> SpacingDetection:
    """Read the payload from full page rasters at 150 dpi, pooling evidence across pages."""
    signs = _key_signs(key)
    carriers = [c for page in pages for c in _carriers(np.asarray(page, dtype=np.float64))]
    soft = np.zeros(MESSAGE_BITS)
    seen = np.zeros(MESSAGE_BITS, dtype=int)
    readings = []
    for c in carriers:
        value = float(np.clip(c.left_gap - c.right_gap, -4, 4)) * signs[c.index]
        soft[c.index] += value
        seen[c.index] += 1
        readings.append((c.index, value))
    if len(carriers) < MESSAGE_BITS or seen.min() == 0:
        return SpacingDetection(False, None, 0.0, len(carriers))
    bits = (soft < 0).astype(np.uint8)
    payload = ecc.check_crc(bits, PAYLOAD_BITS)
    expected = 1.0 - 2.0 * bits
    agree = np.mean([np.sign(v) == expected[i] for i, v in readings if v != 0] or [0.5])
    confidence = round(float(np.clip((agree - 0.5) / 0.5, 0.0, 1.0)), 3)
    return SpacingDetection(payload is not None, payload, confidence, len(carriers))
