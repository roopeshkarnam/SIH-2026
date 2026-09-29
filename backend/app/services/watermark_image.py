"""Layer 3: image-domain watermark for screenshots and photos of a rendered page.

Embedding, on a page raster rendered at RENDER_DPI:
  * Payload: 64-bit trace code + CRC-16, convolutionally encoded to 172 bits.
  * Grid: luminance is averaged over 2x2 pixels into "cells". Each 8x8-cell block carries one
    coded bit as the sign of DCT[1,2] - DCT[2,1]: a relative change between two mid-frequency
    coefficients, so brightness/contrast changes and mild recompression keep it.
  * Tile: 16x16 blocks = 48 keyed pilot bits + 208 data slots (all 172 coded bits, some twice),
    repeated over the whole page, so a crop of ~2x2 tiles (about 9x9 cm) still has full copies.
  * Sync template: five faint sinusoids at keyed frequencies make sharp peaks in the FFT
    magnitude. Where those peaks land in a photo reveals its rotation, scale and shear.

Extraction, from any screenshot, photo or scan:
  FFT peaks -> linear transform (globally, then refined per region so perspective is handled)
  -> resample each region onto the embedding grid -> search block alignment and tile offset
  with the pilots -> soft-combine regions -> Viterbi -> CRC. Returns a confidence score.

The payload is keyed: without the key the pattern can be neither read nor forged.
Only numpy is used, so the desktop bundle stays small.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import math
from dataclasses import dataclass
from functools import lru_cache

import numpy as np

from app.services import watermark_ecc as ecc

RENDER_DPI = 150
CELL = 2                  # page pixels per cell (each side)
BLOCK = 8                 # cells per DCT block (each side)
TILE = 16                 # blocks per tile (each side)
TILE_CELLS = TILE * BLOCK
PILOTS = 48
PAYLOAD_BITS = 64
MESSAGE_BITS = PAYLOAD_BITS + 16
CODED_BITS = ecc.coded_length(MESSAGE_BITS)

DELTA = 16.0              # target |DCT[1,2] - DCT[2,1]| per block (orthonormal DCT units)
MAX_CHANGE = 32.0         # cap on the change per block, limits artefacts next to text
TEMPLATE_AMPLITUDE = 1.6  # grey levels per sync sinusoid
HEADROOM = 8.0            # grey levels kept free at black/white so changes are not clipped
TEMPLATE_RADII = (0.20, 0.23, 0.26, 0.29, 0.32)  # cycles per cell

_n = np.arange(BLOCK)
_D1 = 0.5 * np.cos((2 * _n + 1) * 1 * np.pi / 16)
_D2 = 0.5 * np.cos((2 * _n + 1) * 2 * np.pi / 16)
# sum(block * KERNEL) == DCT[1,2] - DCT[2,1] for the orthonormal 8x8 DCT-II; |KERNEL|^2 == 2.
KERNEL = np.outer(_D1, _D2) - np.outer(_D2, _D1)


@dataclass(frozen=True)
class _Keyed:
    key_sign: np.ndarray    # (16,16) +-1 whitening per block position
    pilot_mask: np.ndarray  # (16,16) bool
    pilot_sym: np.ndarray   # (16,16) +-1 (meaningful at pilots)
    slot_bit: np.ndarray    # (16,16) coded-bit index for data slots, -1 at pilots
    template: np.ndarray    # (5,2) sync frequencies, cycles per page pixel, (x, y)
    phases: np.ndarray      # (5,)


@lru_cache(maxsize=8)
def _keyed(key: bytes) -> _Keyed:
    seed = int.from_bytes(hmac.new(key, b"MUDRA-L3-v1", hashlib.sha256).digest()[:8], "big")
    rng = np.random.default_rng(seed)
    positions = TILE * TILE
    key_sign = rng.choice([-1.0, 1.0], size=positions)
    order = rng.permutation(positions)
    pilot_mask = np.zeros(positions, dtype=bool)
    pilot_mask[order[:PILOTS]] = True
    pilot_sym = rng.choice([-1.0, 1.0], size=positions)
    slot_bit = np.full(positions, -1, dtype=np.int64)
    data_positions = order[PILOTS:]
    coded = np.concatenate([rng.permutation(CODED_BITS),
                            rng.choice(CODED_BITS, size=len(data_positions) - CODED_BITS, replace=False)])
    slot_bit[data_positions] = coded
    # Keyed angles, >= 13 degrees from the page axes, where text puts most of its energy,
    # and irregularly spaced so a lattice of text peaks cannot imitate the constellation.
    base = rng.uniform(15.0, 20.0)
    angles = np.radians(base + np.array([0.0, 38.0, 57.0, 112.0, 143.0]))
    radii = np.array(TEMPLATE_RADII) / CELL
    template = np.stack([radii * np.cos(angles), radii * np.sin(angles)], axis=1)
    return _Keyed(key_sign.reshape(TILE, TILE), pilot_mask.reshape(TILE, TILE), pilot_sym.reshape(TILE, TILE),
                  slot_bit.reshape(TILE, TILE), template, rng.uniform(0, 2 * np.pi, size=len(TEMPLATE_RADII)))


def _tile_symbols(payload: int, keyed: _Keyed) -> np.ndarray:
    code = 1.0 - 2.0 * ecc.conv_encode(ecc.with_crc(payload, PAYLOAD_BITS))
    symbols = np.where(keyed.pilot_mask, keyed.pilot_sym, code[np.maximum(keyed.slot_bit, 0)])
    return symbols * keyed.key_sign


def _template_field(h: int, w: int, keyed: _Keyed) -> np.ndarray:
    y = np.arange(h, dtype=np.float64)[:, None]
    x = np.arange(w, dtype=np.float64)[None, :]
    field = np.zeros((h, w))
    for (fx, fy), phase in zip(keyed.template, keyed.phases):
        field += np.cos(2 * np.pi * (fx * x + fy * y) + phase)
    return TEMPLATE_AMPLITUDE * field


def _masking(lum: np.ndarray) -> np.ndarray:
    """Perceptual masking: how much change each pixel hides, from local contrast.

    Changes are easy to see on blank paper and hard to see inside text or pictures, so the
    watermark is weaker on white (0.5x) and stronger in busy areas (up to 3x).
    """
    mean = _box_blur(lum, 8)
    activity = np.sqrt(np.maximum(_box_blur(lum * lum, 8) - mean * mean, 0.0))
    return _box_blur(np.clip(0.5 + activity / 25.0, 0.5, 3.0), 12)


def embed(rgb: np.ndarray, payload: int, key: bytes) -> np.ndarray:
    """Return a watermarked copy of an RGB (or grey) uint8 page raster."""
    keyed = _keyed(key)
    img = HEADROOM + rgb.astype(np.float64) * ((255.0 - 2 * HEADROOM) / 255.0)
    h, w = img.shape[:2]
    lum = img.mean(axis=2) if img.ndim == 3 else img
    hc, wc = h // CELL, w // CELL
    nby, nbx = hc // BLOCK, wc // BLOCK
    cells = lum[:hc * CELL, :wc * CELL].reshape(hc, CELL, wc, CELL).mean(axis=(1, 3))
    blocks = cells[:nby * BLOCK, :nbx * BLOCK].reshape(nby, BLOCK, nbx, BLOCK)
    current = np.einsum("aibj,ij->ab", blocks, KERNEL)
    mask = _masking(lum)
    block_mask = mask[:nby * BLOCK * CELL, :nbx * BLOCK * CELL].reshape(nby, BLOCK * CELL, nbx, BLOCK * CELL).mean(axis=(1, 3))

    symbols = _tile_symbols(payload, keyed)
    target = DELTA * np.tile(symbols, (nby // TILE + 1, nbx // TILE + 1))[:nby, :nbx]
    # Informed embedding: only change blocks that do not already carry the bit with margin.
    change = np.where(current * np.sign(target) < DELTA, target - current, 0.0)
    change = np.clip(change, -MAX_CHANGE * block_mask, MAX_CHANGE * block_mask)
    delta_cells = np.zeros((hc, wc))
    delta_cells[:nby * BLOCK, :nbx * BLOCK] = (change[:, None, :, None] * KERNEL[None, :, None, :] / 2.0).reshape(nby * BLOCK, nbx * BLOCK)

    delta = np.zeros((h, w))
    delta[:hc * CELL, :wc * CELL] = np.repeat(np.repeat(delta_cells, CELL, axis=0), CELL, axis=1)
    delta += _template_field(h, w, keyed) * mask
    img += delta[..., None] if img.ndim == 3 else delta
    return np.clip(np.rint(img), 0, 255).astype(np.uint8)


# ----------------------------------------------------------------------------------------------
# Extraction
# ----------------------------------------------------------------------------------------------

@dataclass
class ImageDetection:
    detected: bool
    payload: int | None
    confidence: float        # correlation between received soft bits and the decoded codeword
    regions_used: int
    rotation_deg: float | None
    scale: float | None      # page pixels (at RENDER_DPI) per input pixel


def _box_blur(a: np.ndarray, radius: int) -> np.ndarray:
    """Mean over a (2r+1)^2 window using an integral image (edges use the valid part)."""
    pad = np.pad(a, radius, mode="edge")
    s = np.cumsum(np.cumsum(pad, axis=0), axis=1)
    s = np.pad(s, ((1, 0), (1, 0)))
    k = 2 * radius + 1
    total = s[k:, k:] - s[:-k, k:] - s[k:, :-k] + s[:-k, :-k]
    return total / (k * k)


def _gaussian_blur(a: np.ndarray, sigma: float) -> np.ndarray:
    radius = max(1, int(math.ceil(3 * sigma)))
    x = np.arange(-radius, radius + 1)
    kernel = np.exp(-x * x / (2 * sigma * sigma))
    kernel /= kernel.sum()
    pad = np.pad(a, radius, mode="reflect")
    rows = sum(kernel[i] * pad[i:i + a.shape[0], :] for i in range(len(kernel)))
    return sum(kernel[i] * rows[:, i:i + a.shape[1]] for i in range(len(kernel)))


def _downscale(a: np.ndarray, factor: int) -> np.ndarray:
    if factor <= 1:
        return a
    h, w = a.shape[0] // factor, a.shape[1] // factor
    return a[:h * factor, :w * factor].reshape(h, factor, w, factor).mean(axis=(1, 3))


def warp_affine(src: np.ndarray, matrix: np.ndarray, offset: np.ndarray, out_h: int, out_w: int) -> np.ndarray:
    """out[v, u] = src at (x, y) = matrix @ (u, v) + offset, bilinear; outside -> mean of src."""
    uu, vv = np.meshgrid(np.arange(out_w, dtype=np.float64), np.arange(out_h, dtype=np.float64))
    x = matrix[0, 0] * uu + matrix[0, 1] * vv + offset[0]
    y = matrix[1, 0] * uu + matrix[1, 1] * vv + offset[1]
    return _sample(src, x, y)


def _sample(src: np.ndarray, x: np.ndarray, y: np.ndarray) -> np.ndarray:
    """Bilinear sample of src at (x, y); outside -> mean of src."""
    h, w = src.shape
    x0 = np.floor(x).astype(np.int64)
    y0 = np.floor(y).astype(np.int64)
    fx, fy = x - x0, y - y0
    inside = (x0 >= 0) & (y0 >= 0) & (x0 < w - 1) & (y0 < h - 1)
    x0c, y0c = np.clip(x0, 0, w - 2), np.clip(y0, 0, h - 2)
    top = src[y0c, x0c] * (1 - fx) + src[y0c, x0c + 1] * fx
    bottom = src[y0c + 1, x0c] * (1 - fx) + src[y0c + 1, x0c + 1] * fx
    out = top * (1 - fy) + bottom * fy
    return np.where(inside, out, src.mean())


def _spectrum(region: np.ndarray) -> tuple[np.ndarray, int]:
    """Whitened log-magnitude spectrum (fftshifted) of a Hann-windowed region."""
    h, w = region.shape
    n = 1 << int(math.ceil(math.log2(max(h, w))))
    window = np.outer(np.hanning(h), np.hanning(w))
    spectrum = np.abs(np.fft.fftshift(np.fft.fft2((region - region.mean()) * window, s=(n, n))))
    log = np.log1p(spectrum)
    return log - _box_blur(log, 7), n


def _bin(spectrum: np.ndarray, n: int, fx: float, fy: float) -> tuple[int, int]:
    return int(round(fy * n + n / 2)), int(round(fx * n + n / 2))


def _peak_near(spectrum: np.ndarray, n: int, fx: float, fy: float, radius: int) -> tuple[float, float, float] | None:
    """Strongest bin within `radius` of a frequency; returns (value, fx, fy) with sub-bin refinement."""
    cy, cx = _bin(spectrum, n, fx, fy)
    y0, y1, x0, x1 = max(cy - radius, 1), min(cy + radius + 1, n - 1), max(cx - radius, 1), min(cx + radius + 1, n - 1)
    if y0 >= y1 or x0 >= x1:
        return None
    patch = spectrum[y0:y1, x0:x1]
    iy, ix = np.unravel_index(np.argmax(patch), patch.shape)
    py, px = y0 + iy, x0 + ix

    def refine(a, b, c):
        denominator = a - 2 * b + c
        return 0.0 if denominator == 0 else float(np.clip(0.5 * (a - c) / denominator, -0.5, 0.5))

    dy = refine(spectrum[py - 1, px], spectrum[py, px], spectrum[py + 1, px])
    dx = refine(spectrum[py, px - 1], spectrum[py, px], spectrum[py, px + 1])
    return float(spectrum[py, px]), (px + dx - n / 2) / n, (py + dy - n / 2) / n


def _solve(peaks: np.ndarray, freqs: np.ndarray) -> np.ndarray:
    """Least-squares linear map M (input px -> page px) with peaks = M^T @ freqs (columns)."""
    mt = peaks @ freqs.T @ np.linalg.inv(freqs @ freqs.T)
    return mt.T


# Accepted geometry: page pixels (at RENDER_DPI) per input pixel, and how far from a pure
# rotation+scale the local transform may be (perspective, non-square pixels).
MIN_SCALE, MAX_SCALE, MAX_ANISOTROPY = 0.25, 4.0, 1.35


def _plausible(m: np.ndarray) -> bool:
    if not np.all(np.isfinite(m)) or np.linalg.det(m) <= 0:
        return False
    s = np.linalg.svd(m, compute_uv=False)
    return MIN_SCALE <= s[1] and s[0] <= MAX_SCALE and s[0] / s[1] <= MAX_ANISOTROPY


PEAK_THRESHOLD = 1.0


def _max_filter(a: np.ndarray, radius: int) -> np.ndarray:
    pad = np.pad(a, radius, mode="constant", constant_values=-np.inf)
    out = np.full_like(a, -np.inf)
    for dy in range(2 * radius + 1):
        for dx in range(2 * radius + 1):
            out = np.maximum(out, pad[dy:dy + a.shape[0], dx:dx + a.shape[1]])
    return out


AXIS_EXCLUSION = math.radians(7.0)
# Dense text makes hundreds of spectral peaks stronger than the template, so keep many.
SYNC_CANDIDATES = 400


def _global_sync(gray: np.ndarray, keyed: _Keyed) -> tuple[np.ndarray | None, float]:
    """(M, score): M maps input px -> page px; score = weakest of the 4 best template peaks."""
    found = _global_sync_once(gray, keyed, skip_page_axes=True)
    return found if found[0] is not None else _global_sync_once(gray, keyed, skip_page_axes=False)


def _windowed_sync(gray: np.ndarray, keyed: _Keyed) -> np.ndarray | None:
    """Sync on smaller windows and keep the transform most of them agree on.

    Perspective makes the template frequencies drift across the image, which smears the FFT
    peaks of the whole image (the smear grows with the square of the window size). Smaller
    windows see sharp peaks again. Dense text can make every window lock onto the same wrong
    transform (the text lattice), so each distinct candidate is checked by decoding a region
    with it: only the true geometry lines up the watermark's pilot bits.
    """
    h, w = gray.shape
    if min(h, w) < 256:
        return None
    windows = [(h // 2, w // 2, cy, cx) for cy, cx in
               ((h / 2, w / 2), (h / 4, w / 4), (h / 4, 3 * w / 4), (3 * h / 4, w / 4), (3 * h / 4, 3 * w / 4))]
    small = 512
    if min(h, w) >= 2 * small:
        windows += [(small, small, cy, cx) for cy in (h / 4, h / 2, 3 * h / 4) for cx in (w / 4, w / 2, 3 * w / 4)]
    found = []
    for size_y, size_x, cy, cx in windows:
        y0, x0 = int(cy - size_y / 2), int(cx - size_x / 2)
        m, score = _global_sync(gray[max(y0, 0):y0 + size_y, max(x0, 0):x0 + size_x], keyed)
        if m is not None:
            found.append((m, score, (cx, cy)))
    best, best_rho = None, 0.0
    tried = []
    for m, _, center in sorted(found, key=lambda item: -item[1]):
        # Perspective changes the local transform by up to ~15% across a page: same candidate.
        if any(np.linalg.norm(other - m) <= 0.15 * np.linalg.norm(m) for other in tried):
            continue
        tried.append(m)
        prepared, _ = _antialiased(gray, m)
        size = 2 * TILE_CELLS + 2 * BLOCK
        _, rho = _best_orientation(prepared, center, m, size, size, keyed)
        if rho > best_rho:
            best, best_rho = m, rho
    return best


def _global_sync_once(gray: np.ndarray, keyed: _Keyed, skip_page_axes: bool) -> np.ndarray | None:
    """Find M (input px -> page px) from the whole image without any prior.

    Text produces many strong peaks too (line spacing harmonics), so every pair of candidate
    peaks is tried as two template peaks; the other template peaks must then appear exactly
    where the implied transform predicts them.
    """
    factor = max(1, int(math.ceil(max(gray.shape) / 2048)))
    spectrum, n = _spectrum(_downscale(gray, factor))
    near_max = _max_filter(spectrum, 1)
    # Peaks: local maxima over 5x5 (merges the smeared duplicates), strongest first.
    ys, xs = np.nonzero((spectrum >= _max_filter(spectrum, 2)) & (spectrum > PEAK_THRESHOLD))
    fx, fy = (xs - n / 2) / n, (ys - n / 2) / n
    keep = (np.hypot(fx, fy) > 12 / n) & (np.hypot(fx, fy) < 0.49) & ((fy > 0) | ((fy == 0) & (fx > 0)))
    order = np.argsort(-spectrum[ys[keep], xs[keep]])[:SYNC_CANDIDATES]
    cx, cy, cv = fx[keep][order], fy[keep][order], spectrum[ys[keep], xs[keep]][order]
    if skip_page_axes and len(cv):
        # Text lines and character pitch put strong peaks along the page's own axes (which
        # rotate with the page). Find that direction (mod 90 degrees) and drop peaks near it.
        angle = np.arctan2(cy, cx)
        axis = np.angle(np.sum(cv * np.exp(4j * angle))) / 4
        off_axis = np.abs((angle - axis + np.pi / 4) % (np.pi / 2) - np.pi / 4) > AXIS_EXCLUSION
        cx, cy, cv = cx[off_axis], cy[off_axis], cv[off_axis]
    if len(cv) < 2:
        return None, 0.0

    template = keyed.template
    count = len(template)
    best, best_score = None, 0.0
    for a, b in itertools.combinations(range(count), 2):
        others = [k for k in range(count) if k not in (a, b)]
        inv = np.linalg.inv(np.stack([template[a], template[b]], axis=1))
        for sign in (1.0, -1.0):
            # Candidate i plays template a, candidate j plays template b: M^T = [p_i, p_j] @ inv.
            px_i, py_i = cx[:, None], cy[:, None]
            px_j, py_j = sign * cx[None, :], sign * cy[None, :]
            mt00 = px_i * inv[0, 0] + px_j * inv[1, 0]
            mt01 = px_i * inv[0, 1] + px_j * inv[1, 1]
            mt10 = py_i * inv[0, 0] + py_j * inv[1, 0]
            mt11 = py_i * inv[0, 1] + py_j * inv[1, 1]
            det = (mt00 * mt11 - mt01 * mt10) / factor ** 2
            squares = (mt00 ** 2 + mt01 ** 2 + mt10 ** 2 + mt11 ** 2) / factor ** 2
            root = np.sqrt(np.maximum(squares ** 2 - 4 * det ** 2, 0))
            s_max = np.sqrt((squares + root) / 2)
            s_min = np.sqrt(np.maximum((squares - root) / 2, 1e-12))
            ok = (det > 0) & (s_min >= MIN_SCALE) & (s_max <= MAX_SCALE) & (s_max / s_min <= MAX_ANISOTROPY)
            ok &= ~np.eye(len(cv), dtype=bool)
            # The other template peaks must appear where this hypothesis predicts them.
            predicted = []
            for k in others:
                pkx = mt00 * template[k][0] + mt01 * template[k][1]
                pky = mt10 * template[k][0] + mt11 * template[k][1]
                inside = (np.abs(pkx) < 0.49) & (np.abs(pky) < 0.49)
                by = np.clip(np.rint(pky * n + n / 2).astype(np.int64), 0, n - 1)
                bx = np.clip(np.rint(pkx * n + n / 2).astype(np.int64), 0, n - 1)
                predicted.append(np.where(inside, near_max[by, bx], -np.inf))
            predicted = np.sort(np.stack(predicted), axis=0)[::-1]    # strongest first
            # Rank by the weakest of the best four peaks: needs >= 4 of 5 template peaks present,
            # which a text-peak lattice almost never matches by accident.
            fourth = np.minimum(np.minimum(cv[:, None], cv[None, :]), predicted[1])
            score = np.where(ok & (fourth > PEAK_THRESHOLD), fourth, 0.0)
            i, j = np.unravel_index(np.argmax(score), score.shape)
            if score[i, j] > best_score:
                mt = np.array([[mt00[i, j], mt01[i, j]], [mt10[i, j], mt11[i, j]]])
                peaks, freqs = [(cx[i], cy[i]), (sign * cx[j], sign * cy[j])], [template[a], template[b]]
                for k in others:
                    fxk, fyk = mt @ template[k]
                    peak = _peak_near(spectrum, n, fxk, fyk, 1) if max(abs(fxk), abs(fyk)) < 0.49 else None
                    if peak is not None and peak[0] > PEAK_THRESHOLD:
                        peaks.append(peak[1:])
                        freqs.append(template[k])
                best, best_score = _solve(np.array(peaks).T, np.array(freqs).T), score[i, j]
    # That M maps small-image px -> page px; small px = full px / factor.
    return (None, 0.0) if best is None else (best / factor, float(best_score))


def _local_sync(region: np.ndarray, prior: np.ndarray, keyed: _Keyed) -> np.ndarray | None:
    """Measure M on one region near the prior's predicted peaks; None if < 3 peaks are found."""
    spectrum, n = _spectrum(region)
    found, freqs = [], []
    for f in keyed.template:
        fx, fy = prior.T @ f
        if abs(fx) >= 0.49 or abs(fy) >= 0.49:
            continue
        tolerance = max(3, int(0.12 * math.hypot(fx, fy) * n))
        peak = _peak_near(spectrum, n, fx, fy, tolerance)
        if peak is not None and peak[0] >= PEAK_THRESHOLD:
            found.append(peak[1:])
            freqs.append(f)
    if len(found) < 3:
        return None
    m = _solve(np.array(found).T, np.array(freqs).T)
    return m if _plausible(m) else None


def _correlate_valid(a: np.ndarray) -> np.ndarray:
    """r[y, x] = sum(a[y:y+8, x:x+8] * KERNEL) for every valid position (separable), clipped.

    Clipping to +-DELTA stops blocks with text edges (huge DCT values) from drowning the
    watermark when blocks are summed.
    """
    def vertical(img, w):
        return sum(w[i] * img[i:img.shape[0] - BLOCK + 1 + i, :] for i in range(BLOCK))

    def horizontal(img, w):
        return sum(w[j] * img[:, j:img.shape[1] - BLOCK + 1 + j] for j in range(BLOCK))

    r = horizontal(vertical(a, _D1), _D2) - horizontal(vertical(a, _D2), _D1)
    return np.clip(r, -DELTA, DELTA)


def _decode_region(canon: np.ndarray, keyed: _Keyed) -> tuple[np.ndarray, float]:
    """Search block alignment and tile offset with the pilots; return (soft coded bits, pilot rho)."""
    soft, rho, _ = _decode_aligned(canon, keyed)
    return soft, rho


def _decode_aligned(canon: np.ndarray, keyed: _Keyed):
    """As _decode_region, plus where the tile grid starts in `canon`: (row, col) mod TILE_CELLS."""
    r = _correlate_valid(canon)
    pilot_weights = np.where(keyed.pilot_mask, keyed.pilot_sym * keyed.key_sign, 0.0)
    fw = np.conj(np.fft.fft2(pilot_weights))
    fmask = np.conj(np.fft.fft2(keyed.pilot_mask.astype(np.float64)))
    best = (-np.inf, None, None)
    for ay in range(BLOCK):
        for ax in range(BLOCK):
            rb = r[ay::BLOCK, ax::BLOCK]
            ny, nx = -(-rb.shape[0] // TILE) * TILE, -(-rb.shape[1] // TILE) * TILE
            folded = np.zeros((ny, nx))
            folded[:rb.shape[0], :rb.shape[1]] = rb
            folded = folded.reshape(ny // TILE, TILE, nx // TILE, TILE).sum(axis=(0, 2))
            score = np.fft.ifft2(np.fft.fft2(folded) * fw).real
            energy = np.fft.ifft2(np.fft.fft2(folded * folded) * fmask).real
            rho = score / np.sqrt(np.maximum(energy, 1e-9) * PILOTS)
            oy, ox = np.unravel_index(np.argmax(rho), rho.shape)
            if rho[oy, ox] > best[0]:
                best = (rho[oy, ox], folded, (oy, ox), (ay, ax))
    rho, folded, (oy, ox), (ay, ax) = best
    aligned = np.roll(folded, (-oy, -ox), axis=(0, 1)) * keyed.key_sign
    data = ~keyed.pilot_mask
    soft = np.bincount(keyed.slot_bit[data], weights=aligned[data], minlength=CODED_BITS)
    origin = ((ay + BLOCK * oy) % TILE_CELLS, (ax + BLOCK * ox) % TILE_CELLS)
    return soft / max(np.abs(soft).mean(), 1e-9), float(rho), origin


def _canonical(gray: np.ndarray, center: tuple[float, float], m: np.ndarray, out_h: int, out_w: int) -> np.ndarray:
    """Resample the input around `center` onto the embedding cell grid using M (input -> page px)."""
    to_input = np.linalg.inv(m) * CELL           # cell step -> input px
    offset = np.array(center) - to_input @ np.array([(out_w - 1) / 2.0, (out_h - 1) / 2.0])
    return warp_affine(gray, to_input, offset, out_h, out_w)


def _best_orientation(gray: np.ndarray, center, m: np.ndarray, out_h: int, out_w: int, keyed: _Keyed):
    best = (None, -1.0)
    for orientation in (m, -m):                  # FFT peaks cannot tell 0 from 180 degrees
        soft, rho = _decode_region(_canonical(gray, center, orientation, out_h, out_w), keyed)
        if rho > best[1]:
            best = (soft, rho)
    return best


def _decode_whole(gray: np.ndarray, m: np.ndarray, keyed: _Keyed) -> np.ndarray:
    """One transform for the whole image (screenshots, scans, rotations, crops): fold all tiles."""
    h, w = gray.shape
    corners = np.array([[-w, -h], [w, -h], [w, h], [-w, h]], dtype=np.float64) / 2.0
    extent = np.abs(corners @ m.T).max(axis=0) / CELL          # half-size in cells (x, y)
    out_w, out_h = (int(min(2 * e + BLOCK, 4096)) for e in extent)
    soft, _ = _best_orientation(gray, (w / 2.0, h / 2.0), m, out_h, out_w, keyed)
    return soft


def _local_jacobians(gray: np.ndarray, prior, keyed: _Keyed, input_per_cell: float):
    """Measure the local transform (FFT sync) on a grid of regions. Returns [(center, M)].

    `prior(center)` gives the expected transform at a region centre.
    """
    h, w = gray.shape
    window = int(np.clip(3 * TILE_CELLS * input_per_cell, 256, 2048))
    measured = []
    for cy in np.linspace(window / 2, h - window / 2, max(2, round(2 * h / window) - 1)) if h > window else [h / 2]:
        for cx in np.linspace(window / 2, w - window / 2, max(2, round(2 * w / window) - 1)) if w > window else [w / 2]:
            y0, x0 = int(cy - window / 2), int(cx - window / 2)
            region = gray[max(y0, 0):y0 + window, max(x0, 0):x0 + window]
            center = np.array([cx, cy])
            m = _local_sync(region, prior(center), keyed)
            if m is not None:
                measured.append((center, m))
    return measured


def _estimate_perspective(gray: np.ndarray, m_start: np.ndarray, keyed: _Keyed, input_per_cell: float):
    """Local measurements -> homography fit, repeated with the fit as a sharper prior."""
    center = np.array([gray.shape[1] / 2.0, gray.shape[0] / 2.0])
    prior = lambda c: m_start
    params, measured = None, []
    for _ in range(3):
        measured = _local_jacobians(gray, prior, keyed, input_per_cell)
        params = _fit_perspective(measured, center)
        if params is None:
            break
        prior = lambda c, p=params: _jacobian(p, (c - center)[None])[0]
    return params, len(measured)


def _projective(params: np.ndarray, z: np.ndarray) -> np.ndarray:
    """P(z) = A z / (1 + p.z) for z relative to the image centre (rows of z are points)."""
    a, p = params[:4].reshape(2, 2), params[4:]
    return (z @ a.T) / (1.0 + z @ p)[:, None]


def _jacobian(params: np.ndarray, z: np.ndarray) -> np.ndarray:
    a, p = params[:4].reshape(2, 2), params[4:]
    d = 1.0 + z @ p
    az = z @ a.T
    return a[None] / d[:, None, None] - az[:, :, None] * p[None, None, :] / (d ** 2)[:, None, None]


def _fit_perspective(measured, center: np.ndarray) -> np.ndarray | None:
    """Fit a homography (up to a translation, which the tile search recovers) to local transforms.

    Every homography is P(z) + t with P(z) = A z / (1 + p.z); its Jacobian does not depend on t,
    so the local transforms from the FFT sync determine A and p (6 parameters).
    """
    if len(measured) < 4:
        return None
    z = np.array([c for c, _ in measured]) - center
    target = np.array([m for _, m in measured])
    # Drop gross outliers (a region locked onto text peaks) before fitting.
    deviation = np.abs(target - np.median(target, axis=0)).max(axis=(1, 2))
    keep = deviation <= max(4 * np.median(deviation), 0.05)
    z, target = z[keep], target[keep]
    if len(z) < 4:
        return None
    params = np.concatenate([np.median(target, axis=0).ravel(), [0.0, 0.0]])
    scale = np.array([1, 1, 1, 1, 1e-4, 1e-4])            # p is tiny in pixel units
    for _ in range(20):                                    # Gauss-Newton, numeric derivatives
        residual = (_jacobian(params, z) - target).ravel()
        columns = []
        for k in range(6):
            step = np.zeros(6)
            step[k] = 1e-6 * scale[k] * 1e2
            columns.append(((_jacobian(params + step, z) - target).ravel() - residual) / step[k])
        update = np.linalg.lstsq(np.stack(columns, axis=1), -residual, rcond=None)[0]
        params = params + update
        if np.all(np.abs(update) < 1e-9 * scale * 1e3):
            break
    return params if np.all(np.isfinite(params)) else None


def _decode_rectified(gray: np.ndarray, params: np.ndarray, keyed: _Keyed) -> np.ndarray:
    """Undo the fitted perspective for the whole image, then decode it like a flat scan."""
    h, w = gray.shape
    center = np.array([w / 2.0, h / 2.0])
    corners = np.array([[0, 0], [w, 0], [w, h], [0, h]], dtype=np.float64) - center
    page_corners = _projective(params, corners)
    lo, hi = page_corners.min(axis=0) / CELL, page_corners.max(axis=0) / CELL
    out_w, out_h = (int(min(v, 4096)) for v in np.ceil(hi - lo) + BLOCK)
    uu, vv = np.meshgrid(np.arange(out_w, dtype=np.float64), np.arange(out_h, dtype=np.float64))
    page = np.stack([(uu + lo[0]) * CELL, (vv + lo[1]) * CELL], axis=-1)
    # Invert y = A z / (1 + p.z):  z = (A - y p^T)^-1 y, per pixel.
    a, p = params[:4].reshape(2, 2), params[4:]
    m00 = a[0, 0] - page[..., 0] * p[0]
    m01 = a[0, 1] - page[..., 0] * p[1]
    m10 = a[1, 0] - page[..., 1] * p[0]
    m11 = a[1, 1] - page[..., 1] * p[1]
    det = m00 * m11 - m01 * m10
    zx = (m11 * page[..., 0] - m01 * page[..., 1]) / det + center[0]
    zy = (-m10 * page[..., 0] + m00 * page[..., 1]) / det + center[1]
    canon = _sample(gray, zx, zy)
    best = (None, -1.0)
    for image in (canon, canon[::-1, ::-1]):             # 0 or 180 degrees
        for candidate in (image, _tile_refine(image, keyed)):
            if candidate is None:
                continue
            soft, rho = _decode_region(candidate, keyed)
            if rho > best[1]:
                best = (soft, rho)
    return best[0]


def _tile_refine(canon: np.ndarray, keyed: _Keyed) -> np.ndarray | None:
    """Correct a small residual affine error using the watermark's own tile grid as a ruler.

    Folding the whole page needs the grid to line up to ~2 cells over ~600 cells, finer than
    the FFT sync gives on text-heavy pages. Regions decoded separately each report where the
    tile grid starts (to one cell); a residual error makes that position drift linearly across
    the page, so fitting the drift and resampling removes it.
    """
    size, stride = 2 * TILE_CELLS, TILE_CELLS
    h, w = canon.shape
    points, shifts, weights = [], [], []
    for y0 in range(0, max(h - size, 0) + 1, stride):
        for x0 in range(0, max(w - size, 0) + 1, stride):
            _, rho, (oy, ox) = _decode_aligned(canon[y0:y0 + size, x0:x0 + size], keyed)
            if rho > 0.45:
                points.append((x0 + size / 2, y0 + size / 2))
                shifts.append(((x0 + ox) % TILE_CELLS, (y0 + oy) % TILE_CELLS))
                weights.append(rho * rho)
    if len(points) < 4:
        return None
    points, shifts, weights = np.array(points), np.array(shifts, dtype=np.float64), np.array(weights)
    ref = int(np.argmax(weights))
    # Grid position relative to the most reliable region, unwrapped to (-64, 64] cells.
    delta = (shifts - shifts[ref] + TILE_CELLS / 2) % TILE_CELLS - TILE_CELLS / 2
    design = np.column_stack([points - points[ref], np.ones(len(points))])
    keep = np.ones(len(points), dtype=bool)
    for _ in range(2):                                   # fit, drop outliers, refit
        sw = np.sqrt(weights[keep])[:, None]
        coef = np.linalg.lstsq(design[keep] * sw, delta[keep] * sw, rcond=None)[0]
        keep = np.abs(design @ coef - delta).max(axis=1) <= 2.5
        if keep.sum() < 4:
            return None
    # Content that belongs at c appears at c + d(c): sample there to undo the drift.
    uu, vv = np.meshgrid(np.arange(w, dtype=np.float64), np.arange(h, dtype=np.float64))
    rel = np.stack([uu - points[ref][0], vv - points[ref][1]], axis=-1)
    d = rel @ coef[:2] + coef[2]
    return _sample(canon, uu + d[..., 0], vv + d[..., 1])


def _decode_soft(total: np.ndarray) -> tuple[int | None, float]:
    bits = ecc.viterbi_decode(total, MESSAGE_BITS)
    payload = ecc.check_crc(bits, PAYLOAD_BITS)
    codeword = 1.0 - 2.0 * ecc.conv_encode(bits)
    rho = float(np.dot(total, codeword) / (np.linalg.norm(total) * math.sqrt(CODED_BITS) + 1e-12))
    return (payload if payload is not None and rho >= DETECTION_RHO else None), rho


def _antialiased(gray: np.ndarray, m: np.ndarray) -> tuple[np.ndarray, float]:
    input_per_cell = CELL / math.sqrt(np.linalg.det(m))
    if input_per_cell > 1.2:                             # blur before downsampling onto cells
        return _gaussian_blur(gray, 0.45 * input_per_cell), input_per_cell
    return gray, input_per_cell


def extract(gray: np.ndarray, key: bytes) -> ImageDetection:
    """Find the Layer 3 payload in a grey image of any size, rotation, scale or perspective."""
    keyed = _keyed(key)
    gray = np.asarray(gray, dtype=np.float64)
    payload, rho, regions, m_used = None, 0.0, 0, None

    # Stage 1: the whole image under one transform (screenshots, scans, rotations, crops):
    # every tile is folded together, the strongest decode when it holds.
    m_whole, _ = _global_sync(gray, keyed)
    if m_whole is not None:
        prepared, _ = _antialiased(gray, m_whole)
        payload, rho = _decode_soft(_decode_whole(prepared, m_whole, keyed))
        regions, m_used = 1, m_whole

    # Stage 2: photos taken at an angle. Sync on smaller windows (perspective smears the
    # whole-image peaks), measure the local transform in many regions, fit a homography,
    # straighten the whole image and decode it again.
    if payload is None and min(gray.shape) >= 512:
        m_window = _windowed_sync(gray, keyed)
        if m_window is not None:
            prepared, input_per_cell = _antialiased(gray, m_window)
            params, measured = _estimate_perspective(gray, m_window, keyed, input_per_cell)
            if params is not None:
                rect_payload, rect_rho = _decode_soft(_decode_rectified(prepared, params, keyed))
                if rect_payload is not None or rect_rho > rho:
                    payload, rho, regions, m_used = rect_payload, rect_rho, measured, m_window

    if m_used is None:
        return ImageDetection(False, None, 0.0, 0, None, None)
    rotation = round(math.degrees(math.atan2(m_used[1, 0], m_used[0, 0])), 2)
    scale = round(math.sqrt(np.linalg.det(m_used)), 3)
    return ImageDetection(payload is not None, payload, _calibrated(rho), regions, rotation, scale)


# Viterbi always finds *some* codeword close to the input, so the raw correlation on pure noise
# is 0.657 +- 0.014 (max 0.71 over 3000 trials). Detection needs a CRC match AND rho >= 0.72;
# confidence rescales rho so the noise level maps to 0 and a perfect match to 1.
NOISE_RHO = 0.66
DETECTION_RHO = 0.72


def _calibrated(rho: float) -> float:
    return round(float(np.clip((rho - NOISE_RHO) / (1.0 - NOISE_RHO), 0.0, 1.0)), 3)
