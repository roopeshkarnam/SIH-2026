"""Robustness matrix for the Layer 3 image watermark (FFT sync + DCT payload).

Embeds a random 64-bit trace code in test pages, applies each synthetic attack, runs the
real extractor and reports success rate and confidence per attack, plus false positives on
unwatermarked pages. Attacks are OpenCV-based (tests/wm_attacks.py).

    PYTHONPATH=backend .venv/bin/python backend/scripts/watermark_robustness.py --trials 3
"""

import argparse
import os
import platform
import statistics
import sys
import time

import numpy as np

from app.services import watermark_image as L3
from tests import wm_attacks as A

KEY = bytes.fromhex("6d756472612d726f627573746e6573732d6d61747269782d6b65792d3230323600")[:32]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=3, help="trials per page layout")
    parser.add_argument("--pages", default=",".join(A.PAGE_KINDS))
    parser.add_argument("--only", default="", help="comma-separated substrings of attack names")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    kinds = args.pages.split(",")
    attacks = {name: fn for name, fn in A.ATTACKS.items()
               if not args.only or any(s.strip() in name for s in args.only.split(","))}
    pages = {kind: A.page_rgb(kind) for kind in kinds}
    rng = np.random.default_rng(2026)
    rows = {name: [] for name in attacks}
    false_positives = {"unwatermarked, lossless": [], "unwatermarked, phone photo": []}
    distortion = []

    for kind, rgb in pages.items():
        for trial in range(args.trials):
            payload = int(rng.integers(0, 2 ** 63))
            marked = L3.embed(rgb, payload, KEY)
            # Distortion of the watermark itself (excluding the uniform headroom remap).
            remapped = L3.HEADROOM + rgb.astype(float) * ((255 - 2 * L3.HEADROOM) / 255)
            mse = np.mean((marked.astype(float) - remapped) ** 2)
            distortion.append(10 * np.log10(255 ** 2 / mse))
            gray = A.to_gray(marked)
            for name, attack in attacks.items():
                attacked = attack(gray, rng)
                start = time.perf_counter()
                result = L3.extract(attacked, KEY)
                rows[name].append((result.detected and result.payload == payload,
                                   result.detected and result.payload != payload,
                                   result.confidence, time.perf_counter() - start))
                print(f"{kind:7} t{trial} {name:34} ok={rows[name][-1][0]!s:5} conf={result.confidence:.3f}", file=sys.stderr)
            clean = A.to_gray(rgb)
            for name, img in (("unwatermarked, lossless", clean), ("unwatermarked, phone photo", A.phone_photo(clean, rng))):
                result = L3.extract(img, KEY)
                false_positives[name].append((result.detected, result.confidence))

    n = len(kinds) * args.trials
    lines = [
        "| Attack | Decoded correctly | Wrong payload | Mean confidence | Min confidence | Mean time |",
        "|---|---|---|---|---|---|",
    ]
    for name, results in rows.items():
        ok = [r for r in results if r[0]]
        lines.append(
            f"| {name} | {len(ok)}/{len(results)} ({100 * len(ok) / len(results):.0f}%) "
            f"| {sum(r[1] for r in results)} "
            f"| {statistics.mean(r[2] for r in results):.2f} | {min(r[2] for r in results):.2f} "
            f"| {statistics.mean(r[3] for r in results):.1f} s |"
        )
    lines.append("")
    lines.append("| False-positive check (no watermark) | Detections | Max confidence |")
    lines.append("|---|---|---|")
    for name, results in false_positives.items():
        lines.append(f"| {name} | {sum(r[0] for r in results)}/{len(results)} | {max(r[1] for r in results):.2f} |")
    header = (
        f"Layouts: {', '.join(kinds)}; {args.trials} trial(s) each = {n} trials per attack, random 64-bit payloads.\n"
        f"Watermark distortion (PSNR vs. the page after headroom remap): mean {statistics.mean(distortion):.1f} dB.\n"
        f"Machine: {platform.platform()}, Python {platform.python_version()}.\n"
    )
    report = header + "\n" + "\n".join(lines) + "\n"
    print(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main()
