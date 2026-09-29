"""Layer 2: zero-width Unicode characters between words, for copy-paste leaks.

This layer is WEAK by design. Any sanitiser, "paste as plain text" in editors that drop format
characters, or a one-line regex removes it. Its only job is to survive a plain copy-paste of
the text into an unsanitised destination (another document, an email body), where the image
layers cannot help because only text is copied. Never rely on it alone.

Encoding: 64-bit trace code + CRC-16 = 80 bits, written as 51 base-3 digits. Each digit is a
step from the previous symbol to one of the other three of U+200B, U+200C, U+200D, U+FEFF, so
neighbouring symbols are never equal: PDF readers merge repeated identical glyphs at the same
position ("fake bold"), which would otherwise corrupt a copy. A full copy is inserted after every WORDS_PER_COPY-th word, so
any excerpt of about twice that many words carries a complete copy. A copy is one unbroken run
of zero-width characters, so a run cut at the edge of an excerpt is simply ignored.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from app.services import watermark_ecc as ecc

SYMBOLS = "​‌‍﻿"
PAYLOAD_BITS = 64
SYMBOLS_PER_COPY = 51                    # 3**51 > 2**80
WORDS_PER_COPY = 6

_RUN = re.compile(f"[{SYMBOLS}]+")
_WORD = re.compile(r"\S+")


def encode(payload: int) -> str:
    value = ecc.bits_to_int(ecc.with_crc(payload, PAYLOAD_BITS))
    out, previous = [], 0
    for _ in range(SYMBOLS_PER_COPY):
        value, digit = divmod(value, 3)
        previous = (previous + 1 + digit) % 4
        out.append(SYMBOLS[previous])
    return "".join(out)


def _decode(run: str) -> int | None:
    digits, previous = [], 0
    for ch in run:
        index = SYMBOLS.index(ch)
        digit = (index - previous - 1) % 4
        if digit == 3:                           # a repeated symbol: not one of our copies
            return None
        digits.append(digit)
        previous = index
    value = 0
    for digit in reversed(digits):
        value = value * 3 + digit
    if value >> (PAYLOAD_BITS + 16):
        return None
    return ecc.check_crc(ecc.int_to_bits(value, PAYLOAD_BITS + 16), PAYLOAD_BITS)


class Embedder:
    """Inserts copies across several pieces of text (e.g. PDF lines) with one running count."""

    def __init__(self, payload: int):
        self.copy = encode(payload)
        self.words = 0

    def embed(self, text: str) -> str:
        def after_word(match: re.Match) -> str:
            self.words += 1
            return match.group(0) + (self.copy if self.words % WORDS_PER_COPY == 0 else "")

        return _WORD.sub(after_word, text)


def embed(text: str, payload: int) -> str:
    return Embedder(payload).embed(text)


@dataclass
class TextDetection:
    detected: bool
    payload: int | None
    confidence: float     # share of complete copies that agree with the decoded payload
    copies: int           # complete copies with a valid CRC


def extract(text: str) -> TextDetection:
    decoded = []
    for run in _RUN.findall(text):
        if len(run) != SYMBOLS_PER_COPY:
            continue                                  # partial copy at the edge of an excerpt
        decoded.append(_decode(run))
    valid = [p for p in decoded if p is not None]
    if not valid:
        return TextDetection(False, None, 0.0, 0)
    payload, count = Counter(valid).most_common(1)[0]
    return TextDetection(True, payload, round(count / len(decoded), 3), count)


def strip(text: str) -> str:
    """Remove every zero-width symbol (used to show what a sanitiser does)."""
    return _RUN.sub("", text)
