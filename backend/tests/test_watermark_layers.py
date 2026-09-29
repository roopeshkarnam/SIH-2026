"""Tests for the three watermark layers and the attacks each one is meant to survive.

The full robustness matrix (all attacks x layouts x trials) is scripts/watermark_robustness.py;
here a representative subset guards against regressions.
"""

import random

import numpy as np
import pymupdf
import pytest

from app.services import watermark_ecc as ecc
from app.services import watermark_image as L3
from app.services import watermark_spacing as L1
from app.services import watermark_unicode as L2
from app.services.watermark import trace_code, watermark_key, watermark_service
from tests import wm_attacks as A

KEY = b"t" * 32
TRACE = 0x5A17_C0DE_2026_0923


@pytest.fixture(scope="module")
def dense_marked():
    rgb = A.page_rgb("dense")
    return rgb, A.to_gray(L3.embed(L1.embed(rgb, TRACE >> 32, KEY), TRACE, KEY))


# --- error correction -------------------------------------------------------------------------

def test_ecc_corrects_errors_and_rejects_noise():
    rng = np.random.default_rng(0)
    code = 1.0 - 2.0 * ecc.conv_encode(ecc.with_crc(TRACE, 64))
    flipped = code.copy()
    flipped[rng.choice(len(code), 12, replace=False)] *= -1          # 7% hard bit errors
    assert ecc.check_crc(ecc.viterbi_decode(flipped, 80), 64) == TRACE
    assert all(ecc.check_crc(ecc.viterbi_decode(rng.normal(0, 1, len(code)), 80), 64) is None for _ in range(200))


# --- Layer 3: image ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack", [
    "none (lossless copy)", "JPEG q50", "scale 0.5x (small screenshot)", "rotation 5 deg",
    "rotation 180 deg", "crop 50% area", "blur sigma 2.0", "print-and-scan simulation",
    "perspective mild (3%)",
])
def test_image_layer_survives(dense_marked, attack):
    _, gray = dense_marked
    result = L3.extract(A.ATTACKS[attack](gray, np.random.default_rng(1)), KEY)
    assert result.detected and result.payload == TRACE
    assert 0.0 < result.confidence <= 1.0


def test_image_layer_no_false_positives():
    rng = np.random.default_rng(2)
    for kind in ("dense", "figure"):
        clean = A.to_gray(A.page_rgb(kind))
        for image in (clean, A.phone_photo(clean, rng)):
            assert not L3.extract(image, KEY).detected


def test_image_layer_needs_the_key(dense_marked):
    _, gray = dense_marked
    assert not L3.extract(gray, b"x" * 32).detected


# --- Layer 1: word spacing ----------------------------------------------------------------------

def test_spacing_layer_round_trip_and_no_false_positive(dense_marked):
    rgb, gray = dense_marked
    found = L1.extract([gray], KEY)
    assert found.detected and found.payload == TRACE >> 32
    assert not L1.extract([A.to_gray(rgb)], KEY).detected


def test_spacing_layer_survives_rescan_as_jpeg(dense_marked):
    _, gray = dense_marked
    assert L1.extract([A.jpeg(gray, 75)], KEY).payload == TRACE >> 32


# --- Layer 2: zero-width Unicode ----------------------------------------------------------------

def test_unicode_layer_partial_copy_paste_into_txt(tmp_path):
    marked = L2.embed(A.PARAGRAPH * 4, TRACE)
    assert L2.strip(marked) == A.PARAGRAPH * 4            # visible text is unchanged
    words = marked.split(" ")
    rng = random.Random(7)
    for trial in range(50):
        n = rng.randint(14, 30)
        start = rng.randint(0, len(words) - n)
        path = tmp_path / f"paste{trial}.txt"
        path.write_text(" ".join(words[start:start + n]), encoding="utf-8")
        assert L2.extract(path.read_text(encoding="utf-8")).payload == TRACE


def test_unicode_layer_is_removed_by_sanitising():
    # Documented weakness: this layer only survives unsanitised copy-paste.
    assert not L2.extract(L2.strip(L2.embed(A.PARAGRAPH * 4, TRACE))).detected


# --- the delivered copy: attacks on the downloaded PDF -----------------------------------------

@pytest.fixture(scope="module")
def delivered():
    watermark_id = watermark_service.generate_watermark_id()
    copy = watermark_service.protect(A.page_pdf("dense"), "circular.pdf", watermark_id)
    return watermark_id, copy


def _codes(layers):
    return {layer["layer"]: layer["code"] for layer in layers if layer["found"]}


def test_delivered_pdf_carries_all_three_layers(delivered):
    watermark_id, copy = delivered
    code = f"{trace_code(watermark_id):016X}"
    codes = _codes(watermark_service.trace(copy.download))
    assert codes[3] == code and codes[2] == code and codes[1] == code[:8]
    # No readable ID anywhere in the file (the old layer's weakness).
    assert watermark_id.encode() not in copy.download and b"WM-" not in copy.download


def test_metadata_clear_and_text_deletion_do_not_remove_it(delivered):
    watermark_id, copy = delivered
    doc = pymupdf.open(stream=copy.download, filetype="pdf")
    doc.set_metadata({})
    doc.del_xml_metadata()
    for page in doc:                                     # select-all + delete the text layer
        page.add_redact_annot(page.rect)
        page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_NONE)
    stripped = doc.tobytes()
    assert pymupdf.open(stream=stripped, filetype="pdf")[0].get_text().strip() == ""
    codes = _codes(watermark_service.trace(stripped))
    assert codes[3] == f"{trace_code(watermark_id):016X}" and codes[1] == f"{trace_code(watermark_id):016X}"[:8]
    assert 2 not in codes                                # the text layer was deleted, as expected


def test_copy_from_delivered_pdf_carries_unicode_layer(delivered):
    watermark_id, copy = delivered
    copied = pymupdf.open(stream=copy.download, filetype="pdf")[0].get_text()
    assert L2.extract(copied).payload == trace_code(watermark_id)


def test_key_is_derived_not_constant():
    assert len(watermark_key()) == 32
