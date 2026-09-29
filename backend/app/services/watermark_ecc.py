"""Error detection and correction shared by the watermark layers.

* CRC-16/CCITT to reject random matches.
* Rate-1/2 convolutional code (constraint length 7, generators 171/133 octal, the
  NASA/CCSDS standard code) with a soft-decision Viterbi decoder.

Bits are numpy uint8 arrays of 0/1. Soft values use the convention: positive means bit 0,
negative means bit 1, magnitude = reliability.
"""

from __future__ import annotations

import numpy as np

_K = 7
_STATES = 1 << (_K - 1)
_GENERATORS = (0o171, 0o133)


def int_to_bits(value: int, count: int) -> np.ndarray:
    return np.array([(value >> (count - 1 - i)) & 1 for i in range(count)], dtype=np.uint8)


def bits_to_int(bits: np.ndarray) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return value


def crc16(bits: np.ndarray) -> np.ndarray:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) over a bit sequence, MSB first."""
    crc = 0xFFFF
    for bit in bits:
        top = ((crc >> 15) & 1) ^ int(bit)
        crc = (crc << 1) & 0xFFFF
        if top:
            crc ^= 0x1021
    return int_to_bits(crc, 16)


def with_crc(payload: int, payload_bits: int) -> np.ndarray:
    bits = int_to_bits(payload, payload_bits)
    return np.concatenate([bits, crc16(bits)])


def check_crc(bits: np.ndarray, payload_bits: int) -> int | None:
    """Return the payload if the trailing CRC-16 matches, else None."""
    payload = bits[:payload_bits]
    if np.array_equal(crc16(payload), bits[payload_bits:payload_bits + 16]):
        return bits_to_int(payload)
    return None


def _parity(value: int) -> int:
    return bin(value).count("1") & 1


# Trellis tables. State = last 6 input bits; register = (input << 6) | state.
_NEXT = np.zeros((_STATES, 2), dtype=np.int64)
_OUT = np.zeros((_STATES, 2, 2), dtype=np.int8)  # output bits per (state, input, generator)
for _state in range(_STATES):
    for _bit in range(2):
        _register = (_bit << (_K - 1)) | _state
        _NEXT[_state, _bit] = _register >> 1
        for _g, _generator in enumerate(_GENERATORS):
            _OUT[_state, _bit, _g] = _parity(_register & _generator)


def conv_encode(bits: np.ndarray) -> np.ndarray:
    """Encode and terminate (6 zero tail bits): len(out) = 2 * (len(bits) + 6)."""
    state = 0
    out = []
    for bit in list(bits) + [0] * (_K - 1):
        out.extend(_OUT[state, int(bit)])
        state = _NEXT[state, int(bit)]
    return np.array(out, dtype=np.uint8)


def coded_length(message_bits: int) -> int:
    return 2 * (message_bits + _K - 1)


# Each next-state has two predecessors: (ns << 1) & 63 and that | 1, with input bit ns >> 5.
_PRED = np.stack([(np.arange(_STATES) << 1) & (_STATES - 1), ((np.arange(_STATES) << 1) & (_STATES - 1)) | 1], axis=1)
_PRED_INPUT = np.arange(_STATES) >> (_K - 2)
_PRED_SYMBOLS = 1 - 2 * _OUT[_PRED, _PRED_INPUT[:, None]].astype(np.float64)  # (ns, which pred, generator)


def viterbi_decode(soft: np.ndarray, message_bits: int) -> np.ndarray:
    """Soft-decision Viterbi decoding of a terminated codeword. Returns message_bits bits."""
    steps = message_bits + _K - 1
    soft = np.asarray(soft, dtype=np.float64).reshape(steps, 2)
    metric = np.full(_STATES, -np.inf)
    metric[0] = 0.0
    choices = np.zeros((steps, _STATES), dtype=np.uint8)
    for t in range(steps):
        candidates = metric[_PRED] + _PRED_SYMBOLS @ soft[t]
        choice = np.argmax(candidates, axis=1)
        choices[t] = choice
        metric = candidates[np.arange(_STATES), choice]
    state = 0  # terminated trellis ends in state 0
    bits = np.zeros(steps, dtype=np.uint8)
    for t in range(steps - 1, -1, -1):
        bits[t] = _PRED_INPUT[state]
        state = _PRED[state, choices[t, state]]
    return bits[:message_bits]
