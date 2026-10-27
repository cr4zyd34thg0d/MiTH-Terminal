#!/usr/bin/env python3
"""Pure-Python ISO/IEC 18004 QR Code encoder and Unicode terminal renderer.

Zero-dependency implementation supporting Byte Mode (0100), Error Correction
Level L (01), and Versions 1 through 8 (payloads up to 192 UTF-8 bytes).
Renders compact half-block Unicode QR banners ('█', '▀', '▄', ' ') engineered
for instant iPhone / Android camera recognition on dark terminals.

Author: MiTH
License: MIT
"""

from __future__ import annotations

from collections import deque
import sys
from typing import Callable, Final

__all__ = [
    "LEVEL_L_FORMAT_WORDS",
    "compute_bch_format_bits",
    "compute_bch_version_bits",
    "encode_qr_matrix",
    "render_qr_ascii",
]

# ISO/IEC 18004 Error Correction Level L indicator bits ('01')
_ECC_LEVEL_L_BITS: Final[int] = 0b01
_BCH_FORMAT_POLY: Final[int] = 0x537
_BCH_FORMAT_XOR_MASK: Final[int] = 0x5412
_BCH_VERSION_POLY: Final[int] = 0x1F25
_GF256_PRIMITIVE_POLY: Final[int] = 0x11D

# ISO/IEC 18004 Table 9 — Level L parameters for Versions 1..8:
# version -> (total_data_codewords, ec_codewords_per_block, num_blocks)
_VERSION_LEVEL_L_SPEC: Final[dict[int, tuple[int, int, int]]] = {
    1: (19, 7, 1),    # max 17 bytes in Byte Mode (21x21)
    2: (34, 10, 1),   # max 32 bytes in Byte Mode (25x25)
    3: (55, 15, 1),   # max 53 bytes in Byte Mode (29x29)
    4: (80, 20, 1),   # max 78 bytes in Byte Mode (33x33)
    5: (108, 26, 1),  # max 106 bytes in Byte Mode (37x37)
    6: (136, 18, 2),  # max 134 bytes in Byte Mode (41x41)
    7: (156, 20, 2),  # max 154 bytes in Byte Mode (45x45)
    8: (194, 24, 2),  # max 192 bytes in Byte Mode (49x49)
}

# ISO/IEC 18004 Annex E — Alignment pattern center coordinates for Versions 1..8
_ALIGNMENT_CENTERS: Final[dict[int, tuple[int, ...]]] = {
    1: (),
    2: (6, 18),
    3: (6, 22),
    4: (6, 26),
    5: (6, 30),
    6: (6, 34),
    7: (6, 22, 38),
    8: (6, 24, 42),
}

_MAX_BYTE_MODE_PAYLOAD: Final[int] = 192  # Version 8-L capacity: 194 - 2 header bytes

# Mask penalty weights per ISO/IEC 18004 Section 7.8.3.1
_PENALTY_N1: Final[int] = 3
_PENALTY_N2: Final[int] = 3
_PENALTY_N3: Final[int] = 40
_PENALTY_N4: Final[int] = 10

# ISO/IEC 18004 Section 7.8.2 — Data mask predicates indexed 0..7 in (row, col)
_MASK_FUNCTIONS: Final[tuple[Callable[[int, int], bool], ...]] = (
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: (((r + c) % 2) + ((r * c) % 3)) % 2 == 0,
)


def compute_bch_format_bits(ecc_bits: int, mask: int) -> int:
    """Compute 15-bit BCH(15,5) format information word per ISO/IEC 18004 Annex C."""
    if not (0 <= ecc_bits <= 0b11):
        raise ValueError(f"Invalid ECC indicator bits: {ecc_bits}")
    if not (0 <= mask <= 7):
        raise ValueError(f"Mask index out of range [0, 7]: {mask}")

    data = (ecc_bits << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * _BCH_FORMAT_POLY)
    word = ((data << 10) | rem) ^ _BCH_FORMAT_XOR_MASK
    return word & 0x7FFF


def compute_bch_version_bits(version: int) -> int:
    """Compute 18-bit Golay(18,6) version information word for Versions >= 7."""
    if not (7 <= version <= 40):
        raise ValueError(f"Version info applies only to versions 7..40, got {version}")

    rem = version
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * _BCH_VERSION_POLY)
    return ((version << 12) | rem) & 0x3FFFF


# Precompute and mathematically verify all 8 Level-L format words at import time.
LEVEL_L_FORMAT_WORDS: Final[tuple[int, ...]] = tuple(
    compute_bch_format_bits(_ECC_LEVEL_L_BITS, m) for m in range(8)
)
if LEVEL_L_FORMAT_WORDS[0] != 0x77C4:  # 0b111011111000100
    raise AssertionError(
        f"BCH(15,5) Level-L Mask-0 invariant failed: got {LEVEL_L_FORMAT_WORDS[0]:#06x}"
    )


def _gf256_mul(x: int, y: int) -> int:
    """Multiply two elements in GF(2^8) modulo primitive polynomial 0x11D."""
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * _GF256_PRIMITIVE_POLY)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_generator_poly(degree: int) -> bytes:
    """Build monic Reed-Solomon generator polynomial (excluding leading x^degree term)."""
    poly = bytearray([0] * (degree - 1) + [1])
    root = 1
    for _ in range(degree):
        for j in range(degree):
            poly[j] = _gf256_mul(poly[j], root)
            if j + 1 < degree:
                poly[j] ^= poly[j + 1]
        root = _gf256_mul(root, 0x02)
    return bytes(poly)


def _rs_remainder(data: bytes, divisor: bytes) -> bytes:
    """Compute Reed-Solomon ECC remainder bytes via GF(256) polynomial division."""
    rem = bytearray(len(divisor))
    for byte in data:
        factor = byte ^ rem[0]
        del rem[0]
        rem.append(0)
        if factor:
            for idx, coef in enumerate(divisor):
                rem[idx] ^= _gf256_mul(coef, factor)
    return bytes(rem)


def _encode_byte_mode_codewords(payload: bytes) -> tuple[int, bytes]:
    """Select smallest Version 1..8 (Level L) and build interleaved data+ECC codewords."""
    payload_len = len(payload)
    selected_version = 0
    for ver in range(1, 9):
        data_cw, _, _ = _VERSION_LEVEL_L_SPEC[ver]
        if payload_len <= data_cw - 2:
            selected_version = ver
            break

    if selected_version == 0:
        raise ValueError(
            f"Payload length {payload_len} exceeds Version 8-L capacity ({_MAX_BYTE_MODE_PAYLOAD} bytes)"
        )

    total_data_cw, ec_cw_per_block, num_blocks = _VERSION_LEVEL_L_SPEC[selected_version]
    capacity_bits = total_data_cw * 8

    # Bitstream: Mode 0100 (4 bits) + 8-bit byte length + raw payload bytes
    bits: list[int] = [0, 1, 0, 0]
    for shift in range(7, -1, -1):
        bits.append((payload_len >> shift) & 1)
    for byte in payload:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)

    # Terminator (up to 4 zero bits) + pad to 8-bit codeword boundary
    bits.extend([0] * min(4, capacity_bits - len(bits)))
    if len(bits) % 8 != 0:
        bits.extend([0] * (8 - (len(bits) % 8)))

    data_bytes = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for b in bits[i : i + 8]:
            val = (val << 1) | b
        data_bytes.append(val)

    # Pad alternating 0xEC / 0x11 codewords per ISO/IEC 18004 Section 7.4.9
    pad_seq = (0xEC, 0x11)
    pad_idx = 0
    while len(data_bytes) < total_data_cw:
        data_bytes.append(pad_seq[pad_idx & 1])
        pad_idx += 1

    # Split into blocks, compute Reed-Solomon ECC, and interleave
    divisor = _rs_generator_poly(ec_cw_per_block)
    base_data_len = total_data_cw // num_blocks
    num_short_blocks = num_blocks - (total_data_cw % num_blocks)

    data_blocks: list[bytes] = []
    ecc_blocks: list[bytes] = []
    offset = 0
    for blk_idx in range(num_blocks):
        blk_len = base_data_len + (0 if blk_idx < num_short_blocks else 1)
        blk_data = bytes(data_bytes[offset : offset + blk_len])
        offset += blk_len
        data_blocks.append(blk_data)
        ecc_blocks.append(_rs_remainder(blk_data, divisor))

    interleaved = bytearray()
    max_data_len = max(len(b) for b in data_blocks)
    for col in range(max_data_len):
        for blk_data in data_blocks:
            if col < len(blk_data):
                interleaved.append(blk_data[col])
    for col in range(ec_cw_per_block):
        for blk_ecc in ecc_blocks:
            interleaved.append(blk_ecc[col])

    return selected_version, bytes(interleaved)


def _set_function_module(
    modules: list[list[bool]],
    is_func: list[list[bool]],
    row: int,
    col: int,
    dark: bool,
) -> None:
    modules[row][col] = dark
    is_func[row][col] = True


def _draw_finder_pattern(
    modules: list[list[bool]],
    is_func: list[list[bool]],
    center_row: int,
    center_col: int,
    size: int,
) -> None:
    """Draw 7x7 finder pattern plus 1-module white separator clipped to matrix bounds."""
    for dr in range(-4, 5):
        for dc in range(-4, 5):
            r, c = center_row + dr, center_col + dc
            if 0 <= r < size and 0 <= c < size:
                dist = max(abs(dr), abs(dc))
                _set_function_module(modules, is_func, r, c, dist not in (2, 4))


def _draw_alignment_pattern(
    modules: list[list[bool]],
    is_func: list[list[bool]],
    center_row: int,
    center_col: int,
) -> None:
    """Draw 5x5 alignment pattern centered at (center_row, center_col)."""
    for dr in range(-2, 3):
        for dc in range(-2, 3):
            dist = max(abs(dr), abs(dc))
            _set_function_module(modules, is_func, center_row + dr, center_col + dc, dist != 1)


def _draw_format_bits(
    modules: list[list[bool]],
    is_func: list[list[bool]],
    size: int,
    mask: int,
) -> None:
    """Place both copies of the 15-bit format word plus the fixed dark module."""
    bits = LEVEL_L_FORMAT_WORDS[mask]

    # Copy 1: around top-left finder pattern
    for i in range(6):
        _set_function_module(modules, is_func, i, 8, bool((bits >> i) & 1))
    _set_function_module(modules, is_func, 7, 8, bool((bits >> 6) & 1))
    _set_function_module(modules, is_func, 8, 8, bool((bits >> 7) & 1))
    _set_function_module(modules, is_func, 8, 7, bool((bits >> 8) & 1))
    for i in range(9, 15):
        _set_function_module(modules, is_func, 8, 14 - i, bool((bits >> i) & 1))

    # Copy 2: top-right horizontal strip and bottom-left vertical strip
    for i in range(8):
        _set_function_module(modules, is_func, 8, size - 1 - i, bool((bits >> i) & 1))
    for i in range(8, 15):
        _set_function_module(modules, is_func, size - 15 + i, 8, bool((bits >> i) & 1))

    # Fixed dark module at (row = 4 * V + 9 = size - 8, col = 8)
    _set_function_module(modules, is_func, size - 8, 8, True)


def _draw_version_bits(
    modules: list[list[bool]],
    is_func: list[list[bool]],
    version: int,
    size: int,
) -> None:
    """Place both 6x3 / 3x6 Golay(18,6) version blocks for Versions >= 7."""
    if version < 7:
        return
    bits = compute_bch_version_bits(version)
    for i in range(18):
        bit = bool((bits >> i) & 1)
        a = size - 11 + (i % 3)
        b = i // 3
        _set_function_module(modules, is_func, b, a, bit)  # Top-right 6x3 block
        _set_function_module(modules, is_func, a, b, bit)  # Bottom-left 3x6 block


def _place_codewords_zigzag(
    modules: list[list[bool]],
    is_func: list[list[bool]],
    codewords: bytes,
    size: int,
) -> None:
    """Place interleaved data+ECC bits in upward/downward 2-column zigzag order."""
    bit_idx = 0
    total_bits = len(codewords) * 8

    for right_base in range(size - 1, 0, -2):
        right = right_base - 1 if right_base <= 6 else right_base
        upward = ((right + 1) & 2) == 0
        for vert in range(size):
            row = (size - 1 - vert) if upward else vert
            for offset in range(2):
                col = right - offset
                if not is_func[row][col] and bit_idx < total_bits:
                    byte_val = codewords[bit_idx >> 3]
                    modules[row][col] = bool((byte_val >> (7 - (bit_idx & 7))) & 1)
                    bit_idx += 1


def _finder_penalty_count(history: deque[int], size: int) -> int:
    n = history[1]
    if n <= 0 or n > size * 3:
        return 0
    core = (history[2] == history[4] == history[5] == n) and (history[3] == n * 3)
    if not core:
        return 0
    matches = 0
    if history[0] >= n * 4 and history[6] >= n:
        matches += 1
    if history[6] >= n * 4 and history[0] >= n:
        matches += 1
    return matches


def _finder_penalty_push(run_len: int, history: deque[int], size: int) -> None:
    if history[0] == 0:
        run_len += size
    history.appendleft(run_len)


def _finder_penalty_finish(
    run_color: bool, run_len: int, history: deque[int], size: int
) -> int:
    if run_color:
        _finder_penalty_push(run_len, history, size)
        run_len = 0
    run_len += size
    _finder_penalty_push(run_len, history, size)
    return _finder_penalty_count(history, size)


def _compute_penalty_score(modules: list[list[bool]]) -> int:
    """Evaluate all 4 ISO/IEC 18004 mask penalty rules (N1..N4)."""
    size = len(modules)
    score = 0

    # N1 & N3 along rows
    for r in range(size):
        run_color = False
        run_len = 0
        history: deque[int] = deque([0] * 7, maxlen=7)
        row = modules[r]
        for c in range(size):
            if row[c] == run_color:
                run_len += 1
                if run_len == 5:
                    score += _PENALTY_N1
                elif run_len > 5:
                    score += 1
            else:
                _finder_penalty_push(run_len, history, size)
                if not run_color:
                    score += _finder_penalty_count(history, size) * _PENALTY_N3
                run_color = row[c]
                run_len = 1
        score += _finder_penalty_finish(run_color, run_len, history, size) * _PENALTY_N3

    # N1 & N3 along columns
    for c in range(size):
        run_color = False
        run_len = 0
        history = deque([0] * 7, maxlen=7)
        for r in range(size):
            cell = modules[r][c]
            if cell == run_color:
                run_len += 1
                if run_len == 5:
                    score += _PENALTY_N1
                elif run_len > 5:
                    score += 1
            else:
                _finder_penalty_push(run_len, history, size)
                if not run_color:
                    score += _finder_penalty_count(history, size) * _PENALTY_N3
                run_color = cell
                run_len = 1
        score += _finder_penalty_finish(run_color, run_len, history, size) * _PENALTY_N3

    # N2: 2x2 solid-color blocks
    for r in range(size - 1):
        row_cur = modules[r]
        row_nxt = modules[r + 1]
        for c in range(size - 1):
            if row_cur[c] == row_cur[c + 1] == row_nxt[c] == row_nxt[c + 1]:
                score += _PENALTY_N2

    # N4: Dark/light module ratio balance
    dark_modules = sum(cell for row in modules for cell in row)
    total_modules = size * size
    k = (abs(dark_modules * 20 - total_modules * 10) + total_modules - 1) // total_modules - 1
    score += k * _PENALTY_N4
    return score


def _truncate_utf8_bytes(text: str, max_bytes: int) -> bytes:
    """Encode UTF-8 and safely truncate at character boundary if exceeding max_bytes."""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return raw
    return raw[:max_bytes].decode("utf-8", errors="ignore").encode("utf-8")


def encode_qr_matrix(text: str) -> list[list[bool]]:
    """Encode *text* into an ISO/IEC 18004 QR Code matrix (True = dark, False = light).

    Uses Byte Mode (0100) and Error Correction Level L across Versions 1..8
    (up to 192 UTF-8 bytes; gracefully truncates on valid UTF-8 boundary if longer).
    Evaluates all 8 ISO/IEC 18004 masks and returns the minimum-penalty matrix.
    """
    payload = _truncate_utf8_bytes(text, _MAX_BYTE_MODE_PAYLOAD)
    version, codewords = _encode_byte_mode_codewords(payload)
    size = 17 + 4 * version

    base_modules = [[False] * size for _ in range(size)]
    is_func = [[False] * size for _ in range(size)]

    # 1. Timing patterns on row 6 and column 6
    for i in range(size):
        _set_function_module(base_modules, is_func, 6, i, i % 2 == 0)
        _set_function_module(base_modules, is_func, i, 6, i % 2 == 0)

    # 2. Three 7x7 finder patterns + separators
    _draw_finder_pattern(base_modules, is_func, 3, 3, size)
    _draw_finder_pattern(base_modules, is_func, 3, size - 4, size)
    _draw_finder_pattern(base_modules, is_func, size - 4, 3, size)

    # 3. Alignment patterns for Version >= 2
    centers = _ALIGNMENT_CENTERS[version]
    num_centers = len(centers)
    finder_corners = {(0, 0), (0, num_centers - 1), (num_centers - 1, 0)}
    for r_idx in range(num_centers):
        for c_idx in range(num_centers):
            if (r_idx, c_idx) not in finder_corners:
                _draw_alignment_pattern(
                    base_modules, is_func, centers[r_idx], centers[c_idx]
                )

    # 4. Reserve format & version metadata zones
    _draw_format_bits(base_modules, is_func, size, 0)
    _draw_version_bits(base_modules, is_func, version, size)

    # 5. Place data + Reed-Solomon ECC codewords
    _place_codewords_zigzag(base_modules, is_func, codewords, size)

    # 6. Evaluate all 8 ISO/IEC 18004 masks and select lowest penalty score
    best_matrix: list[list[bool]] | None = None
    best_score = sys.maxsize

    for mask_id, mask_fn in enumerate(_MASK_FUNCTIONS):
        candidate = [row[:] for row in base_modules]
        for r in range(size):
            func_row = is_func[r]
            cand_row = candidate[r]
            for c in range(size):
                if not func_row[c] and mask_fn(r, c):
                    cand_row[c] = not cand_row[c]
        _draw_format_bits(candidate, is_func, size, mask_id)
        penalty = _compute_penalty_score(candidate)
        if penalty < best_score:
            best_score = penalty
            best_matrix = candidate

    assert best_matrix is not None
    return best_matrix


def render_qr_ascii(
    text: str,
    indent: str = "   ",
    *,
    quiet_zone: int = 2,
    invert: bool = True,
) -> str:
    """Render *text* as a compact Unicode half-block QR string for terminal display.

    By default (*invert=True*), light modules and the 2-module quiet zone are drawn
    using foreground blocks ('█', '▀', '▄') and dark QR modules use terminal background
    spaces (' '). On dark terminals this produces a true standard-polarity
    black-on-white QR code card that iPhone and Android cameras scan instantaneously.
    """
    if quiet_zone < 0:
        raise ValueError(f"quiet_zone must be >= 0, got {quiet_zone}")

    matrix = encode_qr_matrix(text)
    size = len(matrix)

    # Index lookup: bit0 = top_dark, bit1 = bottom_dark
    # Normal (light-theme): 0->' ', 1->'▀', 2->'▄', 3->'█'
    # Dark-terminal default (invert=True): 0->'█', 1->'▄', 2->'▀', 3->' '
    glyphs = ("█", "▄", "▀", " ") if invert else (" ", "▀", "▄", "█")

    def _module_is_dark(r: int, c: int) -> int:
        # Beyond bottom quiet-zone edge on odd row count: match terminal background
        if invert and quiet_zone > 0 and (r >= size + quiet_zone or c >= size + quiet_zone):
            return 1
        if r < 0 or c < 0 or r >= size or c >= size:
            return 0
        return 1 if matrix[r][c] else 0

    lines: list[str] = []
    start = -quiet_zone
    stop = size + quiet_zone
    for r in range(start, stop, 2):
        row_chars = [
            glyphs[_module_is_dark(r, c) | (_module_is_dark(r + 1, c) << 1)]
            for c in range(start, stop)
        ]
        lines.append(f"{indent}{''.join(row_chars)}")

    return "\n".join(lines)


if __name__ == "__main__":
    sample_url = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "https://example.trycloudflare.com#pin=123456"
    )
    print(render_qr_ascii(sample_url))
