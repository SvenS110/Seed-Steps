"""Rendering helpers for CLI output formatting and coloring."""

from __future__ import annotations

from seed_steps import terminal_style as ts


COLOR_RESET = "\033[0m"
COLOR_ENTROPY = "\033[96m"
COLOR_CHECKSUM = "\033[95m"

MEETUP_PHASE_SEPARATOR = (
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
)


def _colorize(value: str, color: str, *, enable: bool = True) -> str:
    if not enable or not ts.is_enabled():
        return value
    return f"{color}{value}{COLOR_RESET}"


def _color_segmented_bits(bits: str, *, bit_offset: int, entropy_bits_len: int) -> str:
    rendered: list[str] = []
    for idx, bit in enumerate(bits):
        absolute = bit_offset + idx
        if absolute < entropy_bits_len:
            rendered.append(_colorize(bit, COLOR_ENTROPY))
        else:
            rendered.append(_colorize(bit, COLOR_CHECKSUM))
    return "".join(rendered)


def _format_segmented_bits_multiline(
    bits: str, *, entropy_bits_len: int, bytes_per_line: int = 8
) -> str:
    line_size = max(1, bytes_per_line) * 8
    lines: list[str] = []
    for start in range(0, len(bits), line_size):
        line_bits = bits[start : start + line_size]
        groups: list[str] = []
        for i in range(0, len(line_bits), 8):
            chunk = line_bits[i : i + 8]
            groups.append(
                _color_segmented_bits(
                    chunk,
                    bit_offset=start + i,
                    entropy_bits_len=entropy_bits_len,
                )
            )
        lines.append(" ".join(groups))
    return "\n".join(lines)


def format_bits_by_byte(bits: str, *, bytes_per_line: int = 8) -> str:
    chunks = [bits[index : index + 8] for index in range(0, len(bits), 8)]
    line_size = max(1, bytes_per_line)
    lines = [
        " ".join(chunks[index : index + line_size])
        for index in range(0, len(chunks), line_size)
    ]
    return "\n".join(lines)


def _colorize_bit_prefix(bits: str, *, prefix_len: int, color: str) -> str:
    if prefix_len <= 0:
        return bits
    start_idx: int | None = None
    end_idx: int | None = None
    bit_count = 0
    for idx, ch in enumerate(bits):
        if ch not in {"0", "1"}:
            continue
        bit_count += 1
        if start_idx is None:
            start_idx = idx
        end_idx = idx
        if bit_count == prefix_len:
            break

    if start_idx is None or end_idx is None:
        return bits

    prefix_segment = bits[start_idx : end_idx + 1]
    return f"{bits[:start_idx]}{_colorize(prefix_segment, color)}{bits[end_idx + 1 :]}"


def _colorized_11_bit_block(block: str, start_bit: int, entropy_bits_len: int) -> str:
    end_bit = start_bit + len(block)
    entropy_part_len = max(0, min(entropy_bits_len, end_bit) - start_bit)
    checksum_part_len = len(block) - entropy_part_len
    entropy_part = block[:entropy_part_len]
    checksum_part = block[entropy_part_len : entropy_part_len + checksum_part_len]
    return (
        f"{_colorize(entropy_part, COLOR_ENTROPY)}"
        f"{_colorize(checksum_part, COLOR_CHECKSUM)}"
    )


def _colorize_checksum_suffix(bits: str, checksum_suffix_len: int) -> str:
    if checksum_suffix_len <= 0:
        return bits
    if checksum_suffix_len >= len(bits):
        return _colorize(bits, COLOR_CHECKSUM)
    prefix = bits[:-checksum_suffix_len]
    suffix = bits[-checksum_suffix_len:]
    return f"{prefix}{_colorize(suffix, COLOR_CHECKSUM)}"


def _colorize_checksum_by_global_position(
    text: str,
    *,
    bit_offset: int,
    entropy_bits_len: int,
    checksum_color: str = COLOR_CHECKSUM,
) -> str:
    rendered: list[str] = []
    bit_index = 0
    for char in text:
        if char in {"0", "1"}:
            absolute = bit_offset + bit_index
            if absolute >= entropy_bits_len:
                rendered.append(_colorize(char, checksum_color))
            else:
                rendered.append(char)
            bit_index += 1
        else:
            rendered.append(char)
    return "".join(rendered)


def _print_meetup_text_block(lines: list[str]) -> None:
    print()
    for line in lines:
        print(line)


def _print_meetup_intro_without_title(lines: list[str], title: str) -> None:
    intro_lines = lines
    if lines and lines[0].strip() == title.strip():
        intro_lines = lines[1:]
    _print_meetup_text_block(intro_lines)


def _print_meetup_phase_title(title: str) -> None:
    print()
    print(ts.bright_white(title))
    print(MEETUP_PHASE_SEPARATOR)
    print()
