"""Tamariz meetup renderer helpers (phase-specific)."""

from __future__ import annotations

from seed_steps import terminal_style as ts
from seed_steps.explanations import PHASE_A_ENDIAN_NOTES, PHASE_A_INTRO, PHASE_A_NOTES
from seed_steps.rendering import (
    COLOR_CHECKSUM,
    _colorize,
    _colorize_bit_prefix,
    _colorize_checksum_by_global_position,
    _print_meetup_intro_without_title,
    _print_meetup_phase_title,
    format_bits_by_byte,
)


def render_tamariz_phase_a(
    breakdown,
    *,
    source_label: str,
    selected_entropy_bits: int | None,
    pause_between_steps: bool,
) -> str:
    phase_title = "Fase A — BIP39: de entropía a palabras"
    _print_meetup_intro_without_title(PHASE_A_INTRO, phase_title)
    ent = len(breakdown.entropy_bits)
    cs = len(breakdown.checksum_bits)
    words = breakdown.mnemonic.split()
    grouped_words = [" ".join(words[i : i + 4]) for i in range(0, len(words), 4)]

    _print_meetup_phase_title(phase_title)

    print(ts.bright_white("BIP39 1/5 — Entropía"))
    print("- Idea: identificar la fuente y la longitud de entropía.")
    print("- Datos:")
    print(f"  - origen = {source_label}")
    if selected_entropy_bits is not None:
        print(f"  - bits_entropia = {selected_entropy_bits}")
    print(f"  - ENT = {ent} bits")
    print("  - entropy_bits:")
    print(
        "    "
        + format_bits_by_byte(breakdown.entropy_bits, bytes_per_line=4).replace(
            "\n", "\n    "
        )
    )
    print(f"  - entropy_hex = {breakdown.entropy_hex}")
    print("- Resultado: entropía lista para checksum.")

    print()

    print(ts.bright_white("BIP39 2/5 — Checksum"))
    print("- Idea: agregar bits de control para detectar errores.")
    print("- Datos:")
    print(f"  - SHA256(entropy) = {breakdown.sha256_hex}")
    print("  - SHA256(entropy)_bits:")
    sha256_bits = bin(int(breakdown.sha256_hex, 16))[2:].zfill(256)
    sha256_bits_grouped = format_bits_by_byte(sha256_bits, bytes_per_line=4)
    print(
        "    "
        + _colorize_bit_prefix(
            sha256_bits_grouped,
            prefix_len=cs,
            color=COLOR_CHECKSUM,
        ).replace("\n", "\n    ")
    )
    print("- Cálculo: CS = ENT/32")
    print(f"- CS = ENT/32 = {cs} bits")
    print(f"- checksum = {_colorize(breakdown.checksum_bits, COLOR_CHECKSUM)}")
    print("- Resultado: checksum anexable a la entropía.")

    print()

    print(ts.bright_white("BIP39 3/5 — Entropía + checksum"))
    print("- Idea: crear el flujo binario total que define las palabras.")
    print("- Datos:")
    print("  - entropy_bits:")
    print(
        "  "
        + format_bits_by_byte(breakdown.entropy_bits, bytes_per_line=4).replace(
            "\n", "\n  "
        )
    )
    print(f"  - checksum_bits = {_colorize(breakdown.checksum_bits, COLOR_CHECKSUM)}")
    print("- Cálculo: entropy_plus_checksum = entropy_bits || checksum_bits")
    print(f"- total_bits = ENT + CS = {ent + cs}")
    print("- entropy_plus_checksum (agrupado por bytes):")
    full_bits = breakdown.entropy_plus_checksum_bits
    grouped_lines = format_bits_by_byte(full_bits, bytes_per_line=4).splitlines()
    rendered_lines: list[str] = []
    for line_index, line in enumerate(grouped_lines):
        line_start = line_index * 32
        rendered_lines.append(
            _colorize_checksum_by_global_position(
                line,
                bit_offset=line_start,
                entropy_bits_len=len(breakdown.entropy_bits),
                checksum_color=COLOR_CHECKSUM,
            )
        )
    print("  " + "\n  ".join(rendered_lines))
    print("- Resultado: cadena lista para dividir en bloques de 11 bits.")

    print()

    print(ts.bright_white("BIP39 4/5 — Bloques de 11 bits"))
    print("- Idea: cada bloque de 11 bits representa un índice BIP39.")
    print("- Explicación: 2048 = 2^11, por eso 11 bits cubren toda la wordlist.")
    print("- Datos:")
    print(f"- bloques_11 = {len(breakdown.bit_blocks)}")
    print()
    print("Desarrollo")
    for pos, block in enumerate(breakdown.bit_blocks, start=1):
        start_bit = (pos - 1) * 11
        colored_block = _colorize_checksum_by_global_position(
            block,
            bit_offset=start_bit,
            entropy_bits_len=len(breakdown.entropy_bits),
            checksum_color=COLOR_CHECKSUM,
        )
        print(f"- bloque[{pos:02d}] = {colored_block}")
    print("- Resultado: índices listos para mapear a palabras.")

    print()

    print(ts.bright_white("BIP39 5/5 — Índices y palabras"))
    print("- Idea: traducir índices a palabras humanas.")
    print("- Explicación: checksum detecta errores, NO corrige automáticamente.")
    print()
    print("Desarrollo")
    print("pos | bloque(11-bit) | indice | palabra")
    print("----+----------------+--------+----------")
    for pos, step in enumerate(breakdown.steps, start=1):
        start_bit = (pos - 1) * 11
        colored_block = _colorize_checksum_by_global_position(
            step.bit_block,
            bit_offset=start_bit,
            entropy_bits_len=len(breakdown.entropy_bits),
            checksum_color=COLOR_CHECKSUM,
        )
        print(f"{pos:>3} | {colored_block} | {step.index:>6} | {ts.orange(step.word)}")
    for note in PHASE_A_ENDIAN_NOTES:
        print(f"- {note}")
    print("- mnemotécnica:")
    for line in grouped_words:
        print("  " + " ".join(ts.orange(word) for word in line.split()))
    for note in PHASE_A_NOTES:
        print(f"- {note}")

    if not pause_between_steps:
        return "continue"
    return "continue"
