"""Tamariz meetup renderer helpers (phase-specific)."""

from __future__ import annotations

from seed_steps import terminal_style as ts
from seed_steps.explanations import (
    PHASE_A_ENDIAN_NOTES,
    PHASE_A_INTRO,
    PHASE_A_NOTES,
    PHASE_B_INTRO,
    PHASE_B_PBKDF2,
    PHASE_B_STEPS,
    PHASE_C_IL_IR,
    PHASE_C_IL_IR_ENDIAN_NOTES,
    PHASE_C_INTRO,
    PHASE_C_SERIALIZATION_NOTES,
    PHASE_C_STEPS,
)
from seed_steps.rendering import (
    COLOR_CHECKSUM,
    COLOR_IL,
    COLOR_IR,
    COLOR_SEED,
    COLOR_XPRV,
    COLOR_XPUB,
    _colorize,
    _colorize_bit_prefix,
    _colorize_checksum_by_global_position,
    _print_meetup_intro_without_title,
    _print_meetup_phase_title,
    _print_meetup_text_block,
    format_bits_by_byte,
    format_long_hex,
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


def render_tamariz_phase_b_seed(
    *,
    mnemonic: str,
    passphrase_display: str,
    salt: str,
    mnemonic_bytes_len: int,
    u_values: list[bytes],
    seed_display: str,
    color_word: str,
    color_passphrase: str,
    color_seed: str,
) -> None:
    _print_meetup_phase_title("Fase B — BIP39: de palabras a seed")
    _print_meetup_intro_without_title(
        PHASE_B_INTRO, "Fase B — BIP39: de palabras a seed"
    )
    _print_meetup_text_block(PHASE_B_PBKDF2)
    print()
    print(ts.bright_white(PHASE_B_STEPS["1_6"]))
    print(f"- Idea: fijar entrada textual del KDF.")
    print(f"- Datos: mnemonic = {_colorize(mnemonic, color_word)}")
    print("- Resultado: input listo para normalizar.")
    print()
    print(ts.bright_white(PHASE_B_STEPS["2_6"]))
    print("- Idea: canonizar Unicode para resultado determinista.")
    print(f"- Datos: len(password_nfkd) = {mnemonic_bytes_len} bytes")
    print("- Cálculo: password = NFKD(mnemonic).encode('utf-8')")
    print("- Resultado: password preparado para PBKDF2.")
    print()
    print(ts.bright_white(PHASE_B_STEPS["3_6"]))
    print("- Idea: aplicar segundo factor opcional.")
    print(f"- Datos: passphrase = {_colorize(passphrase_display, color_passphrase)}")
    print("- Resultado: passphrase normalizada.")
    print()
    print(ts.bright_white(PHASE_B_STEPS["4_6"]))
    print("- Idea: construir salt de dominio BIP39.")
    print(f"- Datos: salt = {_colorize(salt, color_passphrase)}")
    print("- Cálculo: salt = 'mnemonic' + NFKD(passphrase)")
    print("- Resultado: salt listo para PBKDF2.")
    print()
    print(ts.bright_white(PHASE_B_STEPS["5_6"]))
    print("- Idea: endurecer derivación con 2048 iteraciones.")
    print("- Datos: PBKDF2-HMAC-SHA512, iterations=2048, dklen=64")
    print("- Cálculo: U_1, U_2, U_3, ..., U_2046, U_2047, U_2048; T_1 = XOR(U_i)")
    print()
    print("Desarrollo")
    print(ts.bright_white("- iteracion 0001 -> U_1:"))
    print(format_long_hex(u_values[0].hex(), groups_per_line=2))
    print(ts.bright_white("- iteracion 0002 -> U_2:"))
    print(format_long_hex(u_values[1].hex(), groups_per_line=2))
    print(ts.bright_white("- iteracion 0003 -> U_3:"))
    print(format_long_hex(u_values[2].hex(), groups_per_line=2))
    print(ts.bright_white("- ..."))
    print(ts.bright_white("- 2042 iteraciones intermedias omitidas"))
    print(ts.bright_white("- ..."))
    print(ts.bright_white("- iteracion 2046 -> U_2046:"))
    print(format_long_hex(u_values[2045].hex(), groups_per_line=2))
    print(ts.bright_white("- iteracion 2047 -> U_2047:"))
    print(format_long_hex(u_values[2046].hex(), groups_per_line=2))
    print(ts.bright_white("- iteracion 2048 -> U_2048:"))
    print(format_long_hex(u_values[2047].hex(), groups_per_line=2))
    print(f"- {ts.formula('T_1 = U_1 XOR U_2 XOR ... XOR U_2048')}")
    print("- Resultado: bloque T_1 consolidado.")
    print()
    print(ts.bright_white(PHASE_B_STEPS["6_6"]))
    print("- Idea: entregar la semilla final para BIP32.")
    print(f"- Datos: seed_hex = {_colorize(seed_display, color_seed)}")
    print("- Resultado: seed final de 64 bytes.")


def render_tamariz_phase_c_master(
    *,
    seed_hex: str,
    hmac_hex: str,
    il_hex: str,
    ir_hex: str,
    master_xprv_display: str,
    master_xpub: str,
) -> None:
    _print_meetup_phase_title("Fase C — BIP32: de seed a nodo maestro")
    _print_meetup_intro_without_title(
        PHASE_C_INTRO, "Fase C — BIP32: de seed a nodo maestro"
    )
    _print_meetup_text_block(PHASE_C_IL_IR)
    print()
    print(ts.bright_white(PHASE_C_STEPS["1_4"]))
    print(f"- Idea: usar la seed como material raíz.")
    print(f"- Datos: seed = {_colorize(seed_hex, COLOR_SEED)}")
    print("- Resultado: entrada lista para HMAC BIP32.")
    print()
    print(ts.bright_white(PHASE_C_STEPS["2_4"]))
    print("- Idea: generar I de 64 bytes con clave fija de dominio.")
    print(f"- Datos: hmac_key = 'Bitcoin seed'")
    print(f"- Cálculo: I = HMAC-SHA512(key='Bitcoin seed', data=seed)")
    print(f"- Resultado: I = {_colorize(hmac_hex, COLOR_CHECKSUM)}")
    print()
    print(ts.bright_white(PHASE_C_STEPS["3_4"]))
    print("- Idea: separar secreto y chain code.")
    print(f"- Datos: I = IL || IR")
    print(f"- Resultado: IL = {_colorize(il_hex, COLOR_IL)}")
    print(f"- Resultado: IR = {_colorize(ir_hex, COLOR_IR)}")
    for note in PHASE_C_IL_IR_ENDIAN_NOTES:
        print(f"- {note}")
    print()
    print(ts.bright_white(PHASE_C_STEPS["4_4"]))
    print("- Idea: construir nodo maestro serializable.")
    print("- xprv master = " + _colorize(master_xprv_display, COLOR_XPRV))
    print(f"- xpub master = {_colorize(master_xpub, COLOR_XPUB)}")
    for note in PHASE_C_SERIALIZATION_NOTES:
        print(f"- {note}")
    print("- Resultado: nodo maestro listo para derivación HD.")
