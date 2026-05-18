"""CLI entrypoint for Seed Steps educational BIP39 walkthrough."""

from __future__ import annotations

import argparse
import hmac
import hashlib
import sys
from importlib.resources import as_file, files
from pathlib import Path

from seed_steps.bip32 import (
    HARDENED_OFFSET,
    MAINNET_XPRV_VERSION,
    MAINNET_XPUB_VERSION,
    compressed_pubkey_from_private_key,
    derive_p2wpkh_address_from_node,
    derive_bip32_master_node,
    derive_bip32_node_from_master,
    derive_bip32_path_from_node,
    parse_bip32_path,
    serialize_bip84_extended_keys,
)
from seed_steps.bip39 import build_bip39_breakdown, load_wordlist
from seed_steps.entropy import generate_entropy, parse_entropy_hex
from seed_steps.format import group_binary
from seed_steps.seed import (
    build_bip39_seed_salt,
    derive_bip39_seed,
    normalize_bip39_text,
)
from seed_steps import terminal_style as ts
from seed_steps.rendering import (
    COLOR_CHECKSUM,
    COLOR_ENTROPY,
    _color_segmented_bits,
    _colorize,
    _colorize_bit_prefix,
    _colorize_checksum_by_global_position,
    _colorized_11_bit_block,
    _format_segmented_bits_multiline,
    _print_meetup_intro_without_title,
    _print_meetup_phase_title,
    _print_meetup_text_block,
)
from seed_steps.explanations import (
    MEETUP_INTRO,
    PHASE_A_ENDIAN_NOTES,
    PHASE_A_INTRO,
    PHASE_A_NOTES,
    PHASE_BIG_LITTLE_ENDIAN_NOTE,
    PHASE_B_INTRO,
    PHASE_B_PBKDF2,
    PHASE_B_STEPS,
    PHASE_C_INTRO,
    PHASE_C_IL_IR_ENDIAN_NOTES,
    PHASE_C_IL_IR,
    PHASE_C_SERIALIZATION_NOTES,
    PHASE_C_STEPS,
    PHASE_D_CKDPRIV_ENDIAN_NOTES,
    PHASE_D_INTRO,
    PHASE_D_HARDENED,
    PHASE_D_STEPS,
    PHASE_E_INTRO,
    PHASE_E_HASH160,
    PHASE_E_STEPS,
    PHASE_F_SUMMARY,
)
from seed_steps.trace import MathTrace


class UserCancelledFlow(Exception):
    """Sentinel for user-driven cancellation in wizard substeps."""


def _error_message(error_type: str, cause: str, guide: str) -> str:
    return f"ERROR {error_type}: {cause}. Accion sugerida: {guide}."


def _mask_sensitive(value: str) -> str:
    if not value:
        return "(vacio)"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    if len(value) <= 16:
        return f"{value[:4]}...{value[-4:]} [sha256:{digest}]"
    return f"{value[:8]}...{value[-8:]} [sha256:{digest}]"


def _display_sensitive(value: str, *, show_secrets: bool) -> str:
    if show_secrets:
        return value
    return _mask_sensitive(value)


def _print_secrets_warning() -> None:
    print(
        "ADVERTENCIA DE SEGURIDAD: --show-secrets expone material sensible en terminal, logs e historial."
    )
    print("NO uses semillas o claves reales en este modo.")


COLOR_WORD = "\033[38;5;208m"
COLOR_PASSPHRASE = "\033[95m"
COLOR_SEED = "\033[93m"
COLOR_IL = "\033[94m"
COLOR_IR = "\033[35m"
COLOR_XPRV = "\033[91m"
COLOR_XPUB = "\033[36m"
COLOR_FINAL_ADDRESS = "\033[92m"


def _format_bits_multiline(bits: str, *, bytes_per_line: int = 8) -> str:
    chunks = [bits[index : index + 8] for index in range(0, len(bits), 8)]
    line_size = max(1, bytes_per_line)
    lines = [
        " ".join(chunks[index : index + line_size])
        for index in range(0, len(chunks), line_size)
    ]
    return "\n".join(lines)


def format_hex_bytes(
    data: bytes, *, bytes_per_group: int = 4, groups_per_line: int = 4
) -> str:
    return format_long_hex(
        data.hex(),
        hex_per_group=bytes_per_group * 2,
        groups_per_line=groups_per_line,
    )


def format_bits_by_byte(bits: str, *, bytes_per_line: int = 8) -> str:
    return _format_bits_multiline(bits, bytes_per_line=bytes_per_line)


def format_long_hex(
    value: str, *, hex_per_group: int = 8, groups_per_line: int = 4
) -> str:
    chunks = [
        value[index : index + hex_per_group]
        for index in range(0, len(value), hex_per_group)
    ]
    lines = [
        " ".join(chunks[index : index + groups_per_line])
        for index in range(0, len(chunks), groups_per_line)
    ]
    return "\n".join(lines)


def format_key_material(label: str, value: str, *, color: str | None = None) -> str:
    rendered = value if color is None else _colorize(value, color)
    return f"{label} = {rendered}"


def format_derivation_path(path: str) -> str:
    return " -> ".join(token for token in path.split("/") if token)


def _print_substep_section(title: str) -> None:
    print()
    print(ts.bright_white(title))


def _print_substep_header(phase: int, index: int, total: int, name: str) -> None:
    print(f"\n{ts.dim('━' * 88)}")
    print(ts.bright_white(f"Subpaso {index}/{total} — {name}"))


def _print_substep_sections(
    *,
    objective: list[str],
    what_is: list[str],
    why: list[str],
    inputs: list[str],
    math: list[str],
    substitution: list[str],
    development: list[str],
    result: list[str],
    next_step: list[str],
) -> None:
    def _print_bullet(item: str) -> None:
        lines = item.splitlines() or [""]
        print(f"- {lines[0]}")
        for continuation in lines[1:]:
            print(f"    {continuation}")

    sections = [
        ("Objetivo", objective),
        ("Que es", what_is),
        ("Por que importa", why),
        ("Datos de entrada", inputs),
        ("Matematica", math),
        ("Sustitucion", substitution),
        ("Desarrollo", development),
        ("Resultado", result),
        ("Siguiente paso", next_step),
    ]
    for title, items in sections:
        _print_substep_section(title)
        for item in items:
            _print_bullet(item)


def _as_multiline_block(label: str, value: str) -> str:
    indented_value = "\n".join(f"    {line}" for line in value.splitlines())
    return f"{label}:\n{indented_value}"


def _print_raw_summary_block(
    *,
    mnemonic: str,
    passphrase: str,
    path: str,
    network: str,
    seed_bytes: bytes,
    master,
    derived,
    final_addr,
) -> None:
    print()
    print("mnemonic=" + mnemonic)
    print("passphrase=" + passphrase)
    print("path=" + path)
    print("network=" + network)
    print("seed=" + seed_bytes.hex())
    print("il_master=" + master.master_private_key.hex())
    print("ir_master=" + master.chain_code.hex())
    print("xprv_master=" + master.xprv)
    print("xpub_master=" + master.xpub)
    print("xprv_derived=" + derived.xprv)
    print("xpub_derived=" + derived.xpub)
    print("address=" + final_addr.address)


def _pbkdf2_u_sequence(
    password: bytes, salt: bytes, iterations: int = 2048
) -> list[bytes]:
    u_values: list[bytes] = []
    block_index = (1).to_bytes(4, "big")
    u = hmac.new(password, salt + block_index, hashlib.sha512).digest()
    u_values.append(u)
    for _ in range(1, iterations):
        u = hmac.new(password, u, hashlib.sha512).digest()
        u_values.append(u)
    return u_values


def _prompt_micro_operation(
    *,
    number: int,
    input_data: str,
    operation: str,
    output_data: str,
    enable: bool,
) -> None:
    if not enable:
        return
    print(f"\nMicro-operacion {number}")
    print(f"- Entrada:   {input_data}")
    print(f"- Operacion: {operation}")
    print(f"- Salida:    {output_data}")
    input("ENTER para ejecutar micro-operacion...")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seed-steps",
        description="Educational BIP39 walkthrough from entropy to 12-word mnemonic.",
    )
    parser.add_argument(
        "--entropy",
        type=str,
        help="Hex entropy (128/160/192/224/256 bits). If omitted, generates 128-bit entropy.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Compact output with only key metrics and final mnemonic.",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Renderiza una vista educativa por paneles (read-only) del pipeline completo.",
    )
    parser.add_argument(
        "--interactive",
        "--wizard",
        dest="interactive",
        action="store_true",
        help="Inicia un asistente interactivo paso a paso.",
    )
    parser.add_argument(
        "--tamariz",
        action="store_true",
        help="Modo meetup: wizard condensado con decisiones interactivas y menos pausas.",
    )
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="En wizard, desactiva pausas y confirmaciones entre pasos.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Desactiva colores ANSI en toda la salida.",
    )
    parser.add_argument(
        "--mnemonic",
        type=str,
        help="Mnemotecnica explicita para derivar seed BIP39.",
    )
    parser.add_argument(
        "--passphrase",
        type=str,
        default="",
        help="Passphrase opcional BIP39 (se normaliza NFKD).",
    )
    parser.add_argument(
        "--derive-seed",
        action="store_true",
        help="Deriva seed BIP39 desde mnemotecnica (explicativo).",
    )
    parser.add_argument(
        "--derive-bip32",
        action="store_true",
        help="Deriva master key BIP32 (xprv/xpub) desde seed disponible.",
    )
    parser.add_argument(
        "--path",
        type=str,
        help="Ruta HD BIP32 desde la master key (ej: m/84'/0'/0'/0/0).",
    )
    parser.add_argument(
        "--path-steps",
        action="store_true",
        help="Muestra derivacion por niveles para la ruta HD indicada.",
    )
    parser.add_argument(
        "--network",
        type=str,
        default="mainnet",
        choices=["mainnet", "testnet"],
        help="Red para direccion final (mainnet|testnet).",
    )
    parser.add_argument(
        "--full-journey",
        action="store_true",
        help="Ejecuta flujo E2E completo: entropia/mnemonic -> seed -> BIP32 -> ruta -> direccion.",
    )
    parser.add_argument(
        "--compare-passphrase",
        type=str,
        help="En modo completo, compara passphrase vacia vs este valor.",
    )
    parser.add_argument(
        "--compare-path",
        type=str,
        help="En modo completo, compara ruta principal (--path) contra esta ruta alternativa.",
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Muestra secretos completos (seed/xprv/private key/chain code). Riesgoso.",
    )
    parser.add_argument(
        "--no-secrets",
        action="store_true",
        help="Fuerza redaccion de secretos. Tiene prioridad sobre --show-secrets.",
    )
    parser.add_argument(
        "--summary-raw",
        action="store_true",
        help="En wizard, agrega al final un bloque plano key=value sin ANSI.",
    )
    return parser


def _print_header() -> None:
    print("Seed Steps - De (BIP39) Entropia a la Direccion")
    print("=" * 50)


def _print_stage_entropy(breakdown) -> None:
    print("1. Entropia")
    print("   Por que: Es la fuente de aleatoriedad que determina toda la semilla.")
    print(f"   Entropia (hex):      {breakdown.entropy_hex}")
    print(f"   Entropia (bits):     {_colorize(breakdown.entropy_bits, COLOR_ENTROPY)}")
    print(
        f"   Tamano de entropia:  {_colorize(str(len(breakdown.entropy_bits)), COLOR_ENTROPY)} bits"
    )


def _print_stage_checksum(breakdown) -> None:
    print("2. Checksum")
    print("   Por que: Detecta errores al escribir o transcribir la mnemotecnica.")
    print("   Regla BIP39: tomamos SHA-256(entropia) y usamos solo los primeros bits.")
    print(
        "   Calculo didactico: si la entropia tiene 128 bits, 128/32=4; por eso el checksum usa 4 bits."
    )
    print(f"   SHA256(entropia):    {breakdown.sha256_hex}")
    print(
        f"   Bits de checksum:    {_colorize(breakdown.checksum_bits, COLOR_CHECKSUM)}"
    )
    print(f"   Tamano checksum:     {len(breakdown.checksum_bits)} bits")


def _print_stage_combined_bits(breakdown, *, use_color: bool = False) -> None:
    color_cyan = "\033[96m"
    color_reset = "\033[0m"
    colored_bits = breakdown.entropy_plus_checksum_bits
    if use_color:
        colored_bits = (
            f"{color_cyan}{breakdown.entropy_bits}{color_reset}"
            f"{COLOR_CHECKSUM}{breakdown.checksum_bits}{color_reset}"
        )

    print("3. Bits combinados")
    print("   Por que: BIP39 une entropia y checksum antes de partir en bloques de 11.")
    if use_color:
        print("   Leyenda color:       ENTROPIA=cian | CHECKSUM=magenta claro")
    print(f"   Entropia+checksum:   {colored_bits}")
    print(f"   Total de bits:       {len(breakdown.entropy_plus_checksum_bits)} bits")


def _print_stage_indices(breakdown) -> None:
    print("4. Indices")
    print("   Por que: Cada bloque de 11 bits apunta a una palabra en la lista BIP39.")
    print(f"   Bloques de 11 bits:  {' | '.join(breakdown.bit_blocks)}")
    print(f"   Numero de palabras:  {len(breakdown.steps)}")


def _print_stage_mnemonic(breakdown) -> None:
    print("5. Mnemotecnica")
    print("   Por que: Es la representacion humana de la semilla binaria.")
    print("   Tabla por palabra:")
    print("   pos | bloque(11-bit) | indice | palabra")
    print("   ----+----------------+--------+----------")
    for step in breakdown.steps:
        print(
            f"   {step.position:>3} | {step.bit_block} | {step.index:>6} | {step.word}"
        )
    print(f"\nMnemonic: {breakdown.mnemonic}")


def _print_stage_indices_colored(breakdown) -> None:
    print("4. Indices")
    print("   Por que: Cada bloque de 11 bits apunta a una palabra en la lista BIP39.")
    print("   Leyenda color:       ENTROPIA=cian | CHECKSUM=magenta claro")
    colored_blocks: list[str] = []
    for index, block in enumerate(breakdown.bit_blocks):
        colored_blocks.append(
            _colorized_11_bit_block(block, index * 11, len(breakdown.entropy_bits))
        )
    print(f"   Bloques de 11 bits:  {' | '.join(colored_blocks)}")
    print(f"   Numero de palabras:  {len(breakdown.steps)}")


def _print_stage_mnemonic_colored(breakdown) -> None:
    print("5. Mnemotecnica")
    print("   Por que: Es la representacion humana de la semilla binaria.")
    print("   Leyenda color:       BLOQUE hereda origen bits | PALABRA=naranja")
    print("   Tabla por palabra:")
    print("   pos | bloque(11-bit) | indice | palabra")
    print("   ----+----------------+--------+----------")
    for index, step in enumerate(breakdown.steps):
        colored_block = _colorized_11_bit_block(
            step.bit_block, index * 11, len(breakdown.entropy_bits)
        )
        colored_word = _colorize(step.word, COLOR_WORD)
        print(
            f"   {step.position:>3} | {colored_block} | {step.index:>6} | {colored_word}"
        )
    colored_mnemonic = " ".join(
        _colorize(word, COLOR_WORD) for word in breakdown.mnemonic.split()
    )
    print(f"\nMnemonic: {colored_mnemonic}")


def _prompt_continue() -> None:
    input("\nPresiona Enter para continuar... ")


def _render_math_trace(trace: MathTrace) -> None:
    print(f"\n{trace.titulo}")
    print("   Que es")
    print(f"   - {trace.que_es}")
    print("   Por que se hace")
    print(f"   - {trace.por_que}")
    print("   Datos de entrada")
    for item in trace.datos_entrada:
        print(f"   - {item}")
    print("   Matematica")
    for item in trace.formulas:
        print(f"   - {item}")
    print("   Desarrollo")
    for item in trace.sustituciones:
        print(f"   - {item}")
    for item in trace.desarrollo_intermedio:
        print(f"   - {item}")
    print("   Resultado")
    for item in trace.resultados:
        print(f"   - {item}")
    if trace.nota_tecnica:
        print("   Nota")
        print(f"   - {trace.nota_tecnica}")


def _render_integrated_math_for_substep(
    traces: list[MathTrace],
    *,
    next_input_label: str,
    next_input_value: str,
) -> None:
    if not traces:
        return

    print("   Datos de entrada:")
    for trace in traces:
        for item in trace.datos_entrada:
            print(f"   - {item}")

    print("   Formula matematica:")
    for trace in traces:
        for item in trace.formulas:
            print(f"   - {item}")

    print("   Sustitucion con valores reales:")
    for trace in traces:
        for item in trace.sustituciones:
            print(f"   - {item}")

    dev_items = [item for trace in traces for item in trace.desarrollo_intermedio]
    if dev_items:
        print("   Desarrollo intermedio:")
        for item in dev_items:
            print(f"   - {item}")

    print("   Resultado:")
    for trace in traces:
        for item in trace.resultados:
            print(f"   - {item}")

    print(f"   Salida hacia siguiente subpaso: {next_input_label} = {next_input_value}")


def _build_bip39_math_traces(breakdown) -> list[MathTrace]:
    ent = len(breakdown.entropy_bits)
    cs = len(breakdown.checksum_bits)
    sha256_bits = bin(int(breakdown.sha256_hex, 16))[2:].zfill(256)
    last_block = breakdown.bit_blocks[-1]
    last_index = breakdown.steps[-1].index
    last_word = breakdown.steps[-1].word
    return [
        MathTrace(
            titulo="Traza 1) Entropia de entrada",
            que_es="El valor binario inicial del cual nace la mnemotecnica BIP39.",
            por_que="Sin ENT no existe pipeline; todo calculo posterior depende de estos bits.",
            datos_entrada=[f"entropy_hex = {breakdown.entropy_hex}"],
            formulas=["ENT(bits) = len(entropy_bytes) * 8"],
            sustituciones=[f"ENT = {len(breakdown.entropy_hex) // 2} * 8"],
            resultados=[
                f"ENT = {ent} bits",
                f"entropy_bits = {breakdown.entropy_bits}",
            ],
        ),
        MathTrace(
            titulo="Traza 2) Bytes -> bits",
            que_es="Transformacion de cada byte a su representacion binaria de 8 bits.",
            por_que="BIP39 opera sobre cadenas de bits, no sobre texto hexadecimal.",
            datos_entrada=[f"entropy_bytes = {len(breakdown.entropy_hex) // 2}"],
            formulas=["entropy_bits = concat(format(byte, '08b') para cada byte)"],
            sustituciones=["Para 00h: format(0, '08b') = 00000000"],
            desarrollo_intermedio=[
                f"{len(breakdown.entropy_hex) // 2} bytes x 8 = {ent} bits"
            ],
            resultados=[f"entropy_bits = {breakdown.entropy_bits}"],
        ),
        MathTrace(
            titulo="Traza 3) Longitud ENT",
            que_es="Medida oficial de bits de entropia permitida por BIP39.",
            por_que="Determina directamente checksum y cantidad de palabras.",
            datos_entrada=[f"entropy_bits_len = {ent}"],
            formulas=["ENT in {128,160,192,224,256}"],
            sustituciones=[f"ENT = {ent}"],
            resultados=[f"ENT = {ent} bits"],
        ),
        MathTrace(
            titulo="Traza 4) Longitud checksum",
            que_es="Cantidad de bits de checksum que se anexan a la entropia.",
            por_que="Permite detectar errores de transcripcion de la frase.",
            datos_entrada=[f"ENT = {ent} bits"],
            formulas=["CS = ENT / 32"],
            sustituciones=[f"CS = {ent} / 32"],
            resultados=[f"CS = {cs} bits"],
        ),
        MathTrace(
            titulo="Traza 5) SHA256(entropia)",
            que_es="Hash criptografico de 256 bits calculado sobre la entropia cruda.",
            por_que="BIP39 toma el prefijo de este hash como checksum oficial.",
            datos_entrada=[f"entropy_hex = {breakdown.entropy_hex}"],
            formulas=["digest = SHA256(entropy)"],
            sustituciones=[f"SHA256({breakdown.entropy_hex})"],
            resultados=[f"digest_hex = {breakdown.sha256_hex}"],
        ),
        MathTrace(
            titulo="Traza 6) Extraccion checksum",
            que_es="Recorte de los primeros CS bits del digest SHA256.",
            por_que="Es la regla exacta definida por BIP39 para checksum.",
            datos_entrada=[f"sha256_bits = {sha256_bits}", f"CS = {cs}"],
            formulas=["checksum = sha256_bits[0:CS]"],
            sustituciones=[f"checksum = sha256_bits[0:{cs}]"],
            resultados=[f"checksum = {breakdown.checksum_bits}"],
        ),
        MathTrace(
            titulo="Traza 7) Concatenacion ENT+CS",
            que_es="Union de bits de entropia y bits de checksum en un solo flujo.",
            por_que="Es el insumo directo para partir en bloques de 11 bits.",
            datos_entrada=[
                f"entropy_bits ({ent})",
                f"checksum_bits ({cs}) = {breakdown.checksum_bits}",
            ],
            formulas=["total_bits = entropy_bits + checksum_bits"],
            sustituciones=[f"total = {ent} + {cs}"],
            resultados=[
                f"total_bits = {ent + cs}",
                f"full_bits_length = {ent + cs} bits",
                f"entropy_plus_checksum = {breakdown.entropy_plus_checksum_bits}",
            ],
        ),
        MathTrace(
            titulo="Traza 8) Division en bloques de 11 bits",
            que_es="Particionado del flujo total en segmentos fijos de 11 bits.",
            por_que="Cada segmento representa un indice de wordlist (0..2047).",
            datos_entrada=[f"total_bits = {ent + cs}"],
            formulas=["num_words = (ENT + CS) / 11"],
            sustituciones=[f"num_words = ({ent} + {cs}) / 11"],
            resultados=[
                f"num_words = {len(breakdown.bit_blocks)}",
                f"bloques = {' | '.join(breakdown.bit_blocks)}",
            ],
        ),
        MathTrace(
            titulo="Traza 9) Bloques -> indices",
            que_es="Conversion binario->entero para cada bloque de 11 bits.",
            por_que="El entero resultante indexa directamente la wordlist BIP39.",
            datos_entrada=[f"ultimo_bloque = {last_block}"],
            formulas=["indice = int(bloque_11_bits, 2)"],
            sustituciones=[f"indice = int({last_block}, 2)"],
            resultados=[f"indice = {last_index}"],
        ),
        MathTrace(
            titulo="Traza 10) Indice -> palabra",
            que_es="Lookup del indice en la wordlist inglesa de 2048 palabras.",
            por_que="Mapea numero tecnico a palabra memorizable por humanos.",
            datos_entrada=[f"indice = {last_index}"],
            formulas=["palabra = wordlist[indice]"],
            sustituciones=[f"wordlist[{last_index}]"],
            resultados=[f"wordlist[{last_index}] = {last_word}"],
        ),
        MathTrace(
            titulo="Traza 11) Mnemotecnica final",
            que_es="Frase final de palabras unidas en orden de bloques.",
            por_que="Es la representacion portable para recrear seed y arbol HD.",
            datos_entrada=[f"palabras = {len(breakdown.steps)}"],
            formulas=["mnemonic = ' '.join(palabras_ordenadas)"],
            sustituciones=["join(lista_palabras)"],
            resultados=[f"Mnemonic: {breakdown.mnemonic}"],
            nota_tecnica="NO usar esta salida con fondos reales.",
            sensitive=True,
        ),
    ]


def _prompt_entropy_choice() -> bytes:
    while True:
        choice = (
            input("\nComo quieres la entropia? [A]utomatica / [M]anual: ")
            .strip()
            .lower()
        )

        if choice in {"a", "auto", "automatica", "automatic"}:
            bits = _prompt_entropy_bits_choice()
            return generate_entropy(bits // 8)

        if choice in {"m", "manual"}:
            while True:
                entropy_hex = input(
                    "Ingresa entropy hex (128/160/192/224/256 bits): "
                ).strip()
                try:
                    return parse_entropy_hex(entropy_hex)
                except ValueError as exc:
                    print(f"Entrada invalida: {exc}. Intenta nuevamente.")

        print("Opcion invalida. Escribe A para automatica o M para manual.")


def _prompt_entropy_bits_choice() -> int:
    valid_bits = {"128", "160", "192", "224", "256"}
    while True:
        bits = input(
            "Cuantos bits de entropia automatica deseas? [128/160/192/224/256]: "
        ).strip()
        if bits in valid_bits:
            return int(bits)
        print("Entrada invalida. Elige exactamente: 128, 160, 192, 224 o 256.")


def _prompt_yes_no(prompt: str) -> bool:
    while True:
        choice = input(prompt).strip().lower()
        if choice in {"s", "si", "y", "yes"}:
            return True
        if choice in {"n", "no"}:
            return False
        print("Entrada invalida. Responde S o N.")


def _prompt_continue_with_options() -> str:
    while True:
        if _prompt_yes_no("\nListo este paso. Continuamos al siguiente? (S/N): "):
            return "continue"

        decision = (
            input("Elige una accion: [C]ancelar flujo / [E]ditar este paso: ")
            .strip()
            .lower()
        )
        if decision in {"c", "cancelar"}:
            return "cancel"
        if decision in {"e", "editar", "r", "reintentar"}:
            return "retry"
        print("Opcion invalida. Escribe C para cancelar o E para editar.")


def _prompt_substep_transition(*, pause_between_steps: bool) -> str:
    if not pause_between_steps:
        return "continue"
    return _prompt_continue_with_options()


def _styled_choice_letter(letter: str) -> str:
    return f"[{ts.bright_white(letter)}]"


def _prompt_source_choice(
    wordlist: list[str],
) -> tuple[bytes | None, str, str, int | None]:
    while True:
        choice = (
            input(
                "\nPaso 1 - Elige el punto de partida: "
                f"{_styled_choice_letter('A')} Entropia automatica / "
                f"{_styled_choice_letter('E')} Entropia manual / "
                f"{_styled_choice_letter('M')} Mnemotecnica manual: "
            )
            .strip()
            .lower()
        )

        if choice in {"a", "auto", "automatica", "automatic"}:
            bits = _prompt_entropy_bits_choice()
            entropy = generate_entropy(bits // 8)
            breakdown = build_bip39_breakdown(entropy, wordlist)
            return entropy, breakdown.mnemonic, "entropia automatica", bits

        if choice in {"e", "entropia", "entropia manual", "manual"}:
            while True:
                entropy_hex = input(
                    "Escribe la entropia en hex (32/40/48/56/64 caracteres): "
                ).strip()
                try:
                    entropy = parse_entropy_hex(entropy_hex)
                    breakdown = build_bip39_breakdown(entropy, wordlist)
                    return (
                        entropy,
                        breakdown.mnemonic,
                        "entropia manual",
                        len(entropy) * 8,
                    )
                except ValueError as exc:
                    print(f"Entrada invalida: {exc}. Intenta nuevamente.")

        if choice in {"m", "mnemonica", "mnemotecnica", "mnemonica manual"}:
            while True:
                mnemonic = input("Ingresa mnemotecnica BIP39 manual: ").strip()
                words = [word for word in mnemonic.split() if word]
                if len(words) not in {12, 15, 18, 21, 24}:
                    print(
                        "Entrada invalida: la mnemotecnica debe tener 12/15/18/21/24 palabras."
                    )
                    continue
                invalid_words = [word for word in words if word not in wordlist]
                if invalid_words:
                    print(
                        "Entrada invalida: hay palabras fuera de la wordlist BIP39 inglesa. "
                        f"Ejemplo invalido: {invalid_words[0]}."
                    )
                    continue
                return None, " ".join(words), "mnemotecnica manual", None

        print("Opcion invalida. Escribe A, E o M.")


def _prompt_passphrase() -> str:
    return input("\nPaso 2 - Passphrase BIP39 (Enter si la dejas vacia): ")


def _prompt_network() -> str:
    while True:
        network = (
            input("\nPaso 4 - Elige red objetivo [M] mainnet / [T] testnet: ")
            .strip()
            .lower()
        )
        if network in {"mainnet", "m"}:
            return "mainnet"
        if network in {"testnet", "t"}:
            return "testnet"
        print("Entrada invalida. Escribe M/T o mainnet/testnet.")


def _prompt_hd_path(network: str) -> str:
    default_path = _default_path_for_network(network)
    while True:
        mode = (
            input(
                f"\nPaso 4 - Ruta HD: [D]efault sugerida ({default_path}) / [M]anual: "
            )
            .strip()
            .lower()
        )
        if mode in {"d", "default", ""}:
            return default_path
        if mode in {"m", "manual"}:
            path = input("Ingresa ruta HD (ej: m/84'/0'/0'/0/0): ").strip()
            try:
                parse_bip32_path(path)
                return path
            except ValueError as exc:
                print(
                    f"Entrada invalida: {exc}. Revisa el formato m/.. y vuelve a intentar."
                )
            continue
        print("Opcion invalida. Escribe D o M.")


def _prompt_show_secrets() -> bool:
    print("\nPolitica de seguridad: secretos REDACTADOS por defecto.")
    wants_reveal = _prompt_yes_no("Deseas revelar secretos en pantalla? (S/N): ")
    if not wants_reveal:
        return False

    print(
        "ADVERTENCIA CRITICA: revelar secretos puede exponer material custodial en logs e historial."
    )
    confirm = input("Escribe REVELAR para confirmar (o Enter para cancelar): ").strip()
    if confirm != "REVELAR":
        print("Revelacion cancelada. Se mantiene redaccion de secretos.")
        return False
    _print_secrets_warning()
    return True


def _pause_for_meetup_phase(*, phase_label: str, no_pause: bool) -> None:
    if no_pause:
        return
    input(f"\nPulsa Enter para {phase_label}.")


def _run_bip39_guided_substeps(
    breakdown,
    *,
    source_label: str,
    selected_entropy_bits: int | None,
    pause_between_steps: bool,
) -> str:
    """Render BIP39 didactic substeps with S/N confirmation.

    Returns: continue | retry | cancel
    """

    substeps = [
        "Subpaso BIP39 1/5 — Entropia",
        "Subpaso BIP39 2/5 — Checksum",
        "Subpaso BIP39 3/5 — Entropia + checksum",
        "Subpaso BIP39 4/5 — Bloques de 11 bits",
        "Subpaso BIP39 5/5 — Indices y palabras",
    ]

    ent = len(breakdown.entropy_bits)
    cs = len(breakdown.checksum_bits)
    sha256_bits = bin(int(breakdown.sha256_hex, 16))[2:].zfill(256)

    index = 0
    while index < len(substeps):
        print(f"\n{ts.dim('━' * 72)}")
        print(ts.bright_white(substeps[index]))

        if index == 0:
            _print_substep_section("Objetivo")
            print("- Ver origen binario y longitud de ENT.")
            _print_substep_section("Que es")
            print(
                "- La ENTROPIA es la fuente criptografica inicial del pipeline BIP39."
            )
            _print_substep_section("Por que importa")
            print("- Si cambia un solo bit, cambia todo: checksum, palabras y seed.")
            _print_substep_section("Datos de entrada")
            print(f"- source = {source_label}")
            print(f"- entropy_hex = {ts.cyan(breakdown.entropy_hex)}")
            _print_substep_section("Matematica")
            print(f"- {ts.formula('ENT(bits) = len(entropy_bytes) * 8')}")
            _print_substep_section("Sustitucion")
            print(
                f"- {ts.formula(f'ENT = {len(breakdown.entropy_hex) // 2} * 8 = {ent}')}"
            )
            _print_substep_section("Desarrollo")
            print("- entropy_bits (agrupado por bytes):")
            print(
                ts.cyan(
                    _format_bits_multiline(breakdown.entropy_bits, bytes_per_line=8)
                )
            )
            _print_substep_section("Resultado")
            print(f"- {ts.bright_white('ENT =')} {ts.cyan(str(ent))} bits")
            _print_substep_section("Siguiente paso")
            print("- Calcular SHA-256(entropia) y extraer CS bits iniciales.")
        elif index == 1:
            _print_substep_section("Objetivo")
            print("- Obtener CS desde SHA-256(entropia) segun regla BIP39.")
            _print_substep_section("Que es")
            print("- CHECKSUM = prefijo del digest SHA-256 de la entropia.")
            _print_substep_section("Por que importa")
            print("- Detecta errores de escritura/transcripcion en la mnemotecnica.")
            _print_substep_section("Datos de entrada")
            print(f"- ENT = {ts.cyan(str(ent))} bits")
            print(f"- SHA256(entropy)_hex = {breakdown.sha256_hex}")
            _print_substep_section("Matematica")
            print(f"- {ts.formula('CS = ENT / 32')}")
            print(f"- {ts.formula('checksum_bits = sha256_bits[0:CS]')}")
            _print_substep_section("Sustitucion")
            print(f"- {ts.formula(f'CS = {ent}/32 = {cs}')}")
            print(
                f"- {ts.formula(f'checksum = sha256_bits[0:{cs}] = {breakdown.checksum_bits}')}"
            )
            _print_substep_section("Desarrollo")
            print("- sha256_bits completo (256 bits, agrupado por bytes):")
            print(_format_bits_multiline(sha256_bits, bytes_per_line=8))
            _print_substep_section("Resultado")
            print(f"- {ts.bright_white('CS =')} {ts.pink(str(cs))} bits")
            print(
                f"- {ts.bright_white('checksum =')} {ts.pink(breakdown.checksum_bits)}"
            )
            _print_substep_section("Siguiente paso")
            print("- Concatenar entropy_bits + checksum_bits.")
        elif index == 2:
            _print_substep_section("Objetivo")
            print("- Unificar ENT y CS en un flujo unico de bits.")
            _print_substep_section("Que es")
            print("- Cadena total de 132/165/198/231/264 bits, segun ENT.")
            _print_substep_section("Por que importa")
            print("- Este flujo es el que se divide en bloques de 11 bits.")
            _print_substep_section("Datos de entrada")
            print(f"- entropy_bits = {ts.cyan('...')}")
            print(f"- checksum_bits = {ts.pink(breakdown.checksum_bits)}")
            _print_substep_section("Matematica")
            print(
                f"- {ts.formula('entropy_plus_checksum = entropy_bits + checksum_bits')}"
            )
            _print_substep_section("Sustitucion")
            print(f"- {ts.formula(f'total_bits = {ent} + {cs} = {ent + cs}')}")
            _print_substep_section("Desarrollo")
            print("- entropy_plus_checksum (agrupado por bytes):")
            print(
                _format_segmented_bits_multiline(
                    breakdown.entropy_plus_checksum_bits,
                    entropy_bits_len=len(breakdown.entropy_bits),
                    bytes_per_line=8,
                )
            )
            _print_substep_section("Resultado")
            print(f"- {ts.bright_white('full_bits_length =')} {ent + cs} bits")
            _print_substep_section("Siguiente paso")
            print("- Partir el flujo completo en bloques de 11 bits.")
        elif index == 3:
            _print_substep_section("Objetivo")
            print("- Visualizar TODOS los bloques de 11 bits sin truncar.")
            _print_substep_section("Que es")
            print("- Cada bloque representa un indice decimal entre 0 y 2047.")
            _print_substep_section("Por que importa")
            print("- El orden exacto de bloques define el orden exacto de palabras.")
            _print_substep_section("Datos de entrada")
            print(f"- total_bits = {ent + cs}")
            _print_substep_section("Matematica")
            print(f"- {ts.formula('num_words = (ENT + CS) / 11')}")
            _print_substep_section("Sustitucion")
            print(
                f"- {ts.formula(f'num_words = ({ent} + {cs}) / 11 = {len(breakdown.bit_blocks)}')}"
            )
            _print_substep_section("Desarrollo")
            for pos, block in enumerate(breakdown.bit_blocks, start=1):
                start_bit = (pos - 1) * 11
                block_colored = _color_segmented_bits(
                    block,
                    bit_offset=start_bit,
                    entropy_bits_len=len(breakdown.entropy_bits),
                )
                print(f"- bloque[{pos:02d}] = {block_colored}")
            _print_substep_section("Resultado")
            print(
                f"- {ts.bright_white('Bloques 11-bit generados =')} {len(breakdown.bit_blocks)}"
            )
            _print_substep_section("Siguiente paso")
            print("- Convertir cada bloque binario a indice y luego a palabra.")
        else:
            _print_substep_section("Objetivo")
            print("- Mapear bloques -> indices -> palabras BIP39.")
            _print_substep_section("Que es")
            print(
                "- Lookup directo: indice decimal dentro de wordlist de 2048 palabras."
            )
            _print_substep_section("Por que importa")
            print("- Es la representacion humana portable de la entropia+checksum.")
            _print_substep_section("Datos de entrada")
            print(f"- word_count = {len(breakdown.steps)}")
            _print_substep_section("Matematica")
            print(f"- {ts.formula('indice = int(bloque_11_bits, 2)')}")
            print(f"- {ts.formula('palabra = wordlist[indice]')}")
            _print_substep_section("Sustitucion")
            print(
                f"- {ts.formula(f'ultimo: int({breakdown.steps[-1].bit_block}, 2) = {breakdown.steps[-1].index}')}"
            )
            _print_substep_section("Desarrollo")
            print("pos | bloque(11-bit) | indice | palabra")
            print("----+----------------+--------+----------")
            for pos, step in enumerate(breakdown.steps, start=1):
                block_colored = _color_segmented_bits(
                    step.bit_block,
                    bit_offset=(pos - 1) * 11,
                    entropy_bits_len=len(breakdown.entropy_bits),
                )
                print(
                    f"{pos} | {block_colored} | {ts.bright_white(str(step.index))} | {ts.orange(step.word)}"
                )
            _print_substep_section("Resultado")
            colored_mnemonic = " ".join(
                ts.orange(word) for word in breakdown.mnemonic.split()
            )
            print(
                f"- wordlist[{breakdown.steps[-1].index}] = {breakdown.steps[-1].word}"
            )
            print(f"- {ts.bright_white('Mnemonic:')} {colored_mnemonic}")
            _print_substep_section("Siguiente paso")
            print("- Continuar a derivacion de seed (PBKDF2).")

        action = (
            "continue" if not pause_between_steps else _prompt_continue_with_options()
        )
        if action == "cancel":
            return "cancel"
        if action == "retry":
            continue
        index += 1

    return "continue"


def _run_bip39_condensed_block(
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
    return _prompt_continue_with_options()


def _print_phase_seed_bip39(
    *,
    mnemonic: str,
    passphrase: str,
    show_secrets: bool,
    interactive_micro_steps: bool = False,
    meetup_mode: bool = False,
) -> dict[str, object]:
    if meetup_mode:
        _print_meetup_phase_title("Fase B — BIP39: de palabras a seed")
    else:
        print("\nFase B) Seed BIP39")
    normalized_mnemonic = normalize_bip39_text(mnemonic)
    normalized_passphrase = normalize_bip39_text(passphrase)
    mnemonic_bytes = normalized_mnemonic.encode("utf-8")
    salt = build_bip39_seed_salt(passphrase)
    salt_bytes = salt.encode("utf-8")
    u_values = _pbkdf2_u_sequence(mnemonic_bytes, salt_bytes, 2048)
    t1 = bytearray(u_values[0])
    for u_value in u_values[1:]:
        for i in range(len(t1)):
            t1[i] ^= u_value[i]
    seed_bytes = derive_bip39_seed(mnemonic, passphrase)
    passphrase_display = _display_sensitive(
        passphrase or "(vacia)", show_secrets=show_secrets
    )
    seed_display = _display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)

    if meetup_mode:
        _print_meetup_intro_without_title(
            PHASE_B_INTRO, "Fase B — BIP39: de palabras a seed"
        )
        _print_meetup_text_block(PHASE_B_PBKDF2)
        print()
        print(ts.bright_white(PHASE_B_STEPS["1_6"]))
        print(f"- Idea: fijar entrada textual del KDF.")
        print(f"- Datos: mnemonic = {_colorize(mnemonic, COLOR_WORD)}")
        print("- Resultado: input listo para normalizar.")
        print()
        print(ts.bright_white(PHASE_B_STEPS["2_6"]))
        print("- Idea: canonizar Unicode para resultado determinista.")
        print(f"- Datos: len(password_nfkd) = {len(mnemonic_bytes)} bytes")
        print("- Cálculo: password = NFKD(mnemonic).encode('utf-8')")
        print("- Resultado: password preparado para PBKDF2.")
        print()
        print(ts.bright_white(PHASE_B_STEPS["3_6"]))
        print("- Idea: aplicar segundo factor opcional.")
        print(
            f"- Datos: passphrase = {_colorize(passphrase_display, COLOR_PASSPHRASE)}"
        )
        print("- Resultado: passphrase normalizada.")
        print()
        print(ts.bright_white(PHASE_B_STEPS["4_6"]))
        print("- Idea: construir salt de dominio BIP39.")
        print(f"- Datos: salt = {_colorize(salt, COLOR_PASSPHRASE)}")
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
        print(f"- Datos: seed_hex = {_colorize(seed_display, COLOR_SEED)}")
        print("- Resultado: seed final de 64 bytes.")
        return {"seed_bytes": seed_bytes, "salt": salt}

    substeps = [
        "Mnemonic de entrada",
        "Normalizacion NFKD",
        "Passphrase",
        "Salt BIP39",
        "PBKDF2-HMAC-SHA512",
        "Seed final",
    ]
    index = 1
    while index <= len(substeps):
        name = substeps[index - 1]
        _print_substep_header(2, index, len(substeps), name)
        if index == 1:
            _print_substep_sections(
                objective=[
                    "Fijar la frase mnemotecnica que alimenta toda la derivacion."
                ],
                what_is=["Cadena BIP39 de palabras separadas por espacios."],
                why=["Un cambio minimo altera seed, master key y direcciones finales."],
                inputs=[format_key_material("mnemonic", mnemonic, color=COLOR_WORD)],
                math=[ts.formula("password = mnemonic_norm_utf8")],
                substitution=[ts.formula("password = NFKD(mnemonic)")],
                development=[
                    _as_multiline_block(
                        "mnemotecnica (agrupada)",
                        "\n".join(
                            [
                                " ".join(mnemonic.split()[i : i + 4])
                                for i in range(0, len(mnemonic.split()), 4)
                            ]
                        ),
                    ),
                ],
                result=["salida -> mnemonic original para normalizar"],
                next_step=[
                    "Aplicar NFKD sobre mnemonic para obtener password canonico."
                ],
            )
        elif index == 2:
            _print_substep_sections(
                objective=[
                    "Normalizar texto para cumplir BIP39 de forma determinista."
                ],
                what_is=["NFKD transforma equivalentes Unicode en forma canonica."],
                why=["Evita seeds distintas por diferencias visuales del mismo texto."],
                inputs=[format_key_material("mnemonic", mnemonic, color=COLOR_WORD)],
                math=[ts.formula("password = NFKD(mnemonic).encode('utf-8')")],
                substitution=[
                    ts.formula(f"len(password) = {len(mnemonic_bytes)} bytes")
                ],
                development=[
                    _as_multiline_block(
                        "password bytes (hex)", format_hex_bytes(mnemonic_bytes)
                    ),
                ],
                result=["salida -> password para PBKDF2"],
                next_step=["Procesar passphrase bajo misma regla NFKD."],
            )
        elif index == 3:
            _print_substep_sections(
                objective=["Preparar segundo factor opcional de BIP39."],
                what_is=["Passphrase es texto libre que endurece la derivacion."],
                why=[
                    "Mismo mnemonic + passphrase distinta = seed totalmente distinta."
                ],
                inputs=[
                    format_key_material(
                        "passphrase", passphrase_display, color=COLOR_PASSPHRASE
                    )
                ],
                math=[ts.formula("passphrase_norm = NFKD(passphrase)")],
                substitution=[
                    ts.formula(
                        f"len(passphrase_norm_utf8) = {len(normalized_passphrase.encode('utf-8'))} bytes"
                    )
                ],
                development=["passphrase normalizada lista para construir salt."],
                result=["salida -> passphrase normalizada"],
                next_step=[
                    "Concatenar prefijo fijo 'mnemonic' + passphrase normalizada."
                ],
            )
        elif index == 4:
            _print_substep_sections(
                objective=["Construir salt efectivo usado por PBKDF2."],
                what_is=["Salt BIP39: literal 'mnemonic' + passphrase normalizada."],
                why=["Introduce dominio BIP39 y evita colisiones triviales entre KDF."],
                inputs=[
                    format_key_material(
                        "passphrase_norm", passphrase_display, color=COLOR_PASSPHRASE
                    )
                ],
                math=[ts.formula("salt = 'mnemonic' + passphrase_norm")],
                substitution=[ts.formula(f"salt = 'mnemonic' + '{passphrase}'")],
                development=[
                    "salt (texto): " + _colorize(salt, COLOR_PASSPHRASE),
                    _as_multiline_block(
                        "salt bytes (hex)", format_hex_bytes(salt_bytes)
                    ),
                ],
                result=["salida -> salt para PBKDF2"],
                next_step=["Ejecutar PBKDF2-HMAC-SHA512 con 2048 iteraciones."],
            )
        elif index == 5:
            dev_lines = [
                _as_multiline_block(
                    ts.bright_white("iteracion 0001 -> U_1"),
                    format_long_hex(u_values[0].hex(), groups_per_line=2),
                ),
                _as_multiline_block(
                    ts.bright_white("iteracion 0002 -> U_2"),
                    format_long_hex(u_values[1].hex(), groups_per_line=2),
                ),
                _as_multiline_block(
                    ts.bright_white("iteracion 0003 -> U_3"),
                    format_long_hex(u_values[2].hex(), groups_per_line=2),
                ),
                ts.bright_white("..."),
                ts.bright_white("2042 iteraciones intermedias omitidas"),
                ts.bright_white("..."),
                _as_multiline_block(
                    ts.bright_white("iteracion 2046 -> U_2046"),
                    format_long_hex(u_values[2045].hex(), groups_per_line=2),
                ),
                _as_multiline_block(
                    ts.bright_white("iteracion 2047 -> U_2047"),
                    format_long_hex(u_values[2046].hex(), groups_per_line=2),
                ),
                _as_multiline_block(
                    ts.bright_white("iteracion 2048 -> U_2048"),
                    format_long_hex(u_values[2047].hex(), groups_per_line=2),
                ),
                ts.formula("T_1 = U_1 XOR U_2 XOR ... XOR U_2048"),
                ts.formula("len(seed) = 64 bytes"),
            ]
            _print_substep_sections(
                objective=["Mostrar mecanica iterativa de PBKDF2 sin salida ilegible."],
                what_is=["PBKDF2 encadena HMAC-SHA512 y acumula XOR por bloque."],
                why=[
                    "Visualiza costo computacional (2048 iteraciones) del estandar BIP39."
                ],
                inputs=[
                    format_key_material(
                        "password/mnemonic", mnemonic, color=COLOR_WORD
                    ),
                    format_key_material(
                        "passphrase", passphrase_display, color=COLOR_PASSPHRASE
                    ),
                    format_key_material("salt", salt, color=COLOR_PASSPHRASE),
                ],
                math=[
                    ts.formula("U_1 = PRF(password, salt || INT_32_BE(1))"),
                    ts.formula("U_i = PRF(password, U_{i-1}) para i=2..2048"),
                    ts.formula("T_1 = U_1 XOR U_2 XOR ... XOR U_2048"),
                ],
                substitution=[
                    ts.formula("PRF = HMAC-SHA512"),
                    ts.formula("iterations = 2048"),
                    ts.formula("dklen = 64"),
                ],
                development=dev_lines,
                result=[
                    f"T_1 (64 bytes) = {_colorize(format_long_hex(bytes(t1).hex(), groups_per_line=2), COLOR_SEED)}"
                ],
                next_step=[
                    "Como dklen=64 y bloque SHA512=64, basta UN bloque: DK = T_1."
                ],
            )
        else:
            _print_substep_sections(
                objective=["Entregar seed final para alimentar fase BIP32 raiz."],
                what_is=["Resultado PBKDF2 de 64 bytes para arbol HD."],
                why=["Es la entrada exacta para HMAC-SHA512('Bitcoin seed', seed)."],
                inputs=["T_1 derivado del subpaso PBKDF2"],
                math=[ts.formula("DK = T_1")],
                substitution=[ts.formula("seed = PBKDF2(..., dklen=64) = T_1")],
                development=[
                    _as_multiline_block(
                        "seed final (hex agrupado)",
                        _colorize(format_long_hex(seed_display), COLOR_SEED),
                    ),
                ],
                result=[
                    f"seed (hex, 64 bytes) = {_colorize(seed_display, COLOR_SEED)}"
                ],
                next_step=[
                    "Salida hacia Fase 3: usar seed como mensaje de HMAC BIP32."
                ],
            )
        action = _prompt_substep_transition(pause_between_steps=interactive_micro_steps)
        if action == "cancel":
            raise UserCancelledFlow
        if action == "retry":
            continue
        index += 1

    return {"seed_bytes": seed_bytes, "salt": salt}


def _print_phase_master_bip32(
    seed_bytes: bytes,
    *,
    show_secrets: bool,
    interactive_micro_steps: bool = False,
    meetup_mode: bool = False,
) -> dict[str, object]:
    if meetup_mode:
        _print_meetup_phase_title("Fase C — BIP32: de seed a nodo maestro")
    else:
        print("\nFase C) Master BIP32")
    seed_hex = _display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)
    master = derive_bip32_master_node(seed_bytes)
    hmac_hex = _display_sensitive(master.hmac_i.hex(), show_secrets=show_secrets)
    il_hex = _display_sensitive(
        master.master_private_key.hex(), show_secrets=show_secrets
    )
    ir_hex = _display_sensitive(master.chain_code.hex(), show_secrets=show_secrets)
    i_colored = _colorize(il_hex, COLOR_IL) + _colorize(ir_hex, COLOR_IR)

    xprv_key_data = "00" + master.master_private_key.hex()
    xprv_payload = (
        MAINNET_XPRV_VERSION.hex()
        + "00"
        + "00000000"
        + "00000000"
        + master.chain_code.hex()
        + xprv_key_data
    )
    pubkey_compressed = compressed_pubkey_from_private_key(
        master.master_private_key
    ).hex()
    xpub_payload = (
        MAINNET_XPUB_VERSION.hex()
        + "00"
        + "00000000"
        + "00000000"
        + master.chain_code.hex()
        + pubkey_compressed
    )

    if meetup_mode:
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
        print(
            "- xprv master = "
            + _colorize(
                _display_sensitive(master.xprv, show_secrets=show_secrets), COLOR_XPRV
            )
        )
        print(f"- xpub master = {_colorize(master.xpub, COLOR_XPUB)}")
        for note in PHASE_C_SERIALIZATION_NOTES:
            print(f"- {note}")
        print("- Resultado: nodo maestro listo para derivación HD.")
        return {"master": master}

    substeps = [
        "Seed de entrada",
        "HMAC maestro",
        "Separar IL/IR",
        "Payload xprv",
        "Payload xpub",
        "Nodo maestro final",
    ]
    index = 1
    while index <= len(substeps):
        name = substeps[index - 1]
        _print_substep_header(3, index, len(substeps), name)
        if index == 1:
            _print_substep_sections(
                objective=["Tomar la seed BIP39 como insumo raiz."],
                what_is=["Mensaje de 64 bytes para HMAC inicial BIP32."],
                why=["Sin seed no existe nodo maestro HD."],
                inputs=[format_key_material("seed", seed_hex, color=COLOR_SEED)],
                math=[ts.formula("mensaje = seed")],
                substitution=[ts.formula("len(seed) = 64")],
                development=[
                    _as_multiline_block(
                        "seed agrupada",
                        _colorize(format_long_hex(seed_hex), COLOR_SEED),
                    ),
                ],
                result=["salida -> mensaje para HMAC"],
                next_step=["Aplicar HMAC-SHA512 con clave fija 'Bitcoin seed'."],
            )
        elif index == 2:
            _print_substep_sections(
                objective=["Calcular digest maestro I."],
                what_is=["HMAC-SHA512(clave, mensaje)."],
                why=["Genera material para clave privada y chain code."],
                inputs=[
                    format_key_material("hmac_key", '"Bitcoin seed"', color=COLOR_IR),
                    format_key_material("data", seed_hex, color=COLOR_SEED),
                ],
                math=[ts.formula('I = HMAC-SHA512(key="Bitcoin seed", data=seed)')],
                substitution=[ts.formula("I = IL || IR")],
                development=[
                    '"Bitcoin seed" NO es la seed del usuario ni contrasena; es cadena ASCII fija BIP32.',
                    "Sirve como separacion de dominio estandar.",
                    _as_multiline_block("I (hex, 64 bytes)", i_colored),
                ],
                result=["salida -> I para particionar"],
                next_step=["Partir I en IL (izq) y IR (der)."],
            )
        elif index == 3:
            _print_substep_sections(
                objective=["Separar secreto y cadena de derivacion."],
                what_is=[
                    "IL = material candidato a master private key.",
                    "IR = master chain code.",
                ],
                why=["Cumplen roles distintos en derivacion HD."],
                inputs=["I = IL || IR"],
                math=[
                    ts.formula("IL = I[0:32], IR = I[32:64]"),
                    ts.formula("master_private_key = parse256(IL)"),
                    ts.formula("master_chain_code = IR"),
                ],
                substitution=[ts.formula("32 bytes + 32 bytes")],
                development=[
                    f"IL = {_colorize(il_hex, COLOR_IL)}",
                    f"IR = {_colorize(ir_hex, COLOR_IR)}",
                ],
                result=["salida -> IL/IR listos para serializar"],
                next_step=["Construir payload xprv con IL e IR."],
            )
        elif index == 4:
            _print_substep_sections(
                objective=["Preparar serializacion privada BIP32."],
                what_is=["Payload previo a Base58Check para xprv."],
                why=["Estandariza version/depth/fingerprint/chain/key."],
                inputs=["version xprv + campos BIP32 + IL + IR"],
                math=[
                    ts.formula("xprv_payload = version||depth||fp||child||IR||00||IL")
                ],
                substitution=[ts.formula("version=0488ade4")],
                development=[
                    _as_multiline_block(
                        "payload xprv (hex)",
                        _colorize(format_long_hex(xprv_payload), COLOR_XPRV),
                    )
                ],
                result=["salida -> payload xprv"],
                next_step=["Construir payload equivalente para xpub."],
            )
        elif index == 5:
            _print_substep_sections(
                objective=["Preparar serializacion publica BIP32."],
                what_is=["Payload previo a Base58Check para xpub."],
                why=["Permite derivacion/consulta sin exponer secreto."],
                inputs=["version xpub + campos BIP32 + IR + pubkey"],
                math=[
                    ts.formula("xpub_payload = version||depth||fp||child||IR||pubkey")
                ],
                substitution=[ts.formula("version=0488b21e")],
                development=[
                    _as_multiline_block(
                        "payload xpub (hex)",
                        _colorize(format_long_hex(xpub_payload), COLOR_XPUB),
                    )
                ],
                result=["salida -> payload xpub"],
                next_step=["Codificar ambos payloads en Base58Check."],
            )
        else:
            _print_substep_sections(
                objective=["Entregar nodo maestro BIP32 completo."],
                what_is=["xprv/xpub iniciales del arbol HD."],
                why=["Punto de partida para rutas BIP84."],
                inputs=["payloads xprv/xpub"],
                math=[ts.formula("node_master = {xprv, xpub, IL, IR}")],
                substitution=[ts.formula("depth=0")],
                development=[
                    f"xprv = {_colorize(_display_sensitive(master.xprv, show_secrets=show_secrets), COLOR_XPRV)}",
                    f"xpub = {_colorize(master.xpub, COLOR_XPUB)}",
                ],
                result=["salida -> Fase 4 usa este nodo como origen"],
                next_step=["Aplicar ruta HD objetivo en la siguiente fase."],
            )
        action = _prompt_substep_transition(pause_between_steps=interactive_micro_steps)
        if action == "cancel":
            raise UserCancelledFlow
        if action == "retry":
            continue
        index += 1

    return {"master": master}


def _print_phase_hd_path(
    master,
    path: str,
    network: str,
    *,
    show_secrets: bool,
    interactive_micro_steps: bool = False,
    meetup_mode: bool = False,
) -> dict[str, object]:
    parsed = parse_bip32_path(path)
    current = derive_bip32_node_from_master(master)
    if meetup_mode:
        _print_meetup_phase_title("Fase D — Ruta HD")
    else:
        print("\nFase D) Ruta HD")
    route_tokens = ["m"] + [step.token for step in parsed]
    level_labels = [
        "raiz",
        "purpose'",
        "coin_type'",
        "account'",
        "change",
        "index",
    ]
    table_lines = [
        "nivel | valor   | significado",
        "------+---------+------------------------------",
    ]
    for i, label in enumerate(level_labels):
        value = route_tokens[i] if i < len(route_tokens) else "(no aplica)"
        table_lines.append(f"{i} | {value} | {label}")

    derivation_log: list[str] = []
    if not parsed:
        derivation_log.append("m (sin derivacion): nodo maestro depth=0")
    for step in parsed:
        current = derive_bip32_path_from_node(current, f"m/{step.token}")
        index_label = (
            step.child_number - HARDENED_OFFSET if step.hardened else step.child_number
        )
        hardened_label = "hardened" if step.hardened else "normal"
        derivation_log.append(
            f"{step.token}: index={index_label}, tipo={hardened_label}, depth={current.depth}, fp_padre={current.parent_fingerprint.hex()}"
        )

    if meetup_mode:
        _print_meetup_intro_without_title(PHASE_D_INTRO, "Fase D — Ruta HD")
        _print_meetup_text_block(PHASE_D_HARDENED)
        print()
        print(ts.bright_white(PHASE_D_STEPS["1_3"]))
        print("- Idea: fijar la rama exacta del árbol HD.")
        print(f"- Datos: ruta = {path}")
        print("- Resultado: objetivo de derivación definido.")
        print()
        print(ts.bright_white(PHASE_D_STEPS["2_3"]))
        print("- Idea: interpretar semántica por nivel.")
        print("- Datos: hardened usa apóstrofo (') y normal no.")
        print("- Cálculo: hardened_index = index + 2^31")
        print("- Resultado: niveles y significado:")
        for line in table_lines:
            print(f"  {line}")
        print()
        print(ts.bright_white(PHASE_D_STEPS["3_3"]))
        print("- Idea: derivar nodo final paso a paso con CKDpriv.")
        print("- Cálculo: child = CKDpriv(parent, index), hardened => index + 2^31")
        print("- Log CKDpriv:")
        for line in derivation_log:
            print(f"  {line}")
        for note in PHASE_D_CKDPRIV_ENDIAN_NOTES:
            print(f"- {note}")
        is_leaf_00 = (
            len(parsed) >= 2 and parsed[-2].token == "0" and parsed[-1].token == "0"
        )
        derived_label = (
            "derivado (nodo hoja /0/0, no account)" if is_leaf_00 else "derivado"
        )
        print(
            f"- xprv {derived_label} = "
            + _colorize(
                _display_sensitive(current.xprv, show_secrets=show_secrets), COLOR_XPRV
            )
        )
        print(f"- xpub {derived_label} = {_colorize(current.xpub, COLOR_XPUB)}")
        is_bip84_path = bool(parsed) and parsed[0].token == "84'"
        if is_bip84_path:
            ext_prv, ext_pub = serialize_bip84_extended_keys(current, network)
            prv_prefix = "zprv" if network == "mainnet" else "vprv"
            pub_prefix = "zpub" if network == "mainnet" else "vpub"
            print("- Matiz: xprv/xpub usan serialización clásica BIP32.")
            print("- Matiz: BIP84 cambia version bytes para compatibilidad de wallets.")
            print(
                f"- Matiz: mainnet usa zprv/zpub y testnet usa vprv/vpub (red actual: {network})."
            )
            print(
                "- Matiz: clave privada/pública y chain code no cambian; cambia solo serialización/display."
            )
            print(
                f"- {prv_prefix} {derived_label} = "
                + _colorize(
                    _display_sensitive(ext_prv, show_secrets=show_secrets), COLOR_XPRV
                )
            )
            print(f"- {pub_prefix} {derived_label} = {_colorize(ext_pub, COLOR_XPUB)}")
        print("- Resultado: nodo final listo para construir dirección.")
        return {"derived": current}

    substeps = [
        "Ruta objetivo",
        "Parseo de ruta",
        "Niveles BIP84",
        "Derivacion CKDpriv",
        "Nodo hoja",
        "Material derivado",
    ]
    index = 1
    while index <= len(substeps):
        name = substeps[index - 1]
        _print_substep_header(4, index, len(substeps), name)
        if index == 1:
            _print_substep_sections(
                objective=["Declarar camino exacto hasta la hoja."],
                what_is=["Ruta HD con niveles hardened/normal."],
                why=["Modificar un nivel produce otra clave hija."],
                inputs=[format_key_material("path", path)],
                math=[
                    ts.formula("m / purpose' / coin_type' / account' / change / index")
                ],
                substitution=[ts.formula(format_derivation_path(path))],
                development=["ruta normalizada lista para parseo"],
                result=["salida -> tokens de ruta"],
                next_step=["Parsear y validar sintaxis BIP32."],
            )
        elif index == 2:
            _print_substep_sections(
                objective=["Validar estructura de la ruta."],
                what_is=["Parser BIP32 transforma texto en pasos numericos."],
                why=["Evita derivaciones ambiguas o fuera de norma."],
                inputs=[format_key_material("path", path)],
                math=[ts.formula("steps = parse_bip32_path(path)")],
                substitution=[ts.formula(f"steps = {len(parsed)}")],
                development=["tokens: " + ", ".join(step.token for step in parsed)],
                result=["salida -> lista de pasos valida"],
                next_step=["Mapear cada paso a su nivel semantico."],
            )
        elif index == 3:
            _print_substep_sections(
                objective=["Relacionar ruta con semantica BIP84."],
                what_is=["Tabla nivel/valor/significado."],
                why=["Ayuda a razonar purpose, moneda, cuenta y address index."],
                inputs=["tokens parseados"],
                math=[ts.formula("nivel 0..5")],
                substitution=[ts.formula("m/84'/0'/0'/0/0")],
                development=table_lines,
                result=["salida -> mapa de niveles"],
                next_step=["Ejecutar CKDpriv nivel por nivel."],
            )
        elif index == 4:
            _print_substep_sections(
                objective=["Derivar nodo hijo por cada nivel."],
                what_is=["CKDpriv hardened o normal segun token."],
                why=["Construye camino determinista desde master."],
                inputs=["master node + pasos"],
                math=[
                    ts.formula("child = CKDpriv(parent, index)"),
                    "Caso hardened:",
                    ts.formula("hardened_index = index + 2^31"),
                    ts.formula(
                        "data = 0x00 || ser256(k_parent) || ser32(hardened_index)"
                    ),
                    ts.formula("I = HMAC-SHA512(key=c_parent, data=data)"),
                    ts.formula("IL, IR = I[0:32], I[32:64]"),
                    ts.formula("k_child = (parse256(IL) + k_parent) mod n"),
                    ts.formula("c_child = IR"),
                    "Caso normal:",
                    ts.formula("data = serP(point(k_parent)) || ser32(index)"),
                    ts.formula("I = HMAC-SHA512(key=c_parent, data=data)"),
                    ts.formula("IL, IR = I[0:32], I[32:64]"),
                    ts.formula("k_child = (parse256(IL) + k_parent) mod n"),
                    ts.formula("c_child = IR"),
                ],
                substitution=[
                    ts.formula(
                        "Ejemplo hardened: m/84' => index=84, hardened_index=84+2^31"
                    ),
                    ts.formula("Ejemplo normal: /0 => index=0"),
                ],
                development=derivation_log,
                result=["salida -> nodo hoja depth final"],
                next_step=["Consolidar metadata del nodo hoja."],
            )
        elif index == 5:
            _print_substep_sections(
                objective=["Verificar que llegamos al nodo esperado."],
                what_is=["Depth/child/fingerprint del nodo final."],
                why=["Confirma que la ruta aplicada fue la correcta."],
                inputs=["nodo tras ultima derivacion"],
                math=[ts.formula("depth = len(steps)")],
                substitution=[ts.formula(f"depth = {current.depth}")],
                development=[
                    f"child_number = {current.child_number}",
                    f"parent_fp = {current.parent_fingerprint.hex()}",
                ],
                result=["salida -> nodo listo para serializar"],
                next_step=["Mostrar xprv/xpub de la hoja."],
            )
        else:
            _print_substep_sections(
                objective=["Entregar clave derivada para fase de direccion."],
                what_is=["xprv/xpub del nodo hoja de la ruta."],
                why=["La pubkey de este nodo genera la direccion P2WPKH."],
                inputs=["nodo hoja"],
                math=[ts.formula("serialized node -> xprv/xpub")],
                substitution=[ts.formula("network agnostica en esta fase")],
                development=[
                    f"xprv = {_colorize(_display_sensitive(current.xprv, show_secrets=show_secrets), COLOR_XPRV)}",
                    f"xpub = {_colorize(current.xpub, COLOR_XPUB)}",
                ],
                result=["salida -> Fase 5 usa esta clave publica"],
                next_step=["Construir HASH160 y codificar Bech32."],
            )
        action = _prompt_substep_transition(pause_between_steps=interactive_micro_steps)
        if action == "cancel":
            raise UserCancelledFlow
        if action == "retry":
            continue
        index += 1

    return {"derived": current}


def _print_phase_address(
    derived,
    network: str,
    *,
    show_secrets: bool,
    interactive_micro_steps: bool = False,
    meetup_mode: bool = False,
) -> dict[str, object]:
    p2wpkh = derive_p2wpkh_address_from_node(derived, network)
    if meetup_mode:
        _print_meetup_phase_title("Fase E — De clave pública a dirección")
    else:
        print("\nFase E) Direccion")
    hash160_hex = _display_sensitive(p2wpkh.hash160.hex(), show_secrets=show_secrets)
    sha256_pubkey_hex = _display_sensitive(
        hashlib.sha256(p2wpkh.compressed_pubkey).hexdigest(), show_secrets=show_secrets
    )
    witness_line = f"OP_{p2wpkh.witness_version} {p2wpkh.witness_program.hex()}"
    if meetup_mode:
        _print_meetup_intro_without_title(
            PHASE_E_INTRO, "Fase E — De clave pública a dirección"
        )
        _print_meetup_text_block(PHASE_E_HASH160)
        print()
        print(ts.bright_white(PHASE_E_STEPS["1_4"]))
        pubkey_hex = _display_sensitive(
            p2wpkh.compressed_pubkey.hex(), show_secrets=show_secrets
        )
        print("- Idea: obtener la clave pública comprimida del nodo.")
        print(f"- Datos: pubkey comprimida = {_colorize(pubkey_hex, COLOR_XPUB)}")
        print("- Resultado: entrada para hash de dirección.")
        print()
        print(ts.bright_white(PHASE_E_STEPS["2_4"]))
        print("- Idea: construir HASH160 desde la pubkey.")
        print(
            f"- Datos: SHA256(pubkey) = {_colorize(sha256_pubkey_hex, COLOR_CHECKSUM)}"
        )
        print(
            f"- Cálculo: HASH160 = RIPEMD160(SHA256(pubkey)) = {_colorize(hash160_hex, COLOR_IR)}"
        )
        print("- Resultado: witness program de 20 bytes disponible.")
        print()
        print(ts.bright_white(PHASE_E_STEPS["3_4"]))
        print(f"- Datos: witness = {_colorize(witness_line, COLOR_CHECKSUM)}")
        print(f"- Datos: hrp = {p2wpkh.hrp} (network={network})")
        print("- Cálculo: Bech32 = hrp + '1' + data_5bit + checksum")
        print("- Resultado: cadena Bech32 lista.")
        print()
        print(ts.bright_white(PHASE_E_STEPS["4_4"]))
        print(f"- Resultado: direccion = {ts.bright_white(p2wpkh.address)}")
        return {"final_addr": p2wpkh}

    substeps = [
        "Pubkey comprimida",
        "HASH160",
        "Witness program",
        "HRP de red",
        "Codificacion Bech32",
        "Direccion final",
    ]
    index = 1
    while index <= len(substeps):
        name = substeps[index - 1]
        _print_substep_header(5, index, len(substeps), name)
        if index == 1:
            _print_substep_sections(
                objective=["Extraer pubkey comprimida del nodo derivado."],
                what_is=["Clave publica de 33 bytes (SEC comprimido)."],
                why=["Base para HASH160 y direccion SegWit."],
                inputs=["nodo derivado BIP84"],
                math=[ts.formula("pubkey = point(k_child)")],
                substitution=[ts.formula("len(pubkey)=33")],
                development=[
                    _as_multiline_block(
                        "pubkey comprimida (hex)",
                        _colorize(
                            format_long_hex(
                                _display_sensitive(
                                    p2wpkh.compressed_pubkey.hex(),
                                    show_secrets=show_secrets,
                                )
                            ),
                            COLOR_XPUB,
                        ),
                    )
                ],
                result=["salida -> pubkey comprimida"],
                next_step=["Aplicar HASH160 sobre la pubkey."],
            )
        elif index == 2:
            _print_substep_sections(
                objective=["Obtener identificador corto de la pubkey."],
                what_is=["HASH160 = RIPEMD160(SHA256(pubkey))."],
                why=["Reduce a 20 bytes para witness program P2WPKH."],
                inputs=["pubkey comprimida"],
                math=[ts.formula("hash160 = RIPEMD160(SHA256(pubkey))")],
                substitution=[ts.formula("len(hash160)=20")],
                development=[
                    _as_multiline_block(
                        "hash160 (hex)",
                        _colorize(format_long_hex(hash160_hex), COLOR_IR),
                    )
                ],
                result=["salida -> hash160"],
                next_step=["Formar witness program v0."],
            )
        elif index == 3:
            _print_substep_sections(
                objective=["Construir script witness SegWit v0."],
                what_is=["OP_0 + hash160 de 20 bytes."],
                why=["Estructura requerida por P2WPKH."],
                inputs=["witness_version=0", "hash160"],
                math=[ts.formula("witness = OP_0 <20-byte-hash>")],
                substitution=[ts.formula(witness_line)],
                development=[_colorize(witness_line, COLOR_CHECKSUM)],
                result=["salida -> witness program"],
                next_step=["Seleccionar HRP segun red."],
            )
        elif index == 4:
            _print_substep_sections(
                objective=["Definir prefijo humano legible de red."],
                what_is=["HRP=bc mainnet, tb testnet."],
                why=["Evita confundir direcciones entre redes."],
                inputs=[format_key_material("network", network)],
                math=[ts.formula("hrp in {'bc','tb'}")],
                substitution=[ts.formula(f"hrp = {p2wpkh.hrp}")],
                development=[f"network={network} -> hrp={p2wpkh.hrp}"],
                result=["salida -> hrp para Bech32"],
                next_step=["Codificar witness program en Bech32."],
            )
        elif index == 5:
            _print_substep_sections(
                objective=["Codificar direccion final de transporte."],
                what_is=["Bech32 sobre HRP + datos witness."],
                why=["Formato robusto y legible para SegWit."],
                inputs=["hrp + witness program"],
                math=[
                    ts.formula("hrp = 'bc' o 'tb'"),
                    ts.formula("witness_version = 0"),
                    ts.formula("witness_program = HASH160(pubkey)"),
                    ts.formula(
                        "data_5bit = convertbits(witness_version + witness_program, 8 -> 5)"
                    ),
                    ts.formula("checksum = bech32_polymod(...)"),
                    ts.formula("address = hrp + '1' + data_5bit + checksum"),
                ],
                substitution=[
                    ts.formula(f"hrp={p2wpkh.hrp}, v={p2wpkh.witness_version}")
                ],
                development=[
                    "Flujo: pubkey -> HASH160 -> witness_program -> convertbits -> checksum",
                    "checksum Bech32 integrado en la cadena final",
                ],
                result=["salida -> address string"],
                next_step=["Presentar direccion final consolidada."],
            )
        else:
            _print_substep_sections(
                objective=["Entregar direccion utilizable para recibir BTC."],
                what_is=["P2WPKH Bech32 derivada de la ruta elegida."],
                why=["Es el destino final del flujo pedagógico."],
                inputs=["pubkey + network + witness"],
                math=[ts.formula("final_address = P2WPKH(pubkey, network)")],
                substitution=[ts.formula(p2wpkh.address)],
                development=[ts.bright_white(p2wpkh.address)],
                result=[f"direccion final = {ts.bright_white(p2wpkh.address)}"],
                next_step=["Salida hacia resumen final del wizard."],
            )
        action = _prompt_substep_transition(pause_between_steps=interactive_micro_steps)
        if action == "cancel":
            raise UserCancelledFlow
        if action == "retry":
            continue
        index += 1

    return {"final_addr": p2wpkh}


def _print_phase_final_summary(
    *,
    mnemonic: str,
    passphrase: str,
    path: str,
    network: str,
    seed_bytes: bytes,
    master,
    derived,
    final_addr,
    show_secrets: bool,
    summary_raw: bool = False,
    meetup_mode: bool = False,
) -> None:
    if meetup_mode:
        _print_meetup_phase_title("Fase F — Resumen final")
        _print_meetup_text_block(PHASE_F_SUMMARY)
        for note in PHASE_BIG_LITTLE_ENDIAN_NOTE:
            print(f"- {note}")
    else:
        print("\nFase F) Resumen final")
    print(f"{ts.dim('━' * 88)}")
    print(ts.bright_white("Inputs usados:"))
    colored_mnemonic = " ".join(
        _colorize(word, COLOR_WORD) for word in mnemonic.split()
    )
    print()
    print(f"- mnemonic = {colored_mnemonic}")
    print()
    print(
        "- passphrase = "
        + _colorize(
            _display_sensitive(passphrase or "(vacia)", show_secrets=show_secrets),
            COLOR_PASSPHRASE,
        )
    )
    print()
    print(f"- path = {path}")
    print()
    print(f"- network = {network}")

    if not meetup_mode:
        print()
        print(ts.bright_white("Transformaciones clave:"))
        print()
        print("- A) ENT + CS -> bloques(11) -> mnemonic")
        print("- B) mnemonic + passphrase -> PBKDF2(2048) -> seed")
        print("- C) seed -> HMAC-SHA512('Bitcoin seed') -> IL/IR -> xprv/xpub master")
        print("- D) master + ruta HD -> CKDpriv -> xprv/xpub derivado")
        print("- E) pubkey -> SHA256 -> HASH160 -> witness -> Bech32")

    print()
    print(ts.bright_white("Outputs clave:"))
    print()
    print(
        "- seed = "
        + _colorize(
            _display_sensitive(seed_bytes.hex(), show_secrets=show_secrets), COLOR_SEED
        )
    )
    print()
    print(
        "- IL master = "
        + _colorize(
            _display_sensitive(
                master.master_private_key.hex(), show_secrets=show_secrets
            ),
            COLOR_IL,
        )
    )
    print()
    print(
        "- IR master = "
        + _colorize(
            _display_sensitive(master.chain_code.hex(), show_secrets=show_secrets),
            COLOR_IR,
        )
    )
    print()
    print(
        "- xprv master = "
        + _colorize(
            _display_sensitive(master.xprv, show_secrets=show_secrets), COLOR_XPRV
        )
    )
    print()
    print(f"- xpub master = {_colorize(master.xpub, COLOR_XPUB)}")
    print()
    print(
        "- xprv derivado = "
        + _colorize(
            _display_sensitive(derived.xprv, show_secrets=show_secrets), COLOR_XPRV
        )
    )
    print()
    print(f"- xpub derivado = {_colorize(derived.xpub, COLOR_XPUB)}")
    print()
    print(f"- direccion final = {ts.bright_white(final_addr.address)}")

    print()
    print(ts.warning("ADVERTENCIA:"))
    print("- EDUCATIVO, NO CUSTODIA REAL")

    if summary_raw:
        _print_raw_summary_block(
            mnemonic=mnemonic,
            passphrase=passphrase,
            path=path,
            network=network,
            seed_bytes=seed_bytes,
            master=master,
            derived=derived,
            final_addr=final_addr,
        )


def _run_interactive_guided_pipeline(state: dict[str, object]) -> int:
    phase_index = 0
    while phase_index < 5:
        if phase_index == 0:
            seed_artifacts = _print_phase_seed_bip39(
                mnemonic=str(state["mnemonic"]),
                passphrase=str(state["passphrase"]),
                show_secrets=bool(state["show_secrets"]),
            )
            state.update(seed_artifacts)
        elif phase_index == 1:
            master_artifacts = _print_phase_master_bip32(
                state["seed_bytes"], show_secrets=bool(state["show_secrets"])
            )
            state.update(master_artifacts)
        elif phase_index == 2:
            path_artifacts = _print_phase_hd_path(
                state["master"],
                str(state["path"]),
                str(state["network"]),
                show_secrets=bool(state["show_secrets"]),
            )
            state.update(path_artifacts)
        elif phase_index == 3:
            address_artifacts = _print_phase_address(
                state["derived"],
                str(state["network"]),
                show_secrets=bool(state["show_secrets"]),
            )
            state.update(address_artifacts)
        else:
            _print_phase_final_summary(
                mnemonic=str(state["mnemonic"]),
                passphrase=str(state["passphrase"]),
                path=str(state["path"]),
                network=str(state["network"]),
                seed_bytes=state["seed_bytes"],
                master=state["master"],
                derived=state["derived"],
                final_addr=state["final_addr"],
                show_secrets=bool(state["show_secrets"]),
            )

        action = _prompt_continue_with_options()
        if action == "cancel":
            print("Flujo cancelado por usuario. Salida limpia.")
            return 0
        if action == "retry":
            if phase_index == 0:
                state["passphrase"] = _prompt_passphrase()
            elif phase_index == 2:
                state["path"] = _prompt_hd_path(str(state["network"]))
            elif phase_index == 3:
                state["network"] = _prompt_network()
            elif phase_index == 4:
                print(
                    "Reintento de resumen: se recalcula con los mismos inputs actuales."
                )
            continue
        phase_index += 1

    return 0


def _print_manual_mnemonic_limit_note() -> None:
    print("\nSubpaso BIP39 (entrada manual de mnemotecnica)")
    print("   Objetivo del paso: aclarar el limite didactico de esta modalidad.")
    print(
        "   Que debes observar: aqui continuamos desde frase, no desde entropia original."
    )
    print(
        "No se puede reconstruir de forma fiable la entropia/checksum/bloques de 11 bits ORIGINALES "
        "a partir de solo la mnemotecnica ingresada."
    )
    print(
        "Alternativa educativa: continuar desde mnemotecnica -> seed -> BIP32 -> ruta -> direccion."
    )


def _print_detailed_breakdown(breakdown) -> None:
    _print_stage_entropy(breakdown)
    print()
    _print_stage_checksum(breakdown)
    print()
    _print_stage_combined_bits(breakdown)
    print()
    _print_stage_indices(breakdown)
    print()
    _print_stage_mnemonic(breakdown)


def _run_interactive(
    wordlist: list[str],
    *,
    preset_entropy: bytes | None = None,
    no_pause: bool = False,
    default_passphrase: str = "",
    summary_raw: bool = False,
    meetup_mode: bool = False,
    network_override: str | None = None,
    path_override: str | None = None,
) -> int:
    _print_header()
    print(f"Bienvenido a {ts.orange('Seed Steps')} by SvenS101")
    print(
        "Avanzamos por pasos cortos: eliges entrada, ves operacion y confirmas salida."
    )
    print(
        "Nota docente: en el wizard se muestran valores COMPLETOS para fines de aprendizaje."
    )
    print(
        "No uses material real; la politica segura por defecto sigue activa fuera del wizard."
    )
    if meetup_mode:
        _print_meetup_text_block(MEETUP_INTRO)

    state: dict[str, object] = {
        "entropy": None,
        "mnemonic": "",
        "source_label": "",
        "selected_entropy_bits": None,
        "passphrase": "",
        "network": "mainnet",
        "path": "",
        "show_secrets": False,
        "summary_raw": summary_raw,
    }

    stage_index = 0
    while stage_index < 5:
        if stage_index == 0:
            if preset_entropy is not None:
                entropy = preset_entropy
                breakdown = build_bip39_breakdown(entropy, wordlist)
                mnemonic = breakdown.mnemonic
                source_label = "entropia manual (--entropy)"
                selected_entropy_bits = len(entropy) * 8
            else:
                entropy, mnemonic, source_label, selected_entropy_bits = (
                    _prompt_source_choice(wordlist)
                )
            state["entropy"] = entropy
            state["mnemonic"] = mnemonic
            state["source_label"] = source_label
            state["selected_entropy_bits"] = selected_entropy_bits
            if not meetup_mode:
                print("\nEtapa 1/5 completada: origen seleccionado")
                print(f"- Origen: {source_label}")
                print(f"- Mnemotecnica: {mnemonic}")

            if entropy is not None:
                if meetup_mode:
                    _pause_for_meetup_phase(
                        phase_label="ver la fase A: BIP39 de entropía a palabras",
                        no_pause=no_pause,
                    )
                if preset_entropy is None:
                    try:
                        breakdown = build_bip39_breakdown(entropy, wordlist)
                    except ValueError as exc:
                        print(
                            _error_message(
                                "DOMINIO BIP39",
                                f"validacion de reglas BIP39 fallida ({exc})",
                                "revisa la entropia y la integridad de la wordlist",
                            ),
                            file=sys.stderr,
                        )
                        return 4

                if meetup_mode:
                    b39_action = _run_bip39_condensed_block(
                        breakdown,
                        source_label=source_label,
                        selected_entropy_bits=selected_entropy_bits,
                        pause_between_steps=(not no_pause) and (not meetup_mode),
                    )
                else:
                    b39_action = _run_bip39_guided_substeps(
                        breakdown,
                        source_label=source_label,
                        selected_entropy_bits=selected_entropy_bits,
                        pause_between_steps=not no_pause,
                    )
                if b39_action == "cancel":
                    print("Flujo cancelado por usuario. Salida limpia.")
                    return 0
                if b39_action == "retry":
                    continue
            else:
                _print_manual_mnemonic_limit_note()
                b39_action = "continue" if no_pause else _prompt_continue_with_options()
                if b39_action == "cancel":
                    print("Flujo cancelado por usuario. Salida limpia.")
                    return 0
                if b39_action == "retry":
                    continue

            stage_index += 1
            continue

        elif stage_index == 1:
            if meetup_mode:
                _pause_for_meetup_phase(
                    phase_label="ver la fase B: palabras a seed",
                    no_pause=no_pause,
                )
            passphrase = (
                default_passphrase
                if (no_pause and not meetup_mode)
                else _prompt_passphrase()
            )
            state["passphrase"] = passphrase
            try:
                seed_artifacts = _print_phase_seed_bip39(
                    mnemonic=str(state["mnemonic"]),
                    passphrase=passphrase,
                    show_secrets=True,
                    interactive_micro_steps=(not no_pause) and (not meetup_mode),
                    meetup_mode=meetup_mode,
                )
            except UserCancelledFlow:
                print("Flujo cancelado por usuario. Salida limpia.")
                return 0
            state.update(seed_artifacts)
            if not meetup_mode:
                print("\nEtapa 2/5 completada: seed BIP39 derivada")
            stage_index += 1
            continue

        elif stage_index == 2:
            if meetup_mode:
                _pause_for_meetup_phase(
                    phase_label="entrar en la fase C: seed a nodo maestro BIP32",
                    no_pause=no_pause,
                )
            try:
                master_artifacts = _print_phase_master_bip32(
                    state["seed_bytes"],
                    show_secrets=True,
                    interactive_micro_steps=(not no_pause) and (not meetup_mode),
                    meetup_mode=meetup_mode,
                )
            except UserCancelledFlow:
                print("Flujo cancelado por usuario. Salida limpia.")
                return 0
            state.update(master_artifacts)
            if not meetup_mode:
                print("\nEtapa 3/5 completada: master BIP32 derivada")
            stage_index += 1
            continue

        elif stage_index == 3:
            if meetup_mode:
                _pause_for_meetup_phase(
                    phase_label="recorrer la fase D: ruta HD",
                    no_pause=no_pause,
                )
            if network_override is not None:
                network = network_override
            else:
                network = (
                    "mainnet" if (no_pause and not meetup_mode) else _prompt_network()
                )
            state["network"] = network
            if path_override is not None:
                path = path_override
            else:
                path = (
                    _default_path_for_network(network)
                    if (no_pause and not meetup_mode)
                    else _prompt_hd_path(str(state["network"]))
                )
            state["path"] = path
            try:
                path_artifacts = _print_phase_hd_path(
                    state["master"],
                    path,
                    str(state["network"]),
                    show_secrets=True,
                    interactive_micro_steps=(not no_pause) and (not meetup_mode),
                    meetup_mode=meetup_mode,
                )
            except UserCancelledFlow:
                print("Flujo cancelado por usuario. Salida limpia.")
                return 0
            state.update(path_artifacts)
            if not meetup_mode:
                print("\nEtapa 4/5 completada: ruta HD derivada")
            stage_index += 1
            continue

        else:
            if meetup_mode:
                _pause_for_meetup_phase(
                    phase_label="ver la fase E: clave pública a dirección",
                    no_pause=no_pause,
                )
            try:
                address_artifacts = _print_phase_address(
                    state["derived"],
                    str(state["network"]),
                    show_secrets=True,
                    interactive_micro_steps=(not no_pause) and (not meetup_mode),
                    meetup_mode=meetup_mode,
                )
            except UserCancelledFlow:
                print("Flujo cancelado por usuario. Salida limpia.")
                return 0
            state.update(address_artifacts)
            if meetup_mode:
                _pause_for_meetup_phase(
                    phase_label="ver la fase F: resumen final",
                    no_pause=no_pause,
                )
            _print_phase_final_summary(
                mnemonic=str(state["mnemonic"]),
                passphrase=str(state["passphrase"]),
                path=str(state["path"]),
                network=str(state["network"]),
                seed_bytes=state["seed_bytes"],
                master=state["master"],
                derived=state["derived"],
                final_addr=state["final_addr"],
                show_secrets=True,
                summary_raw=bool(state["summary_raw"]),
                meetup_mode=meetup_mode,
            )
            if not meetup_mode:
                print("\nEtapa 5/5 completada: direccion y resumen final")
            stage_index += 1

    return 0


def _print_compact_breakdown(breakdown) -> None:
    print("1. Resumen")
    print("   Por que: Vista rapida para validar valores clave de BIP39.")
    print(f"   Entropia (hex):      {breakdown.entropy_hex}")
    print(f"   Bits entropia:       {len(breakdown.entropy_bits)}")
    print(f"   Bits checksum:       {len(breakdown.checksum_bits)}")
    print(f"   Bits totales:        {len(breakdown.entropy_plus_checksum_bits)}")
    print(f"   Numero de palabras:  {len(breakdown.steps)}")
    print(f"   Mnemonic:            {breakdown.mnemonic}")


def _print_seed_derivation(
    mnemonic: str, passphrase: str, *, show_secrets: bool
) -> None:
    seed_bytes = derive_bip39_seed(mnemonic, passphrase)
    salt = build_bip39_seed_salt(passphrase)

    print()
    print("6. Seed BIP39")
    print("   Por que: Convierte la mnemotecnica en semilla binaria para BIP32.")
    print(f"   Mnemonic usada:      {mnemonic}")
    if passphrase:
        print(f"   Passphrase:          {passphrase}")
    else:
        print("   Passphrase:          (vacia)")
    print("   Salt PBKDF2:         'mnemonic' + passphrase")
    print(f"   Salt efectivo:       {salt}")
    print("   KDF:                 PBKDF2-HMAC-SHA512, iteraciones=2048")
    print(
        f"   Seed (hex, 64 bytes): {_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)}"
    )


def _print_bip32_derivation(seed_bytes: bytes, *, show_secrets: bool) -> None:
    master = derive_bip32_master_node(seed_bytes)
    print()
    print("7. Master node BIP32")
    print(
        "   Por que: BIP32 separa secreto (master key) y ruta de derivacion (chain code)."
    )
    print(
        f"   I = HMAC-SHA512:     {_display_sensitive(master.hmac_i.hex(), show_secrets=show_secrets)}  | Digest completo de 64 bytes"
    )
    print(
        f"   IL (master key):     {_display_sensitive(master.master_private_key.hex(), show_secrets=show_secrets)}  | 32 bytes izquierdos: private key maestra"
    )
    print(
        f"   IR (chain code):     {_display_sensitive(master.chain_code.hex(), show_secrets=show_secrets)}  | 32 bytes derechos: chain code del arbol"
    )
    print(
        f"   Master private key:  {_display_sensitive(master.master_private_key.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   Chain code:          {_display_sensitive(master.chain_code.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   xprv (mainnet):      {_display_sensitive(master.xprv, show_secrets=show_secrets)}"
    )
    print(f"   xpub (mainnet):      {master.xpub}")


def _print_bip32_path_derivation(
    seed_bytes: bytes, path: str, show_steps: bool, network: str, *, show_secrets: bool
) -> None:
    parsed = parse_bip32_path(path)
    master = derive_bip32_master_node(seed_bytes)
    current = derive_bip32_node_from_master(master)

    print()
    print("8. Ruta HD BIP32")
    print("   Por que: Permite derivar cuentas/direcciones sin exponer la master key.")
    print(f"   Ruta solicitada:     {path}")

    if show_steps:
        print("   Pasos:")
        if not parsed:
            print(
                "   - m (sin derivacion, se mantiene nodo master) | depth=0 y sin hijo aplicado"
            )
        for step in parsed:
            current = derive_bip32_path_from_node(current, f"m/{step.token}")
            index_label = (
                step.child_number - HARDENED_OFFSET
                if step.hardened
                else step.child_number
            )
            hardened_label = "hardened" if step.hardened else "normal"
            print(
                f"   - {step.token}: index={index_label}, tipo={hardened_label}, depth={current.depth}, fp_padre={current.parent_fingerprint.hex()} | index=numero hijo, tipo=hardened/normal, depth=nivel actual, fp_padre=huella del nodo padre"
            )
    else:
        current = derive_bip32_path_from_node(current, path)

    print(f"   Depth final:         {current.depth}")
    print(f"   Child number final:  {current.child_number}")
    print(f"   Parent fingerprint:  {current.parent_fingerprint.hex()}")
    print(
        f"   xprv derivado:       {_display_sensitive(current.xprv, show_secrets=show_secrets)}"
    )
    print(f"   xpub derivado:       {current.xpub}")

    p2wpkh = derive_p2wpkh_address_from_node(current, network)
    print()
    print("9. Direccion Bitcoin P2WPKH (Bech32)")
    print("   Por que: Convierte la pubkey derivada en direccion SegWit v0 utilizable.")
    print(f"   Red:                 {network} ({p2wpkh.hrp})")
    print(
        f"   Pubkey comprimida:   {_display_sensitive(p2wpkh.compressed_pubkey.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   HASH160(pubkey):     {_display_sensitive(p2wpkh.hash160.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   Witness program:     OP_{p2wpkh.witness_version} {p2wpkh.witness_program.hex()}"
    )
    print(f"   Direccion final:     {p2wpkh.address}")


def _default_path_for_network(network: str) -> str:
    if network == "testnet":
        return "m/84'/1'/0'/0/0"
    return "m/84'/0'/0'/0/0"


def _derive_path_artifacts(
    seed_bytes: bytes, path: str, network: str
) -> dict[str, str]:
    master = derive_bip32_master_node(seed_bytes)
    root = derive_bip32_node_from_master(master)
    node = derive_bip32_path_from_node(root, path)
    addr = derive_p2wpkh_address_from_node(node, network)
    return {
        "path": path,
        "xprv": node.xprv,
        "xpub": node.xpub,
        "address": addr.address,
    }


def _build_pipeline_artifacts(
    *,
    entropy: bytes | None,
    mnemonic: str,
    passphrase: str,
    path: str,
    network: str,
) -> dict[str, object]:
    seed_bytes = derive_bip39_seed(mnemonic, passphrase)
    master = derive_bip32_master_node(seed_bytes)
    root = derive_bip32_node_from_master(master)
    derived = derive_bip32_path_from_node(root, path)
    final_addr = derive_p2wpkh_address_from_node(derived, network)

    entropy_hex = entropy.hex() if entropy is not None else None
    return {
        "entropy_hex": entropy_hex,
        "mnemonic": mnemonic,
        "passphrase": passphrase,
        "seed_bytes": seed_bytes,
        "seed_fingerprint": hashlib.sha256(seed_bytes).hexdigest(),
        "salt": build_bip39_seed_salt(passphrase),
        "master": master,
        "derived": derived,
        "final_addr": final_addr,
        "path": path,
        "network": network,
    }


def _print_tui_read_only_panels(
    artifacts: dict[str, object], *, show_secrets: bool
) -> int:
    print("+--------------------------------------------------------------------+")
    print("| Seed Steps - TUI Educativa (READ-ONLY)                             |")
    print("+--------------------------------------------------------------------+")

    entropy_hex = artifacts["entropy_hex"]
    mnemonic = artifacts["mnemonic"]
    passphrase = artifacts["passphrase"]
    seed_bytes = artifacts["seed_bytes"]
    master = artifacts["master"]
    derived = artifacts["derived"]
    final_addr = artifacts["final_addr"]
    path = artifacts["path"]
    network = artifacts["network"]

    print("[Panel 1/3] Inputs usados")
    print(
        f"- entropy:    {entropy_hex if entropy_hex else '(no provista: entrada por --mnemonic)'}"
    )
    print(f"- mnemonic:   {mnemonic}")
    print(f"- passphrase: {passphrase or '(vacia)'}")
    print(f"- path:       {path}")
    print(f"- network:    {network}")
    print()

    print("[Panel 2/3] Resultado por etapa")
    print(f"- BIP39 mnemonic:  {mnemonic}")
    print(
        "- BIP39 seed:      "
        f"{_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)}"
    )
    print(
        "- BIP32 master:    "
        f"xprv={_display_sensitive(master.xprv, show_secrets=show_secrets)} | xpub={master.xpub}"
    )
    print(
        "- BIP32 ruta:      "
        f"xprv={_display_sensitive(derived.xprv, show_secrets=show_secrets)} | xpub={derived.xpub}"
    )
    print(f"- P2WPKH address:  {final_addr.address}")
    print()

    print("[Panel 3/3] Resumen ejecutivo")
    print(f"- red:             {network} ({final_addr.hrp})")
    print(f"- ruta final:      {path}")
    print(f"- salt PBKDF2:     {artifacts['salt']}")
    print(f"- seed sha256:     {artifacts['seed_fingerprint']}")
    print(f"- direccion final: {final_addr.address}")
    print("- politica:        secreto redactado por defecto")
    print("- advertencia:     EDUCATIVO, NO CUSTODIA REAL")
    return 0


def _print_full_journey(
    *,
    entropy: bytes | None,
    mnemonic: str,
    passphrase: str,
    path: str,
    network: str,
    wordlist: list[str],
    compare_passphrase: str | None,
    compare_path: str | None,
    show_secrets: bool,
) -> int:
    _print_header()
    print("Modo: Full Journey E2E (educativo guiado)")
    print()

    if entropy is not None:
        breakdown = build_bip39_breakdown(entropy, wordlist)
        print("1. Entropia -> Mnemotecnica (BIP39)")
        print("   Que es: Entropia cruda convertida a palabras mediante checksum.")
        print(
            "   Por que importa: La calidad de esta entropia define todo el arbol de claves."
        )
        print(
            "   Que se rompe si cambia: Cambia la mnemotecnica y TODO (seed/xprv/xpub/direcciones)."
        )
        print(f"   Entropia (hex):      {breakdown.entropy_hex}")
        print(f"   Checksum bits:       {breakdown.checksum_bits}")
        print(f"   Mnemotecnica:        {breakdown.mnemonic}")
    else:
        breakdown = None
        print("1. Entrada mnemotecnica explicita")
        print(
            "   Que es: Se recibe una mnemotecnica ya formada (no se recalcula entropia)."
        )
        print(
            "   Por que importa: Permite continuar el flujo sin exponer el origen de la entropia."
        )
        print(
            "   Que se rompe si cambia: Una sola palabra distinta cambia toda la seed y derivaciones."
        )
        print(f"   Mnemotecnica:        {mnemonic}")

    artifacts = _build_pipeline_artifacts(
        entropy=entropy,
        mnemonic=mnemonic,
        passphrase=passphrase,
        path=path,
        network=network,
    )
    seed_bytes = artifacts["seed_bytes"]
    seed_fingerprint = artifacts["seed_fingerprint"]
    master = artifacts["master"]
    derived = artifacts["derived"]
    final_addr = artifacts["final_addr"]

    print()
    print("2. Mnemotecnica -> Seed (BIP39 PBKDF2)")
    print("   Que es: KDF PBKDF2-HMAC-SHA512 (2048 iteraciones) sobre mnemonic + salt.")
    print(
        "   Por que importa: Endurece la derivacion y soporta passphrase como factor extra."
    )
    print("   Que se rompe si cambia: Passphrase distinta => seed totalmente distinta.")
    print(f"   Passphrase usada:    {passphrase or '(vacia)'}")
    print(f"   Salt efectivo:       {build_bip39_seed_salt(passphrase)}")
    print(
        f"   Seed (hex, 64 bytes): {_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)}"
    )

    print()
    print("3. Seed -> Master BIP32")
    print("   Que es: HMAC-SHA512('Bitcoin seed', seed) para obtener IL/IR.")
    print(
        "   Por que importa: IL inicia el secreto maestro y IR el chain code del arbol HD."
    )
    print(
        "   Que se rompe si cambia: Se altera todo el arbol de derivacion (xprv/xpub/hijos)."
    )
    print(
        f"   xprv master:         {_display_sensitive(master.xprv, show_secrets=show_secrets)}"
    )
    print(f"   xpub master:         {master.xpub}")

    print()
    print("4. Master -> Ruta derivada")
    print("   Que es: Aplicar la ruta HD para llegar a una clave hija concreta.")
    print("   Por que importa: Separa cuentas/ramas y evita reutilizacion de claves.")
    print(
        "   Que se rompe si cambia: Ruta diferente => xprv/xpub/direccion diferentes."
    )
    print(f"   Ruta usada:          {path}")
    print(
        f"   xprv derivado:       {_display_sensitive(derived.xprv, show_secrets=show_secrets)}"
    )
    print(f"   xpub derivado:       {derived.xpub}")

    print()
    print("5. Ruta derivada -> Direccion P2WPKH")
    print("   Que es: Pubkey comprimida -> HASH160 -> Bech32 SegWit v0.")
    print("   Por que importa: Es la direccion compatible para recibir BTC.")
    print("   Que se rompe si cambia: Pubkey/ruta/red distinta => direccion distinta.")
    print(f"   Red:                 {network} ({final_addr.hrp})")
    print(f"   Direccion final:     {final_addr.address}")

    if compare_passphrase:
        print()
        print("6. Comparador pedagogico: passphrase vacia vs valor")
        print(
            "   Que se compara: mismo mnemonic, passphrase='' frente a passphrase personalizada."
        )
        empty_seed = derive_bip39_seed(mnemonic, "")
        custom_seed = derive_bip39_seed(mnemonic, compare_passphrase)
        empty_artifacts = _derive_path_artifacts(empty_seed, path, network)
        custom_artifacts = _derive_path_artifacts(custom_seed, path, network)
        print(
            f"   Caso A (vacia) seed: {_display_sensitive(empty_seed.hex(), show_secrets=show_secrets)}"
        )
        print(
            f"   Caso B ('{compare_passphrase}') seed: {_display_sensitive(custom_seed.hex(), show_secrets=show_secrets)}"
        )
        print(
            f"   A xprv:              {_display_sensitive(empty_artifacts['xprv'], show_secrets=show_secrets)}"
        )
        print(
            f"   B xprv:              {_display_sensitive(custom_artifacts['xprv'], show_secrets=show_secrets)}"
        )
        print(f"   A xpub:              {empty_artifacts['xpub']}")
        print(f"   B xpub:              {custom_artifacts['xpub']}")
        print(f"   A direccion:         {empty_artifacts['address']}")
        print(f"   B direccion:         {custom_artifacts['address']}")

    if compare_path:
        print()
        print("7. Comparador pedagogico: ruta A vs ruta B")
        print("   Que se compara: misma seed, dos rutas HD distintas.")
        path_a = _derive_path_artifacts(seed_bytes, path, network)
        path_b = _derive_path_artifacts(seed_bytes, compare_path, network)
        print(f"   Ruta A:              {path_a['path']}")
        print(f"   Ruta B:              {path_b['path']}")
        print(
            f"   A xprv:              {_display_sensitive(path_a['xprv'], show_secrets=show_secrets)}"
        )
        print(
            f"   B xprv:              {_display_sensitive(path_b['xprv'], show_secrets=show_secrets)}"
        )
        print(f"   A xpub:              {path_a['xpub']}")
        print(f"   B xpub:              {path_b['xpub']}")
        print(f"   A direccion:         {path_a['address']}")
        print(f"   B direccion:         {path_b['address']}")

    print()
    print("Resumen ejecutivo")
    print(f"   Red:                 {network}")
    print(f"   Ruta final:          {path}")
    print(f"   Mnemotecnica usada:  {mnemonic}")
    print(f"   Seed resumen:        sha256={seed_fingerprint}")
    print(f"   xpub derivada:       {derived.xpub}")
    print(f"   Direccion final:     {final_addr.address}")
    print("   ADVERTENCIA: EDUCATIVO, NO CUSTODIA REAL")
    return 0


def run() -> int:
    parser = build_parser()
    args = parser.parse_args()
    ts.set_enabled(ts.should_use_color(no_color_flag=args.no_color))

    wordlist_path = files("seed_steps").joinpath("data/english.txt")

    try:
        with as_file(wordlist_path) as resolved_path:
            wordlist = load_wordlist(resolved_path)
    except FileNotFoundError as exc:
        print(
            _error_message(
                "OPERATIVO",
                f"no se encontro la wordlist BIP39 ({exc})",
                "verifica que exista seed_steps/data/english.txt en la instalacion",
            ),
            file=sys.stderr,
        )
        return 3
    except ValueError as exc:
        print(
            _error_message(
                "CONFIGURACION",
                f"wordlist BIP39 invalida ({exc})",
                "asegura 2048 palabras no vacias en english.txt",
            ),
            file=sys.stderr,
        )
        return 3

    meetup_mode = args.tamariz

    if args.interactive or meetup_mode:
        preset_entropy = None
        argv_tokens = sys.argv[1:]
        network_override = (
            args.network if (meetup_mode and "--network" in argv_tokens) else None
        )
        path_override = args.path if (meetup_mode and "--path" in argv_tokens) else None
        if args.entropy:
            try:
                preset_entropy = parse_entropy_hex(args.entropy)
            except ValueError as exc:
                print(
                    _error_message(
                        "ENTRADA",
                        f"valor invalido en --entropy ({exc})",
                        "usa un hexadecimal valido de 128/160/192/224/256 bits",
                    ),
                    file=sys.stderr,
                )
                return 2
        return _run_interactive(
            wordlist,
            preset_entropy=preset_entropy,
            no_pause=args.no_pause,
            default_passphrase=args.passphrase,
            summary_raw=args.summary_raw,
            meetup_mode=meetup_mode,
            network_override=network_override,
            path_override=path_override,
        )

    show_secrets = args.show_secrets and not args.no_secrets
    if show_secrets:
        _print_secrets_warning()
        print()

    if args.tui:
        if args.mnemonic:
            mnemonic = args.mnemonic
            entropy = None
        else:
            try:
                entropy = (
                    parse_entropy_hex(args.entropy)
                    if args.entropy
                    else generate_entropy(16)
                )
            except ValueError as exc:
                print(
                    _error_message(
                        "ENTRADA",
                        f"valor invalido en --entropy ({exc})",
                        "usa un hexadecimal valido de 128/160/192/224/256 bits",
                    ),
                    file=sys.stderr,
                )
                return 2
            try:
                breakdown = build_bip39_breakdown(entropy, wordlist)
            except ValueError as exc:
                print(
                    _error_message(
                        "DOMINIO BIP39",
                        f"validacion de reglas BIP39 fallida ({exc})",
                        "revisa la entropia y la integridad de la wordlist",
                    ),
                    file=sys.stderr,
                )
                return 4
            mnemonic = breakdown.mnemonic

        tui_path = args.path or _default_path_for_network(args.network)
        try:
            artifacts = _build_pipeline_artifacts(
                entropy=entropy,
                mnemonic=mnemonic,
                passphrase=args.passphrase,
                path=tui_path,
                network=args.network,
            )
            return _print_tui_read_only_panels(artifacts, show_secrets=show_secrets)
        except ValueError as exc:
            print(
                _error_message(
                    "DOMINIO BIP32",
                    f"no se pudo derivar flujo TUI ({exc})",
                    "verifica seed, ruta y red para la derivacion",
                ),
                file=sys.stderr,
            )
            return 4

    if args.full_journey:
        if args.mnemonic:
            mnemonic = args.mnemonic
            entropy = None
        else:
            try:
                entropy = (
                    parse_entropy_hex(args.entropy)
                    if args.entropy
                    else generate_entropy(16)
                )
            except ValueError as exc:
                print(
                    _error_message(
                        "ENTRADA",
                        f"valor invalido en --entropy ({exc})",
                        "usa un hexadecimal valido de 128/160/192/224/256 bits",
                    ),
                    file=sys.stderr,
                )
                return 2
            try:
                breakdown = build_bip39_breakdown(entropy, wordlist)
            except ValueError as exc:
                print(
                    _error_message(
                        "DOMINIO BIP39",
                        f"validacion de reglas BIP39 fallida ({exc})",
                        "revisa la entropia y la integridad de la wordlist",
                    ),
                    file=sys.stderr,
                )
                return 4
            mnemonic = breakdown.mnemonic

        full_path = args.path or _default_path_for_network(args.network)
        try:
            return _print_full_journey(
                entropy=entropy,
                mnemonic=mnemonic,
                passphrase=args.passphrase,
                path=full_path,
                network=args.network,
                wordlist=wordlist,
                compare_passphrase=args.compare_passphrase,
                compare_path=args.compare_path,
                show_secrets=show_secrets,
            )
        except ValueError as exc:
            print(
                _error_message(
                    "DOMINIO BIP32",
                    f"no se pudo derivar flujo completo ({exc})",
                    "verifica seed, ruta y red para la derivacion",
                ),
                file=sys.stderr,
            )
            return 4

    if args.mnemonic:
        _print_header()
        seed_bytes = derive_bip39_seed(args.mnemonic, args.passphrase)
        _print_seed_derivation(
            args.mnemonic, args.passphrase, show_secrets=show_secrets
        )
        if args.derive_bip32 or args.path:
            try:
                _print_bip32_derivation(seed_bytes, show_secrets=show_secrets)
                if args.path:
                    _print_bip32_path_derivation(
                        seed_bytes,
                        args.path,
                        args.path_steps,
                        args.network,
                        show_secrets=show_secrets,
                    )
            except ValueError as exc:
                print(
                    _error_message(
                        "DOMINIO BIP32",
                        f"no se pudo derivar master node ({exc})",
                        "verifica que la seed sea valida para BIP32",
                    ),
                    file=sys.stderr,
                )
                return 4
        return 0

    try:
        entropy = (
            parse_entropy_hex(args.entropy) if args.entropy else generate_entropy(16)
        )
    except ValueError as exc:
        print(
            _error_message(
                "ENTRADA",
                f"valor invalido en --entropy ({exc})",
                "usa un hexadecimal valido de 128/160/192/224/256 bits",
            ),
            file=sys.stderr,
        )
        return 2

    try:
        breakdown = build_bip39_breakdown(entropy, wordlist)
    except ValueError as exc:
        print(
            _error_message(
                "DOMINIO BIP39",
                f"validacion de reglas BIP39 fallida ({exc})",
                "revisa la entropia y la integridad de la wordlist",
            ),
            file=sys.stderr,
        )
        return 4

    _print_header()
    if args.compact:
        _print_compact_breakdown(breakdown)
    else:
        _print_detailed_breakdown(breakdown)

    seed_bytes = None
    if args.derive_seed or args.passphrase or args.derive_bip32 or args.path:
        seed_bytes = derive_bip39_seed(breakdown.mnemonic, args.passphrase)
        _print_seed_derivation(
            breakdown.mnemonic, args.passphrase, show_secrets=show_secrets
        )
    if args.derive_bip32 or args.path:
        try:
            _print_bip32_derivation(seed_bytes, show_secrets=show_secrets)
            if args.path:
                _print_bip32_path_derivation(
                    seed_bytes,
                    args.path,
                    args.path_steps,
                    args.network,
                    show_secrets=show_secrets,
                )
        except ValueError as exc:
            print(
                _error_message(
                    "DOMINIO BIP32",
                    f"no se pudo derivar master node ({exc})",
                    "verifica que la seed sea valida para BIP32",
                ),
                file=sys.stderr,
            )
            return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
