"""CLI entrypoint for Seed Steps educational BIP39 walkthrough."""

from __future__ import annotations

import argparse
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
)
from seed_steps.bip39 import build_bip39_breakdown, load_wordlist
from seed_steps.entropy import generate_entropy, parse_entropy_hex
from seed_steps.format import group_binary
from seed_steps.seed import build_bip39_seed_salt, derive_bip39_seed
from seed_steps.trace import MathTrace


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


COLOR_RESET = "\033[0m"
COLOR_ENTROPY = "\033[96m"
COLOR_CHECKSUM = "\033[93m"
COLOR_WORD = "\033[38;5;208m"
COLOR_PASSPHRASE = "\033[95m"
COLOR_SEED = "\033[92m"
COLOR_IL = "\033[94m"
COLOR_IR = "\033[35m"
COLOR_XPRV = "\033[91m"
COLOR_XPUB = "\033[36m"
COLOR_FINAL_ADDRESS = "\033[92m"


def _colorize(value: str, color: str, *, enable: bool = True) -> str:
    if not enable:
        return value
    return f"{color}{value}{COLOR_RESET}"


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
        "--no-pause",
        action="store_true",
        help="En wizard, desactiva pausas y confirmaciones entre pasos.",
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
    color_yellow = "\033[93m"
    color_reset = "\033[0m"
    colored_bits = breakdown.entropy_plus_checksum_bits
    if use_color:
        colored_bits = (
            f"{color_cyan}{breakdown.entropy_bits}{color_reset}"
            f"{color_yellow}{breakdown.checksum_bits}{color_reset}"
        )

    print("3. Bits combinados")
    print("   Por que: BIP39 une entropia y checksum antes de partir en bloques de 11.")
    if use_color:
        print("   Leyenda color:       ENTROPIA=cian | CHECKSUM=amarillo")
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
    print("   Leyenda color:       ENTROPIA=cian | CHECKSUM=amarillo")
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


def _prompt_source_choice(
    wordlist: list[str],
) -> tuple[bytes | None, str, str, int | None]:
    while True:
        choice = (
            input(
                "\nPaso 1 - Elige el punto de partida: [A] Entropia automatica / [E] Entropia manual / [M] Mnemotecnica manual: "
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
        "Subpaso BIP39 1/5: Entropia",
        "Subpaso BIP39 2/5: Checksum",
        "Subpaso BIP39 3/5: Bits combinados",
        "Subpaso BIP39 4/5: Indices (bloques de 11 bits)",
        "Subpaso BIP39 5/5: Mnemotecnica",
    ]

    all_traces = _build_bip39_math_traces(breakdown)
    traces_by_substep = {
        0: all_traces[0:3],
        1: all_traces[3:6],
        2: all_traces[6:7],
        3: all_traces[7:9],
        4: all_traces[9:11],
    }

    index = 0
    while index < len(substeps):
        title = substeps[index]
        print(f"\n{title}")
        print("   Objetivo del paso: entender esta transformacion antes de avanzar.")
        if index == 0:
            _print_stage_entropy(breakdown)
            entropy_bits = selected_entropy_bits or len(breakdown.entropy_bits)
            print(
                "   Que debes observar: tamano de bits y que la fuente coincide con lo elegido."
            )
            print(
                f"   Fuente usada:        {source_label} (wizard) | tamano elegido: {_colorize(str(entropy_bits), COLOR_ENTROPY)} bits"
            )
            _render_integrated_math_for_substep(
                traces_by_substep[index],
                next_input_label="entropy_bits",
                next_input_value=breakdown.entropy_bits,
            )
        elif index == 1:
            _print_stage_checksum(breakdown)
            ent_bits = len(breakdown.entropy_bits)
            checksum_bits = ent_bits // 32
            print(
                "   Que debes observar: dividir los bits de entropia entre 32 define cuantos bits de checksum se agregan."
            )
            print(
                f"   Calculo docente:     {ent_bits} bits / 32 = {checksum_bits} bits de checksum, tomados del inicio de SHA-256(entropia)"
            )
            _render_integrated_math_for_substep(
                traces_by_substep[index],
                next_input_label="checksum_bits",
                next_input_value=breakdown.checksum_bits,
            )
        elif index == 2:
            _print_stage_combined_bits(breakdown, use_color=True)
            print(
                "   Que debes observar: cian=entropia y amarillo=checksum dentro del mismo flujo de bits."
            )
            _render_integrated_math_for_substep(
                traces_by_substep[index],
                next_input_label="entropy_plus_checksum_bits",
                next_input_value=breakdown.entropy_plus_checksum_bits,
            )
        elif index == 3:
            _print_stage_indices_colored(breakdown)
            print(
                "   Que debes observar: cada bloque de 11 bits se convierte en un indice de la wordlist."
            )
            _render_integrated_math_for_substep(
                traces_by_substep[index],
                next_input_label="indices",
                next_input_value=str([step.index for step in breakdown.steps]),
            )
        else:
            _print_stage_mnemonic_colored(breakdown)
            print(
                "   Que debes observar: el orden de palabras depende exactamente del orden de bloques."
            )
            _render_integrated_math_for_substep(
                traces_by_substep[index],
                next_input_label="mnemonic",
                next_input_value=breakdown.mnemonic,
            )

        action = (
            "continue" if not pause_between_steps else _prompt_continue_with_options()
        )
        if action == "cancel":
            return "cancel"
        if action == "retry":
            continue
        index += 1

    return "continue"


def _print_phase_seed_bip39(
    *,
    mnemonic: str,
    passphrase: str,
    show_secrets: bool,
    interactive_micro_steps: bool = False,
) -> dict[str, object]:
    _prompt_micro_operation(
        number=1,
        input_data="mnemonic cruda del usuario",
        operation="normalizar mnemotecnica (NFKD)",
        output_data="mnemonic normalizada",
        enable=interactive_micro_steps,
    )
    mnemonic_value = _colorize(mnemonic, COLOR_WORD)
    print(f"\n   [micro] Mnemonic normalizada: {mnemonic_value}")

    passphrase_display = _display_sensitive(
        passphrase or "(vacia)", show_secrets=show_secrets
    )
    _prompt_micro_operation(
        number=2,
        input_data="passphrase del usuario (o vacia)",
        operation="normalizar passphrase y concatenar con prefijo 'mnemonic'",
        output_data="salt efectivo para PBKDF2",
        enable=interactive_micro_steps,
    )
    salt = build_bip39_seed_salt(passphrase)
    print(
        "   [micro] Salt = "
        f"'mnemonic' + {_colorize(passphrase_display, COLOR_PASSPHRASE)} => {_colorize(salt, COLOR_PASSPHRASE)}"
    )

    _prompt_micro_operation(
        number=3,
        input_data="mnemonic normalizada + salt",
        operation="PBKDF2-HMAC-SHA512 (2048 iteraciones)",
        output_data="seed BIP39 de 64 bytes",
        enable=interactive_micro_steps,
    )
    seed_bytes = derive_bip39_seed(mnemonic, passphrase)
    print("\nFase B) Seed BIP39")
    print("   Objetivo del paso: convertir la mnemotecnica en una seed de 64 bytes.")
    print(
        "   Lectura docente: tomamos tu frase y la pasamos por una maquina de estiramiento criptografico."
    )
    print(
        "   Que debes observar: cambiar passphrase produce una seed completamente distinta."
    )
    print("   Que entra:")
    print(f"   - Mnemonic:           {mnemonic_value}")
    print()
    print(f"   - Passphrase:         {_colorize(passphrase_display, COLOR_PASSPHRASE)}")
    print()
    print("   Que operacion se hace:")
    print(
        "   - Formula mental: "
        f"{_colorize('seed', COLOR_SEED)} = PBKDF2("
        f"{_colorize('mnemonic', COLOR_WORD)}, salt='mnemonic'+{_colorize('passphrase', COLOR_PASSPHRASE)}, 2048)"
    )
    print("   - Motor real: PBKDF2-HMAC-SHA512, iteraciones=2048")
    print()
    print(f"   - Salt:               {_colorize(salt, COLOR_PASSPHRASE)}")
    print()
    print("   Que sale:")
    print(
        f"   - Seed (hex, 64 bytes): {_colorize(_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets), COLOR_SEED)}"
    )
    return {"seed_bytes": seed_bytes, "salt": salt}


def _print_phase_master_bip32(
    seed_bytes: bytes, *, show_secrets: bool, interactive_micro_steps: bool = False
) -> dict[str, object]:
    _prompt_micro_operation(
        number=1,
        input_data="seed BIP39 (64 bytes)",
        operation="preparar seed como mensaje para HMAC",
        output_data="mensaje listo para HMAC-SHA512",
        enable=interactive_micro_steps,
    )
    seed_hex = _display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)
    print(f"\n   [micro] Seed entrada: {_colorize(seed_hex, COLOR_SEED)}")
    _prompt_micro_operation(
        number=2,
        input_data="clave='Bitcoin seed' + mensaje=seed",
        operation="HMAC-SHA512(clave, mensaje)",
        output_data="digest I (IL || IR)",
        enable=interactive_micro_steps,
    )
    master = derive_bip32_master_node(seed_bytes)
    hmac_hex = _display_sensitive(master.hmac_i.hex(), show_secrets=show_secrets)
    il_hex = _display_sensitive(
        master.master_private_key.hex(), show_secrets=show_secrets
    )
    ir_hex = _display_sensitive(master.chain_code.hex(), show_secrets=show_secrets)
    i_colored = _colorize(il_hex, COLOR_IL) + _colorize(ir_hex, COLOR_IR)

    _prompt_micro_operation(
        number=3,
        input_data="IL (master key) + IR (chain code)",
        operation="serializar payload xprv (BIP32 mainnet)",
        output_data="xprv payload previo a Base58Check",
        enable=interactive_micro_steps,
    )
    xprv_key_data = "00" + master.master_private_key.hex()
    xprv_payload = (
        MAINNET_XPRV_VERSION.hex()
        + "00"
        + "00000000"
        + "00000000"
        + master.chain_code.hex()
        + xprv_key_data
    )
    _prompt_micro_operation(
        number=4,
        input_data="pubkey comprimida + chain code",
        operation="serializar payload xpub (BIP32 mainnet)",
        output_data="xpub payload previo a Base58Check",
        enable=interactive_micro_steps,
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

    print("\nFase C) Master BIP32")
    print(
        "   Objetivo del paso: obtener la clave maestra y el chain code del arbol HD."
    )
    print(
        "   Lectura docente: desde la seed nacen dos piezas: secreto maestro y cadena de derivacion."
    )
    print(
        "   Que debes observar: IL e IR salen del mismo HMAC, pero cumplen funciones distintas."
    )
    print("   Que entra:")
    print(f"   - Seed:               {_colorize(seed_hex, COLOR_SEED)}")
    print()
    print("   Que operacion se hace:")
    print(f"   - Clave HMAC:         {_colorize('Bitcoin seed', COLOR_IR)}")
    print(
        "   - Origen de esa clave: constante fija del estandar BIP32 para derivar la master key."
    )
    print()
    print(f"   - Entrada HMAC:       {_colorize(seed_hex, COLOR_SEED)}")
    print()
    print("   - Operacion:          HMAC-SHA512(clave, entrada)")
    print()
    print("   Que sale:")
    print(f"   - I:                  {i_colored}  | IL(izq, azul) + IR(der, morado)")
    print()
    print(
        f"   - IL (master key):    {_colorize(il_hex, COLOR_IL)}  | Mitad izquierda: clave privada raiz"
    )
    print()
    print(
        f"   - IR (chain code):    {_colorize(ir_hex, COLOR_IR)}  | Mitad derecha: cadena que guia derivaciones"
    )
    print()
    print(f"   - Payload xprv:       {_colorize(xprv_payload, COLOR_XPRV)}")
    print(f"   - Payload xpub:       {_colorize(xpub_payload, COLOR_XPUB)}")
    print()
    print(
        f"   - xprv:               {_colorize(_display_sensitive(master.xprv, show_secrets=show_secrets), COLOR_XPRV)}  | Empaquetado del nodo privado maestro"
    )
    print()
    print(
        f"   - xpub:               {_colorize(master.xpub, COLOR_XPUB)}  | Version publica para derivar/consultar sin firmar"
    )
    print(
        "   Explicacion simple: xprv firma y deriva; xpub solo deriva/consulta direcciones."
    )
    return {"master": master}


def _print_phase_hd_path(
    master, path: str, *, show_secrets: bool, interactive_micro_steps: bool = False
) -> dict[str, object]:
    parsed = parse_bip32_path(path)
    current = derive_bip32_node_from_master(master)
    print("\nFase D) Ruta HD")
    print("   Objetivo del paso: llegar desde la raiz a una clave hija especifica.")
    print(
        "   Mapa mental BIP44/BIP84: m / purpose' / coin_type' / account' / change / index"
    )
    print(
        "   Que debes observar: un solo cambio en la ruta termina en otra clave y otra direccion."
    )
    print("   Que entra:")
    print(f"   - Ruta:               {path}")
    print()
    route_tokens = ["m"] + [step.token for step in parsed]
    level_labels = [
        "raiz",
        "purpose'",
        "coin_type'",
        "account'",
        "change",
        "index",
    ]
    print("   Tabla de niveles para ESTA ruta:")
    print("   nivel | valor   | significado")
    print("   ------+---------+------------------------------")
    for i, label in enumerate(level_labels):
        value = route_tokens[i] if i < len(route_tokens) else "(no aplica)"
        print(f"   {i:>5} | {value:<7} | {label}")
    print("   Que operacion se hace:")
    print("   - Derivacion nivel por nivel (de m hacia la hoja)")
    print()
    if not parsed:
        print("   - m (sin derivacion) | Se mantiene el nodo maestro en depth=0")
    for micro_index, step in enumerate(parsed, start=1):
        _prompt_micro_operation(
            number=micro_index,
            input_data=f"nodo nivel={current.depth} + paso={step.token}",
            operation="CKDpriv segun tipo hardened/normal",
            output_data="nodo hijo del siguiente nivel",
            enable=interactive_micro_steps,
        )
        current = derive_bip32_path_from_node(current, f"m/{step.token}")
        index_label = (
            step.child_number - HARDENED_OFFSET if step.hardened else step.child_number
        )
        hardened_label = "hardened" if step.hardened else "normal"
        print(
            f"   - {step.token}: index={index_label}, tipo={hardened_label}, nivel={current.depth}, fp_padre={current.parent_fingerprint.hex()}  | fp_padre=huella corta (4 bytes) del nodo padre; avanzamos un nivel del mapa HD"
        )
    print("   Que sale:")
    print(f"   - Nodo depth final:   {current.depth}")
    print(
        f"   - xprv derivado:      {_colorize(_display_sensitive(current.xprv, show_secrets=show_secrets), COLOR_XPRV)}"
    )
    print()
    print(f"   - xpub derivado:      {_colorize(current.xpub, COLOR_XPUB)}")
    return {"derived": current}


def _print_phase_address(
    derived, network: str, *, show_secrets: bool, interactive_micro_steps: bool = False
) -> dict[str, object]:
    _prompt_micro_operation(
        number=1,
        input_data="nodo derivado (clave privada hija)",
        operation="extraer pubkey comprimida",
        output_data="pubkey comprimida lista para hash",
        enable=interactive_micro_steps,
    )
    p2wpkh = derive_p2wpkh_address_from_node(derived, network)
    print("\nFase E) Direccion")
    print(
        "   Objetivo del paso: transformar la clave publica derivada en direccion usable."
    )
    print(
        "   Contexto: la pubkey comprimida sale del nodo derivado (clave privada hija)."
    )
    print("   Que debes observar: red y ruta afectan directamente el resultado final.")
    print("   Que entra:")
    print(
        f"   - Pubkey comprimida:  {_colorize(_display_sensitive(p2wpkh.compressed_pubkey.hex(), show_secrets=show_secrets), COLOR_XPUB)}"
    )
    print()
    print(f"   - Red:                {network}")
    _prompt_micro_operation(
        number=2,
        input_data="pubkey comprimida",
        operation="HASH160(pubkey)",
        output_data="hash160 (20 bytes)",
        enable=interactive_micro_steps,
    )
    hash160_hex = _display_sensitive(p2wpkh.hash160.hex(), show_secrets=show_secrets)
    _prompt_micro_operation(
        number=3,
        input_data="hash160 + witness_version=0",
        operation="formar witness program SegWit v0",
        output_data="script witness OP_0 <20-byte-hash>",
        enable=interactive_micro_steps,
    )
    witness_line = f"OP_{p2wpkh.witness_version} {p2wpkh.witness_program.hex()}"
    _prompt_micro_operation(
        number=4,
        input_data="hrp de red + witness program",
        operation="codificar Bech32",
        output_data="direccion P2WPKH final",
        enable=interactive_micro_steps,
    )
    print("   Que operacion se hace:")
    print(
        "   - Flujo completo: "
        f"contexto priv/pub -> {_colorize('pubkey comprimida', COLOR_XPUB)}"
        f" -> {_colorize('HASH160', COLOR_IR)} -> witness program -> Bech32"
    )
    print("   Que sale:")
    print(f"   - HASH160:            {_colorize(hash160_hex, COLOR_IR)}")
    print()
    print(f"   - Witness:            {_colorize(witness_line, COLOR_CHECKSUM)}")
    print()
    print(f"   - Direccion final:    {_colorize(p2wpkh.address, COLOR_FINAL_ADDRESS)}")
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
) -> None:
    print("\nFase F) Resumen final")
    print("   Objetivo del paso: consolidar entradas y salidas clave del recorrido.")
    print(
        "   Que debes observar: con estos mismos datos siempre obtienes el mismo resultado."
    )
    print("   Inputs usados:")
    colored_mnemonic = " ".join(
        _colorize(word, COLOR_WORD) for word in mnemonic.split()
    )
    print(f"   - Mnemonic:           {colored_mnemonic}")
    print()
    print(
        f"   - Passphrase:         {_colorize(_display_sensitive(passphrase or '(vacia)', show_secrets=show_secrets), COLOR_PASSPHRASE)}"
    )
    print()
    print(f"   - Ruta:               {path}")
    print()
    print(f"   - Red:                {network}")
    print()
    print("   Outputs clave:")
    print(
        f"   - Seed:               {_colorize(_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets), COLOR_SEED)}"
    )
    print()
    print(
        f"   - IL master:          {_colorize(_display_sensitive(master.master_private_key.hex(), show_secrets=show_secrets), COLOR_IL)}"
    )
    print()
    print(
        f"   - IR master:          {_colorize(_display_sensitive(master.chain_code.hex(), show_secrets=show_secrets), COLOR_IR)}"
    )
    print()
    print(
        f"   - xprv master:        {_colorize(_display_sensitive(master.xprv, show_secrets=show_secrets), COLOR_XPRV)}"
    )
    print()
    print(f"   - xpub master:        {_colorize(master.xpub, COLOR_XPUB)}")
    print()
    print(
        f"   - xprv derivado:      {_colorize(_display_sensitive(derived.xprv, show_secrets=show_secrets), COLOR_XPRV)}"
    )
    print()
    print(f"   - xpub derivado:      {_colorize(derived.xpub, COLOR_XPUB)}")
    print()
    print(
        f"   - Direccion final:    {_colorize(final_addr.address, COLOR_FINAL_ADDRESS)}"
    )
    print()
    print("   ADVERTENCIA: EDUCATIVO, NO CUSTODIA REAL")


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
    wordlist: list[str], *, preset_entropy: bytes | None = None, no_pause: bool = False
) -> int:
    _print_header()
    print("Bienvenido a Seed Steps by SvenS101")
    print(
        "Avanzamos por pasos cortos: eliges entrada, ves operacion y confirmas salida."
    )
    print(
        "Nota docente: en el wizard se muestran valores COMPLETOS para fines de aprendizaje."
    )
    print(
        "No uses material real; la politica segura por defecto sigue activa fuera del wizard."
    )

    state: dict[str, object] = {
        "entropy": None,
        "mnemonic": "",
        "source_label": "",
        "selected_entropy_bits": None,
        "passphrase": "",
        "network": "mainnet",
        "path": "",
        "show_secrets": False,
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
            print("\nEtapa 1/5 completada: origen seleccionado")
            print(f"- Origen: {source_label}")
            print(f"- Mnemotecnica: {mnemonic}")

            if entropy is not None:
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
                if no_pause:
                    return 0
            else:
                _print_manual_mnemonic_limit_note()
                b39_action = _prompt_continue_with_options()
                if b39_action == "cancel":
                    print("Flujo cancelado por usuario. Salida limpia.")
                    return 0
                if b39_action == "retry":
                    continue

            stage_index += 1
            continue

        elif stage_index == 1:
            passphrase = _prompt_passphrase()
            state["passphrase"] = passphrase
            seed_artifacts = _print_phase_seed_bip39(
                mnemonic=str(state["mnemonic"]),
                passphrase=passphrase,
                show_secrets=True,
                interactive_micro_steps=True,
            )
            state.update(seed_artifacts)
            print("\nEtapa 2/5 completada: seed BIP39 derivada")

        elif stage_index == 2:
            master_artifacts = _print_phase_master_bip32(
                state["seed_bytes"], show_secrets=True, interactive_micro_steps=True
            )
            state.update(master_artifacts)
            print("\nEtapa 3/5 completada: master BIP32 derivada")

        elif stage_index == 3:
            network = _prompt_network()
            state["network"] = network
            path = _prompt_hd_path(str(state["network"]))
            state["path"] = path
            path_artifacts = _print_phase_hd_path(
                state["master"],
                path,
                show_secrets=True,
                interactive_micro_steps=True,
            )
            state.update(path_artifacts)
            print("\nEtapa 4/5 completada: ruta HD derivada")

        else:
            address_artifacts = _print_phase_address(
                state["derived"],
                str(state["network"]),
                show_secrets=True,
                interactive_micro_steps=True,
            )
            state.update(address_artifacts)
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
            )
            print("\nEtapa 5/5 completada: direccion y resumen final")

        action = "continue" if no_pause else _prompt_continue_with_options()
        if action == "cancel":
            print("Flujo cancelado por usuario. Salida limpia.")
            return 0
        if action == "continue":
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

    if args.interactive:
        preset_entropy = None
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
