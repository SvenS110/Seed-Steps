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
COLOR_SEED = "\033[32m"
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


def _prompt_micro_step(label: str, *, enable: bool) -> None:
    if not enable:
        return
    input(f"\nENTER -> {label}")


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
    print(f"   Entropia (bits):     {group_binary(breakdown.entropy_bits, 8)}")
    print(f"   Tamano de entropia:  {len(breakdown.entropy_bits)} bits")


def _print_stage_checksum(breakdown) -> None:
    print("2. Checksum")
    print("   Por que: Detecta errores al escribir o transcribir la mnemotecnica.")
    print("   Regla BIP39: checksum = primeros ENT/32 bits de SHA-256(entropia).")
    print(f"   SHA256(entropia):    {breakdown.sha256_hex}")
    print(f"   Bits de checksum:    {breakdown.checksum_bits}")
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
        if _prompt_yes_no("\nContinuar al siguiente paso? (S/N): "):
            return "continue"

        decision = (
            input("Elige: [C]ancelar flujo / [E]ditar esta etapa: ").strip().lower()
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
                "\nOrigen de mnemotecnica: [A] Entropia automatica / [E] Entropia manual / [M] Mnemotecnica manual: "
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
                    "Ingresa entropy hex (128/160/192/224/256 bits): "
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
    return input("\nPassphrase BIP39 (Enter para vacia): ")


def _prompt_network() -> str:
    while True:
        network = input("\nRed objetivo [M] mainnet / [T] testnet: ").strip().lower()
        if network in {"mainnet", "m"}:
            return "mainnet"
        if network in {"testnet", "t"}:
            return "testnet"
        print("Entrada invalida. Escribe M/T o mainnet/testnet.")


def _prompt_hd_path(network: str) -> str:
    default_path = _default_path_for_network(network)
    while True:
        mode = (
            input(f"\nRuta HD: [D]efault sugerida ({default_path}) / [M]anual: ")
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
                print(f"Entrada invalida: {exc}. Intenta nuevamente.")
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
    breakdown, *, source_label: str, selected_entropy_bits: int | None
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

    index = 0
    while index < len(substeps):
        title = substeps[index]
        print(f"\n{title}")
        if index == 0:
            _print_stage_entropy(breakdown)
            entropy_bits = selected_entropy_bits or len(breakdown.entropy_bits)
            print(
                f"   Fuente usada:        {source_label} (wizard) | tamano elegido: {entropy_bits} bits"
            )
        elif index == 1:
            _print_stage_checksum(breakdown)
            ent_bits = len(breakdown.entropy_bits)
            checksum_bits = ent_bits // 32
            print(
                f"   Calculo docente:     ENT={ent_bits} => ENT/32={checksum_bits} bits desde SHA-256(entropia)"
            )
        elif index == 2:
            _print_stage_combined_bits(breakdown, use_color=True)
        elif index == 3:
            _print_stage_indices_colored(breakdown)
        else:
            _print_stage_mnemonic_colored(breakdown)

        action = _prompt_continue_with_options()
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
    _prompt_micro_step("normalizar y fijar Mnemonic", enable=interactive_micro_steps)
    mnemonic_value = _colorize(mnemonic, COLOR_WORD)
    print(f"\n   [micro] Mnemonic normalizada: {mnemonic_value}")

    passphrase_display = _display_sensitive(
        passphrase or "(vacia)", show_secrets=show_secrets
    )
    _prompt_micro_step(
        "normalizar passphrase y construir salt", enable=interactive_micro_steps
    )
    salt = build_bip39_seed_salt(passphrase)
    print(
        "   [micro] Salt = "
        f"'mnemonic' + {_colorize(passphrase_display, COLOR_PASSPHRASE)} => {_colorize(salt, COLOR_PASSPHRASE)}"
    )

    _prompt_micro_step(
        "ejecutar PBKDF2-HMAC-SHA512 (2048)", enable=interactive_micro_steps
    )
    seed_bytes = derive_bip39_seed(mnemonic, passphrase)
    print("\nFase B) Seed BIP39")
    print(
        "   Lectura docente: tomamos tu frase y la pasamos por una maquina de estiramiento criptografico."
    )
    print("   Que entra:")
    print(f"   - Mnemonic:           {mnemonic_value}")
    print(f"   - Passphrase:         {_colorize(passphrase_display, COLOR_PASSPHRASE)}")
    print("   Que operacion se hace:")
    print(
        "   - Formula mental: "
        f"{_colorize('seed', COLOR_SEED)} = PBKDF2("
        f"{_colorize('mnemonic', COLOR_WORD)}, salt='mnemonic'+{_colorize('passphrase', COLOR_PASSPHRASE)}, 2048)"
    )
    print("   - Motor real: PBKDF2-HMAC-SHA512, iteraciones=2048")
    print(f"   - Salt:               {_colorize(salt, COLOR_PASSPHRASE)}")
    print("   Que sale:")
    print(
        f"   - Seed (hex, 64 bytes): {_colorize(_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets), COLOR_SEED)}"
    )
    return {"seed_bytes": seed_bytes, "salt": salt}


def _print_phase_master_bip32(
    seed_bytes: bytes, *, show_secrets: bool, interactive_micro_steps: bool = False
) -> dict[str, object]:
    _prompt_micro_step(
        "preparar entrada seed para HMAC", enable=interactive_micro_steps
    )
    seed_hex = _display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)
    print(f"\n   [micro] Seed entrada: {_colorize(seed_hex, COLOR_SEED)}")
    _prompt_micro_step(
        "ejecutar HMAC-SHA512 con clave 'Bitcoin seed'", enable=interactive_micro_steps
    )
    master = derive_bip32_master_node(seed_bytes)
    hmac_hex = _display_sensitive(master.hmac_i.hex(), show_secrets=show_secrets)
    il_hex = _display_sensitive(
        master.master_private_key.hex(), show_secrets=show_secrets
    )
    ir_hex = _display_sensitive(master.chain_code.hex(), show_secrets=show_secrets)
    i_colored = _colorize(il_hex, COLOR_IL) + _colorize(ir_hex, COLOR_IR)

    _prompt_micro_step(
        "serializar xprv (version+depth+fp+child+cc+key)",
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
    _prompt_micro_step(
        "serializar xpub (version+depth+fp+child+cc+pubkey)",
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
        "   Lectura docente: desde la seed nacen dos piezas: secreto maestro y cadena de derivacion."
    )
    print("   Que entra:")
    print(f"   - Seed:               {_colorize(seed_hex, COLOR_SEED)}")
    print("   Que operacion se hace:")
    print(f"   - Clave HMAC:         {_colorize('Bitcoin seed', COLOR_IR)}")
    print(f"   - Entrada HMAC:       {_colorize(seed_hex, COLOR_SEED)}")
    print("   - Operacion:          HMAC-SHA512(clave, entrada)")
    print("   Que sale:")
    print(f"   - I:                  {i_colored}  | IL(izq, azul) + IR(der, morado)")
    print(
        f"   - IL (master key):    {_colorize(il_hex, COLOR_IL)}  | Mitad izquierda: clave privada raiz"
    )
    print(
        f"   - IR (chain code):    {_colorize(ir_hex, COLOR_IR)}  | Mitad derecha: cadena que guia derivaciones"
    )
    print(f"   - Payload xprv:       {_colorize(xprv_payload, COLOR_XPRV)}")
    print(f"   - Payload xpub:       {_colorize(xpub_payload, COLOR_XPUB)}")
    print(
        f"   - xprv:               {_colorize(_display_sensitive(master.xprv, show_secrets=show_secrets), COLOR_XPRV)}  | Empaquetado del nodo privado maestro"
    )
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
    print(
        "   Mapa mental BIP44/BIP84: m / purpose' / coin_type' / account' / change / index"
    )
    print("   Que entra:")
    print(f"   - Ruta:               {path}")
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
    if not parsed:
        print("   - m (sin derivacion) | Se mantiene el nodo maestro en depth=0")
    for step in parsed:
        _prompt_micro_step(
            f"derivar nivel {step.token}", enable=interactive_micro_steps
        )
        current = derive_bip32_path_from_node(current, f"m/{step.token}")
        index_label = (
            step.child_number - HARDENED_OFFSET if step.hardened else step.child_number
        )
        hardened_label = "hardened" if step.hardened else "normal"
        print(
            f"   - {step.token}: index={index_label}, tipo={hardened_label}, depth={current.depth}, fp_padre={current.parent_fingerprint.hex()}  | avanzamos un nivel del mapa HD"
        )
    print("   Que sale:")
    print(f"   - Nodo depth final:   {current.depth}")
    print(
        f"   - xprv derivado:      {_colorize(_display_sensitive(current.xprv, show_secrets=show_secrets), COLOR_XPRV)}"
    )
    print(f"   - xpub derivado:      {_colorize(current.xpub, COLOR_XPUB)}")
    return {"derived": current}


def _print_phase_address(
    derived, network: str, *, show_secrets: bool, interactive_micro_steps: bool = False
) -> dict[str, object]:
    _prompt_micro_step(
        "obtener pubkey comprimida desde nodo derivado", enable=interactive_micro_steps
    )
    p2wpkh = derive_p2wpkh_address_from_node(derived, network)
    print("\nFase E) Direccion")
    print(
        "   Contexto: la pubkey comprimida sale del nodo derivado (clave privada hija)."
    )
    print("   Que entra:")
    print(
        f"   - Pubkey comprimida:  {_colorize(_display_sensitive(p2wpkh.compressed_pubkey.hex(), show_secrets=show_secrets), COLOR_XPUB)}"
    )
    print(f"   - Red:                {network}")
    _prompt_micro_step("aplicar HASH160(pubkey)", enable=interactive_micro_steps)
    hash160_hex = _display_sensitive(p2wpkh.hash160.hex(), show_secrets=show_secrets)
    _prompt_micro_step(
        "formar witness program SegWit v0", enable=interactive_micro_steps
    )
    witness_line = f"OP_{p2wpkh.witness_version} {p2wpkh.witness_program.hex()}"
    _prompt_micro_step("codificar Bech32(hrp, witness)", enable=interactive_micro_steps)
    print("   Que operacion se hace:")
    print(
        "   - Flujo completo: "
        f"contexto priv/pub -> {_colorize('pubkey comprimida', COLOR_XPUB)}"
        f" -> {_colorize('HASH160', COLOR_IR)} -> witness program -> Bech32"
    )
    print("   Que sale:")
    print(f"   - HASH160:            {_colorize(hash160_hex, COLOR_IR)}")
    print(f"   - Witness:            {_colorize(witness_line, COLOR_CHECKSUM)}")
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
    print("   Inputs usados:")
    colored_mnemonic = " ".join(
        _colorize(word, COLOR_WORD) for word in mnemonic.split()
    )
    print(f"   - Mnemonic:           {colored_mnemonic}")
    print(
        f"   - Passphrase:         {_colorize(_display_sensitive(passphrase or '(vacia)', show_secrets=show_secrets), COLOR_PASSPHRASE)}"
    )
    print(f"   - Ruta:               {path}")
    print(f"   - Red:                {network}")
    print("   Outputs clave:")
    print(
        f"   - Seed:               {_colorize(_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets), COLOR_SEED)}"
    )
    print(
        f"   - IL master:          {_colorize(_display_sensitive(master.master_private_key.hex(), show_secrets=show_secrets), COLOR_IL)}"
    )
    print(
        f"   - IR master:          {_colorize(_display_sensitive(master.chain_code.hex(), show_secrets=show_secrets), COLOR_IR)}"
    )
    print(
        f"   - xprv master:        {_colorize(_display_sensitive(master.xprv, show_secrets=show_secrets), COLOR_XPRV)}"
    )
    print(f"   - xpub master:        {_colorize(master.xpub, COLOR_XPUB)}")
    print(
        f"   - xprv derivado:      {_colorize(_display_sensitive(derived.xprv, show_secrets=show_secrets), COLOR_XPRV)}"
    )
    print(f"   - xpub derivado:      {_colorize(derived.xpub, COLOR_XPUB)}")
    print(
        f"   - Direccion final:    {_colorize(final_addr.address, COLOR_FINAL_ADDRESS)}"
    )
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


def _run_interactive(wordlist: list[str]) -> int:
    _print_header()
    print("Bienvenido al wizard guiado 11.3 de Seed Steps.")
    print("Cada fase pide datos, valida entrada y muestra resultado antes de avanzar.")
    print(
        "Nota: en wizard se muestran valores COMPLETOS por preferencia didactica del usuario."
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
                )
                if b39_action == "cancel":
                    print("Flujo cancelado por usuario. Salida limpia.")
                    return 0
                if b39_action == "retry":
                    continue
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

        action = _prompt_continue_with_options()
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
        return _run_interactive(wordlist)

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
