"""CLI entrypoint for Seed Steps educational BIP39 walkthrough."""

from __future__ import annotations

import argparse
import sys
from importlib.resources import as_file, files
from pathlib import Path

from seed_steps.bip32 import (
    HARDENED_OFFSET,
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
    return parser


def _print_header() -> None:
    print("Seed Steps - BIP39 Educational Breakdown")
    print("=" * 44)


def _print_stage_entropy(breakdown) -> None:
    print("1. Entropia")
    print("   Por que: Es la fuente de aleatoriedad que determina toda la semilla.")
    print(f"   Entropia (hex):      {breakdown.entropy_hex}")
    print(f"   Entropia (bits):     {group_binary(breakdown.entropy_bits, 8)}")
    print(f"   Tamano de entropia:  {len(breakdown.entropy_bits)} bits")


def _print_stage_checksum(breakdown) -> None:
    print("2. Checksum")
    print("   Por que: Detecta errores al escribir o transcribir la mnemotecnica.")
    print(f"   SHA256(entropia):    {breakdown.sha256_hex}")
    print(f"   Bits de checksum:    {breakdown.checksum_bits}")
    print(f"   Tamano checksum:     {len(breakdown.checksum_bits)} bits")


def _print_stage_combined_bits(breakdown) -> None:
    print("3. Bits combinados")
    print("   Por que: BIP39 une entropia y checksum antes de partir en bloques de 11.")
    print(f"   Entropia+checksum:   {breakdown.entropy_plus_checksum_bits}")
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
            return generate_entropy(16)

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
    print("Bienvenido al modo wizard de Seed Steps.")
    print("Veras cada etapa de BIP39 y avanzaras cuando presiones Enter.")

    entropy = _prompt_entropy_choice()

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

    _prompt_continue()
    _print_stage_entropy(breakdown)
    _prompt_continue()
    _print_stage_checksum(breakdown)
    _prompt_continue()
    _print_stage_combined_bits(breakdown)
    _prompt_continue()
    _print_stage_indices(breakdown)
    _prompt_continue()
    _print_stage_mnemonic(breakdown)
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


def _print_seed_derivation(mnemonic: str, passphrase: str) -> None:
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
    print(f"   Seed (hex, 64 bytes): {seed_bytes.hex()}")


def _print_bip32_derivation(seed_bytes: bytes) -> None:
    master = derive_bip32_master_node(seed_bytes)
    print()
    print("7. Master node BIP32")
    print(
        "   Por que: BIP32 separa secreto (master key) y ruta de derivacion (chain code)."
    )
    print(f"   I = HMAC-SHA512:     {master.hmac_i.hex()}")
    print(f"   IL (master key):     {master.master_private_key.hex()}")
    print(f"   IR (chain code):     {master.chain_code.hex()}")
    print(f"   Master private key:  {master.master_private_key.hex()}")
    print(f"   Chain code:          {master.chain_code.hex()}")
    print(f"   xprv (mainnet):      {master.xprv}")
    print(f"   xpub (mainnet):      {master.xpub}")


def _print_bip32_path_derivation(
    seed_bytes: bytes, path: str, show_steps: bool, network: str
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
            print("   - m (sin derivacion, se mantiene nodo master)")
        for step in parsed:
            current = derive_bip32_path_from_node(current, f"m/{step.token}")
            index_label = (
                step.child_number - HARDENED_OFFSET
                if step.hardened
                else step.child_number
            )
            hardened_label = "hardened" if step.hardened else "normal"
            print(
                f"   - {step.token}: index={index_label}, tipo={hardened_label}, depth={current.depth}, fp_padre={current.parent_fingerprint.hex()}"
            )
    else:
        current = derive_bip32_path_from_node(current, path)

    print(f"   Depth final:         {current.depth}")
    print(f"   Child number final:  {current.child_number}")
    print(f"   Parent fingerprint:  {current.parent_fingerprint.hex()}")
    print(f"   xprv derivado:       {current.xprv}")
    print(f"   xpub derivado:       {current.xpub}")

    p2wpkh = derive_p2wpkh_address_from_node(current, network)
    print()
    print("9. Direccion Bitcoin P2WPKH (Bech32)")
    print("   Por que: Convierte la pubkey derivada en direccion SegWit v0 utilizable.")
    print(f"   Red:                 {network} ({p2wpkh.hrp})")
    print(f"   Pubkey comprimida:   {p2wpkh.compressed_pubkey.hex()}")
    print(f"   HASH160(pubkey):     {p2wpkh.hash160.hex()}")
    print(
        f"   Witness program:     OP_{p2wpkh.witness_version} {p2wpkh.witness_program.hex()}"
    )
    print(f"   Direccion final:     {p2wpkh.address}")


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

    if args.mnemonic:
        _print_header()
        seed_bytes = derive_bip39_seed(args.mnemonic, args.passphrase)
        _print_seed_derivation(args.mnemonic, args.passphrase)
        if args.derive_bip32 or args.path:
            try:
                _print_bip32_derivation(seed_bytes)
                if args.path:
                    _print_bip32_path_derivation(
                        seed_bytes, args.path, args.path_steps, args.network
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
        _print_seed_derivation(breakdown.mnemonic, args.passphrase)
    if args.derive_bip32 or args.path:
        try:
            _print_bip32_derivation(seed_bytes)
            if args.path:
                _print_bip32_path_derivation(
                    seed_bytes, args.path, args.path_steps, args.network
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
