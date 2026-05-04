"""CLI entrypoint for Seed Steps educational BIP39 walkthrough."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from seed_steps.bip39 import build_bip39_breakdown, load_wordlist
from seed_steps.entropy import generate_entropy, parse_entropy_hex
from seed_steps.format import group_binary


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
    return parser


def _print_header() -> None:
    print("Seed Steps - BIP39 Educational Breakdown")
    print("=" * 44)


def _print_detailed_breakdown(breakdown) -> None:
    entropy_bit_count = len(breakdown.entropy_bits)
    checksum_bit_count = len(breakdown.checksum_bits)
    total_bit_count = len(breakdown.entropy_plus_checksum_bits)
    word_count = len(breakdown.steps)

    print("1. Entropia")
    print("   Por que: Es la fuente de aleatoriedad que determina toda la semilla.")
    print(f"   Entropia (hex):      {breakdown.entropy_hex}")
    print(f"   Entropia (bits):     {group_binary(breakdown.entropy_bits, 8)}")
    print(f"   Tamano de entropia:  {entropy_bit_count} bits")
    print()

    print("2. Checksum")
    print("   Por que: Detecta errores al escribir o transcribir la mnemotecnica.")
    print(f"   SHA256(entropia):    {breakdown.sha256_hex}")
    print(f"   Bits de checksum:    {breakdown.checksum_bits}")
    print(f"   Tamano checksum:     {checksum_bit_count} bits")
    print()

    print("3. Bits combinados")
    print("   Por que: BIP39 une entropia y checksum antes de partir en bloques de 11.")
    print(f"   Entropia+checksum:   {breakdown.entropy_plus_checksum_bits}")
    print(f"   Total de bits:       {total_bit_count} bits")
    print()

    print("4. Indices")
    print("   Por que: Cada bloque de 11 bits apunta a una palabra en la lista BIP39.")
    print(f"   Bloques de 11 bits:  {' | '.join(breakdown.bit_blocks)}")
    print(f"   Numero de palabras:  {word_count}")
    print()

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


def _print_compact_breakdown(breakdown) -> None:
    print("1. Resumen")
    print("   Por que: Vista rapida para validar valores clave de BIP39.")
    print(f"   Entropia (hex):      {breakdown.entropy_hex}")
    print(f"   Bits entropia:       {len(breakdown.entropy_bits)}")
    print(f"   Bits checksum:       {len(breakdown.checksum_bits)}")
    print(f"   Bits totales:        {len(breakdown.entropy_plus_checksum_bits)}")
    print(f"   Numero de palabras:  {len(breakdown.steps)}")
    print(f"   Mnemonic:            {breakdown.mnemonic}")


def run() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        entropy = (
            parse_entropy_hex(args.entropy) if args.entropy else generate_entropy(16)
        )
    except ValueError as exc:
        print(f"Error de entrada (--entropy): {exc}", file=sys.stderr)
        return 2

    try:
        wordlist = load_wordlist(Path("data/english.txt"))
    except FileNotFoundError as exc:
        print(f"Error operativo (wordlist): {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"Error de configuracion de wordlist: {exc}", file=sys.stderr)
        return 3

    try:
        breakdown = build_bip39_breakdown(entropy, wordlist)
    except ValueError as exc:
        print(f"Error de validacion BIP39: {exc}", file=sys.stderr)
        return 4

    _print_header()
    if args.compact:
        _print_compact_breakdown(breakdown)
    else:
        _print_detailed_breakdown(breakdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
