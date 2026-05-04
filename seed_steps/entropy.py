"""Entropy generation and parsing for BIP39 flows."""

from __future__ import annotations

import secrets
import string

VALID_ENTROPY_BYTE_LENGTHS = {16, 20, 24, 28, 32}


def generate_entropy(byte_length: int = 16) -> bytes:
    if byte_length not in VALID_ENTROPY_BYTE_LENGTHS:
        raise ValueError(
            f"Invalid entropy length: {byte_length} bytes. "
            f"Valid lengths: {sorted(VALID_ENTROPY_BYTE_LENGTHS)}"
        )
    return secrets.token_bytes(byte_length)


def parse_entropy_hex(entropy_hex: str) -> bytes:
    normalized = entropy_hex.strip().lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]

    if not normalized:
        raise ValueError(
            "Entropy vacia: usa un valor hexadecimal de 32/40/48/56/64 caracteres "
            "(128/160/192/224/256 bits)"
        )

    if len(normalized) % 2 != 0:
        raise ValueError(
            "Entropy hexadecimal invalida: la longitud debe ser par. "
            "Ejemplo valido: 00000000000000000000000000000000"
        )

    if any(char not in string.hexdigits.lower() for char in normalized):
        raise ValueError(
            "Entropy hexadecimal invalida: solo se permiten caracteres [0-9a-fA-F]"
        )

    try:
        entropy = bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError("Entropy must be valid hexadecimal") from exc

    if len(entropy) not in VALID_ENTROPY_BYTE_LENGTHS:
        valid_bits = sorted(length * 8 for length in VALID_ENTROPY_BYTE_LENGTHS)
        raise ValueError(
            f"Longitud de entropy invalida: {len(entropy) * 8} bits. "
            f"Longitudes permitidas por BIP39: {valid_bits} bits"
        )
    return entropy
