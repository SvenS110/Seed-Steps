"""Core BIP39 educational breakdown logic."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from seed_steps.format import bytes_to_binary, bytes_to_hex, split_every


@dataclass(frozen=True)
class Bip39WordStep:
    position: int
    bit_block: str
    index: int
    visual_position: int
    word: str


@dataclass(frozen=True)
class Bip39Breakdown:
    entropy_hex: str
    entropy_bits: str
    sha256_hex: str
    checksum_bits: str
    entropy_plus_checksum_bits: str
    bit_blocks: list[str]
    steps: list[Bip39WordStep]
    mnemonic: str


def load_wordlist(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"No se encontro el archivo de wordlist: {path}")

    words = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(words) != 2048:
        raise ValueError(
            f"La wordlist BIP39 debe contener 2048 palabras; se encontraron {len(words)}"
        )
    return words


def build_bip39_breakdown(entropy: bytes, wordlist: list[str]) -> Bip39Breakdown:
    if len(wordlist) != 2048:
        raise ValueError("La wordlist debe contener exactamente 2048 palabras")

    entropy_hex = bytes_to_hex(entropy)
    entropy_bits = bytes_to_binary(entropy)
    entropy_bit_length = len(entropy) * 8

    digest = sha256(entropy).digest()
    digest_bits = bytes_to_binary(digest)
    checksum_length = entropy_bit_length // 32
    checksum_bits = digest_bits[:checksum_length]

    entropy_plus_checksum_bits = entropy_bits + checksum_bits
    bit_blocks = split_every(entropy_plus_checksum_bits, 11)
    if any(len(block) != 11 for block in bit_blocks):
        raise ValueError("Todos los bloques mnemotecnicos deben tener 11 bits")

    steps: list[Bip39WordStep] = []
    for position, block in enumerate(bit_blocks, start=1):
        index = int(block, 2)
        steps.append(
            Bip39WordStep(
                position=position,
                bit_block=block,
                index=index,
                visual_position=index + 1,
                word=wordlist[index],
            )
        )

    mnemonic = " ".join(step.word for step in steps)
    return Bip39Breakdown(
        entropy_hex=entropy_hex,
        entropy_bits=entropy_bits,
        sha256_hex=bytes_to_hex(digest),
        checksum_bits=checksum_bits,
        entropy_plus_checksum_bits=entropy_plus_checksum_bits,
        bit_blocks=bit_blocks,
        steps=steps,
        mnemonic=mnemonic,
    )
