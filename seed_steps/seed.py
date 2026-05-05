"""BIP39 seed derivation utilities (educational)."""

from __future__ import annotations

import hashlib
import unicodedata


def normalize_bip39_text(value: str) -> str:
    """Normalize text with NFKD per BIP39."""
    return unicodedata.normalize("NFKD", value)


def derive_bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Derive 64-byte BIP39 seed from mnemonic and optional passphrase."""
    normalized_mnemonic = normalize_bip39_text(mnemonic)
    normalized_passphrase = normalize_bip39_text(passphrase)
    salt = "mnemonic" + normalized_passphrase
    return hashlib.pbkdf2_hmac(
        "sha512",
        normalized_mnemonic.encode("utf-8"),
        salt.encode("utf-8"),
        2048,
        dklen=64,
    )


def build_bip39_seed_salt(passphrase: str = "") -> str:
    """Build normalized BIP39 salt string: 'mnemonic' + passphrase."""
    return "mnemonic" + normalize_bip39_text(passphrase)
