"""Minimal BIP32 master node derivation and serialization (educational)."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

MAINNET_XPRV_VERSION = bytes.fromhex("0488ade4")
MAINNET_XPUB_VERSION = bytes.fromhex("0488b21e")
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass(frozen=True)
class BIP32MasterNode:
    hmac_i: bytes
    master_private_key: bytes
    chain_code: bytes
    xprv: str
    xpub: str


def derive_bip32_master_node(seed: bytes) -> BIP32MasterNode:
    """Derive BIP32 master node from BIP39 seed bytes."""
    i_value = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    il = i_value[:32]
    ir = i_value[32:]

    private_key_int = int.from_bytes(il, "big")
    if private_key_int == 0 or private_key_int >= SECP256K1_N:
        raise ValueError(
            "Master private key invalida: IL fuera de rango secp256k1 (1 <= k < n)"
        )

    xprv = serialize_extended_private_key(il, ir)
    xpub = serialize_extended_public_key(il, ir)
    return BIP32MasterNode(
        hmac_i=i_value,
        master_private_key=il,
        chain_code=ir,
        xprv=xprv,
        xpub=xpub,
    )


def serialize_extended_private_key(
    private_key: bytes,
    chain_code: bytes,
    depth: int = 0,
    parent_fingerprint: bytes = b"\x00\x00\x00\x00",
    child_number: int = 0,
) -> str:
    payload = (
        MAINNET_XPRV_VERSION
        + bytes([depth])
        + parent_fingerprint
        + child_number.to_bytes(4, "big")
        + chain_code
        + b"\x00"
        + private_key
    )
    return base58check_encode(payload)


def serialize_extended_public_key(
    private_key: bytes,
    chain_code: bytes,
    depth: int = 0,
    parent_fingerprint: bytes = b"\x00\x00\x00\x00",
    child_number: int = 0,
) -> str:
    public_key = _compressed_pubkey_from_private_key(private_key)
    payload = (
        MAINNET_XPUB_VERSION
        + bytes([depth])
        + parent_fingerprint
        + child_number.to_bytes(4, "big")
        + chain_code
        + public_key
    )
    return base58check_encode(payload)


def base58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum

    value = int.from_bytes(data, "big")
    encoded = ""
    while value > 0:
        value, remainder = divmod(value, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded

    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    if encoded:
        return ("1" * leading_zeros) + encoded
    return "1" * max(1, leading_zeros)


def _compressed_pubkey_from_private_key(private_key: bytes) -> bytes:
    scalar = int.from_bytes(private_key, "big")
    point = _scalar_multiply(scalar, (SECP256K1_GX, SECP256K1_GY))
    if point is None:
        raise ValueError("No se pudo derivar pubkey desde la clave privada")
    x_coord, y_coord = point
    prefix = b"\x02" if y_coord % 2 == 0 else b"\x03"
    return prefix + x_coord.to_bytes(32, "big")


def _scalar_multiply(k: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    result: tuple[int, int] | None = None
    addend = point

    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _point_add(
    p1: tuple[int, int] | None, p2: tuple[int, int] | None
) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None

    if p1 == p2:
        slope = ((3 * x1 * x1) * pow(2 * y1, -1, SECP256K1_P)) % SECP256K1_P
    else:
        slope = (
            (y2 - y1) * pow((x2 - x1) % SECP256K1_P, -1, SECP256K1_P)
        ) % SECP256K1_P

    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3
