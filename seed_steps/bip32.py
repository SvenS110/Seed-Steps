"""Minimal BIP32 derivation and serialization (educational)."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from seed_steps.bech32 import bech32_encode, convertbits


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

MAINNET_XPRV_VERSION = bytes.fromhex("0488ade4")
MAINNET_XPUB_VERSION = bytes.fromhex("0488b21e")
MAINNET_ZPRV_VERSION = bytes.fromhex("04b2430c")
MAINNET_ZPUB_VERSION = bytes.fromhex("04b24746")
TESTNET_VPRV_VERSION = bytes.fromhex("045f18bc")
TESTNET_VPUB_VERSION = bytes.fromhex("045f1cf6")
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HARDENED_OFFSET = 0x80000000


@dataclass(frozen=True)
class BIP32MasterNode:
    hmac_i: bytes
    master_private_key: bytes
    chain_code: bytes
    xprv: str
    xpub: str


@dataclass(frozen=True)
class BIP32PathStep:
    index: int
    hardened: bool
    child_number: int
    token: str


@dataclass(frozen=True)
class BIP32Node:
    private_key: bytes
    chain_code: bytes
    depth: int
    child_number: int
    parent_fingerprint: bytes
    xprv: str
    xpub: str


@dataclass(frozen=True)
class P2WPKHAddress:
    network: str
    hrp: str
    compressed_pubkey: bytes
    hash160: bytes
    witness_version: int
    witness_program: bytes
    address: str


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


def parse_bip32_path(path: str) -> list[BIP32PathStep]:
    raw_path = path.strip()
    if not raw_path:
        raise ValueError("Ruta BIP32 vacia")
    if raw_path == "m":
        return []
    if not raw_path.startswith("m/"):
        raise ValueError("Ruta BIP32 invalida: debe iniciar con 'm/'")

    tokens = raw_path[2:].split("/")
    if any(token == "" for token in tokens):
        raise ValueError("Ruta BIP32 invalida: contiene niveles vacios")

    steps: list[BIP32PathStep] = []
    for token in tokens:
        hardened = token.endswith("'")
        number_part = token[:-1] if hardened else token

        if not number_part.isdecimal():
            raise ValueError(f"Ruta BIP32 invalida en '{token}': indice no numerico")

        index = int(number_part)
        if index >= HARDENED_OFFSET:
            raise ValueError(
                f"Ruta BIP32 invalida en '{token}': indice fuera de rango (0..2147483647)"
            )

        child_number = index + HARDENED_OFFSET if hardened else index
        steps.append(
            BIP32PathStep(
                index=index,
                hardened=hardened,
                child_number=child_number,
                token=token,
            )
        )
    return steps


def derive_bip32_node_from_master(master: BIP32MasterNode) -> BIP32Node:
    return BIP32Node(
        private_key=master.master_private_key,
        chain_code=master.chain_code,
        depth=0,
        child_number=0,
        parent_fingerprint=b"\x00\x00\x00\x00",
        xprv=master.xprv,
        xpub=master.xpub,
    )


def derive_bip32_path(seed: bytes, path: str) -> BIP32Node:
    master = derive_bip32_master_node(seed)
    root = derive_bip32_node_from_master(master)
    return derive_bip32_path_from_node(root, path)


def derive_bip32_path_from_node(node: BIP32Node, path: str) -> BIP32Node:
    steps = parse_bip32_path(path)
    current = node
    for step in steps:
        current = ckd_priv(current, step.child_number)
    return current


def ckd_priv(parent: BIP32Node, child_number: int) -> BIP32Node:
    if child_number < 0 or child_number > 0xFFFFFFFF:
        raise ValueError("Child number invalido: fuera de rango uint32")

    parent_key_int = int.from_bytes(parent.private_key, "big")
    if parent_key_int == 0 or parent_key_int >= SECP256K1_N:
        raise ValueError("Clave privada padre invalida: fuera de rango secp256k1")

    is_hardened = child_number >= HARDENED_OFFSET
    if is_hardened:
        data = b"\x00" + parent.private_key + child_number.to_bytes(4, "big")
    else:
        parent_pub = _compressed_pubkey_from_private_key(parent.private_key)
        data = parent_pub + child_number.to_bytes(4, "big")

    i_value = hmac.new(parent.chain_code, data, hashlib.sha512).digest()
    il = i_value[:32]
    ir = i_value[32:]

    il_int = int.from_bytes(il, "big")
    if il_int >= SECP256K1_N:
        raise ValueError("Derivacion BIP32 invalida: IL fuera de rango secp256k1")

    child_key_int = (il_int + parent_key_int) % SECP256K1_N
    if child_key_int == 0:
        raise ValueError(
            "Derivacion BIP32 invalida: clave hija fuera de rango secp256k1"
        )

    child_private_key = child_key_int.to_bytes(32, "big")
    parent_fingerprint = _fingerprint_from_private_key(parent.private_key)
    depth = parent.depth + 1
    if depth > 255:
        raise ValueError("Derivacion BIP32 invalida: profundidad maxima excedida (255)")

    return BIP32Node(
        private_key=child_private_key,
        chain_code=ir,
        depth=depth,
        child_number=child_number,
        parent_fingerprint=parent_fingerprint,
        xprv=serialize_extended_private_key(
            child_private_key,
            ir,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
        ),
        xpub=serialize_extended_public_key(
            child_private_key,
            ir,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
        ),
    )


def serialize_extended_private_key(
    private_key: bytes,
    chain_code: bytes,
    depth: int = 0,
    parent_fingerprint: bytes = b"\x00\x00\x00\x00",
    child_number: int = 0,
    version: bytes = MAINNET_XPRV_VERSION,
) -> str:
    payload = (
        version
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
    version: bytes = MAINNET_XPUB_VERSION,
) -> str:
    public_key = _compressed_pubkey_from_private_key(private_key)
    payload = (
        version
        + bytes([depth])
        + parent_fingerprint
        + child_number.to_bytes(4, "big")
        + chain_code
        + public_key
    )
    return base58check_encode(payload)


def serialize_bip84_extended_keys(node: BIP32Node, network: str) -> tuple[str, str]:
    if network == "mainnet":
        prv_version = MAINNET_ZPRV_VERSION
        pub_version = MAINNET_ZPUB_VERSION
    elif network == "testnet":
        prv_version = TESTNET_VPRV_VERSION
        pub_version = TESTNET_VPUB_VERSION
    else:
        raise ValueError("Red invalida: usa mainnet o testnet")

    return (
        serialize_extended_private_key(
            node.private_key,
            node.chain_code,
            depth=node.depth,
            parent_fingerprint=node.parent_fingerprint,
            child_number=node.child_number,
            version=prv_version,
        ),
        serialize_extended_public_key(
            node.private_key,
            node.chain_code,
            depth=node.depth,
            parent_fingerprint=node.parent_fingerprint,
            child_number=node.child_number,
            version=pub_version,
        ),
    )


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


def compressed_pubkey_from_private_key(private_key: bytes) -> bytes:
    return _compressed_pubkey_from_private_key(private_key)


def derive_p2wpkh_address_from_node(node: BIP32Node, network: str) -> P2WPKHAddress:
    if network == "mainnet":
        hrp = "bc"
    elif network == "testnet":
        hrp = "tb"
    else:
        raise ValueError("Red invalida: usa mainnet o testnet")

    pubkey = _compressed_pubkey_from_private_key(node.private_key)
    hash160 = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
    witness_version = 0
    witness_program = hash160
    data = [witness_version] + convertbits(witness_program, 8, 5, pad=True)
    address = bech32_encode(hrp, data)

    return P2WPKHAddress(
        network=network,
        hrp=hrp,
        compressed_pubkey=pubkey,
        hash160=hash160,
        witness_version=witness_version,
        witness_program=witness_program,
        address=address,
    )


def _fingerprint_from_private_key(private_key: bytes) -> bytes:
    pubkey = _compressed_pubkey_from_private_key(private_key)
    hash160 = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
    return hash160[:4]


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
