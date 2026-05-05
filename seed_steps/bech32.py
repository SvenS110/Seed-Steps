"""Minimal Bech32 encoder/decoder (BIP173 educational subset)."""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_MAP = {char: idx for idx, char in enumerate(CHARSET)}


def bech32_encode(hrp: str, data: list[int]) -> str:
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def bech32_decode(bech: str) -> tuple[str, list[int]]:
    if not bech:
        raise ValueError("Bech32 invalido: cadena vacia")
    if bech.lower() != bech and bech.upper() != bech:
        raise ValueError("Bech32 invalido: mezcla mayusculas y minusculas")

    normalized = bech.lower()
    separator = normalized.rfind("1")
    if separator < 1 or separator + 7 > len(normalized):
        raise ValueError("Bech32 invalido: separador o longitud incorrecta")

    hrp = normalized[:separator]
    payload_chars = normalized[separator + 1 :]
    try:
        data = [_CHARSET_MAP[ch] for ch in payload_chars]
    except KeyError as exc:
        raise ValueError("Bech32 invalido: caracter fuera de alfabeto") from exc

    if not _bech32_verify_checksum(hrp, data):
        raise ValueError("Bech32 invalido: checksum incorrecto")
    return hrp, data[:-6]


def convertbits(
    data: bytes | list[int], frombits: int, tobits: int, pad: bool
) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1

    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("convertbits invalido: valor fuera de rango")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("convertbits invalido: relleno no permitido")
    return ret


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for idx in range(5):
            if (top >> idx) & 1:
                chk ^= generator[idx]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - idx)) & 31 for idx in range(6)]


def _bech32_verify_checksum(hrp: str, data: list[int]) -> bool:
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == 1
