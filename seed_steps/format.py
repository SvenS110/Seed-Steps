"""Formatting helpers for educational CLI output."""

from __future__ import annotations


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def bytes_to_binary(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def split_every(value: str, size: int) -> list[str]:
    if size <= 0:
        raise ValueError("size must be greater than zero")
    return [value[index : index + size] for index in range(0, len(value), size)]


def group_binary(value: str, size: int = 8) -> str:
    return " ".join(split_every(value, size))
