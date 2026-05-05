"""Reusable ANSI styling helpers for terminal output."""

from __future__ import annotations

_ENABLED = True


def set_enabled(enabled: bool) -> None:
    global _ENABLED
    _ENABLED = enabled


def is_enabled() -> bool:
    return _ENABLED


def _wrap(value: str, code: str) -> str:
    if not _ENABLED:
        return value
    return f"\033[{code}m{value}\033[0m"


def cyan(value: str) -> str:
    return _wrap(value, "96")


def pink(value: str) -> str:
    return _wrap(value, "95")


def orange(value: str) -> str:
    return _wrap(value, "38;5;208")


def yellow(value: str) -> str:
    return _wrap(value, "93")


def blue(value: str) -> str:
    return _wrap(value, "94")


def purple(value: str) -> str:
    return _wrap(value, "35")


def red(value: str) -> str:
    return _wrap(value, "91")


def turquoise(value: str) -> str:
    return _wrap(value, "96")


def green(value: str) -> str:
    return _wrap(value, "32")


def bright_green(value: str) -> str:
    return _wrap(value, "92")


def bright_white(value: str) -> str:
    return _wrap(value, "97")


def dim(value: str) -> str:
    return _wrap(value, "2")


def formula(value: str) -> str:
    return _wrap(value, "37")


def warning(value: str) -> str:
    return _wrap(value, "1;93")
