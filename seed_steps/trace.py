"""Reusable educational trace model for wizard output."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MathTrace:
    titulo: str
    que_es: str
    por_que: str
    datos_entrada: list[str] = field(default_factory=list)
    formulas: list[str] = field(default_factory=list)
    sustituciones: list[str] = field(default_factory=list)
    desarrollo_intermedio: list[str] = field(default_factory=list)
    resultados: list[str] = field(default_factory=list)
    nota_tecnica: str | None = None
    sensitive: bool = False
