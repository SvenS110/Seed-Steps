# Seed Steps (Python)

CLI educativa para entender BIP39 paso a paso: desde entropia hexadecimal hasta mnemotecnica de 12 palabras.

## Objetivo de esta fase

- Mostrar el proceso BIP39 de forma transparente y verificable.
- Mantener separacion entre logica (`seed_steps/*.py`) y presentacion CLI (`seed_steps/cli.py`).
- NO incluye aun BIP32, BIP84, xprv/xpub ni direcciones.

## Requisitos

- Python 3.11+

## Instalacion (entorno local)

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Uso

Generar entropia de 128 bits automaticamente:

```bash
python -m seed_steps.cli
```

Usar entropia fija:

```bash
python -m seed_steps.cli --entropy 00000000000000000000000000000000
```

Modo compacto (sin tabla detallada por palabra):

```bash
python -m seed_steps.cli --entropy 00000000000000000000000000000000 --compact
```

### Salida educativa (modo detallado por defecto)

La CLI organiza la explicacion en 5 secciones numeradas:

1. Entropia
2. Checksum
3. Bits combinados
4. Indices
5. Mnemotecnica

Cada seccion incluye una linea de "Por que" para contexto pedagogico, metricas clave de bits y una tabla por palabra con posicion, bloque de 11 bits, indice y palabra final.

## Tests

```bash
pytest
```

## Nota sobre wordlist

La wordlist BIP39 inglesa debe estar en `data/english.txt` y contener exactamente 2048 palabras.

## Advertencia de seguridad

ESTA HERRAMIENTA ES SOLO EDUCATIVA. NO USES SEMILLAS REALES NI FONDOS REALES.
