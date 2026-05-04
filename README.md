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
seed-steps
```

Usar entropia fija:

```bash
seed-steps --entropy 00000000000000000000000000000000
```

Modo compacto (sin tabla detallada por palabra):

```bash
seed-steps --entropy 00000000000000000000000000000000 --compact
```

Ejecucion como modulo (equivalente):

```bash
python -m seed_steps --entropy 00000000000000000000000000000000
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

## Contrato de errores CLI

- Los errores se imprimen en `stderr` con plantilla uniforme:
  `ERROR <TIPO>: <causa>. Accion sugerida: <guia>.`
- Codigos de salida:
  - `0`: ejecucion exitosa
  - `2`: error de entrada (`--entropy`)
  - `3`: error operativo o de configuracion (wordlist)
  - `4`: error de dominio BIP39

## Nota sobre wordlist

La wordlist BIP39 inglesa se carga desde `seed_steps/data/english.txt` (empaquetada con el proyecto) y debe contener exactamente 2048 palabras.

## Advertencia de seguridad

ESTA HERRAMIENTA ES SOLO EDUCATIVA. NO USES SEMILLAS REALES NI FONDOS REALES.
