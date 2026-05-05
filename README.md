# Seed Steps (Python)

CLI educativa para entender BIP39 paso a paso: desde entropia hexadecimal hasta mnemotecnica de 12 palabras.

## Objetivo de esta fase

- Mostrar el proceso BIP39 de forma transparente y verificable.
- Mantener separacion entre logica (`seed_steps/*.py`) y presentacion CLI (`seed_steps/cli.py`).
- Incluye derivacion de master node BIP32 (xprv/xpub mainnet) desde seed BIP39.
- Incluye derivacion de seed BIP39 (PBKDF2-HMAC-SHA512, 2048 iteraciones).

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

Modo wizard interactivo paso a paso:

```bash
seed-steps --interactive
```

Alias equivalente:

```bash
seed-steps --wizard
```

Ejecucion como modulo (equivalente):

```bash
python -m seed_steps --entropy 00000000000000000000000000000000
```

Derivar seed desde mnemotecnica explicita:

```bash
seed-steps --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR
```

Derivar seed usando la mnemotecnica generada en el flujo normal:

```bash
seed-steps --entropy 00000000000000000000000000000000 --derive-seed
```

Derivar master node BIP32 (xprv/xpub) desde seed disponible:

```bash
seed-steps --entropy 00000000000000000000000000000000 --derive-bip32
```

Derivar master node BIP32 desde mnemotecnica explicita:

```bash
seed-steps --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR --derive-bip32
```

### Salida educativa (modo detallado por defecto)

La CLI organiza la explicacion en 5 secciones numeradas (6 cuando se deriva seed):

1. Entropia
2. Checksum
3. Bits combinados
4. Indices
5. Mnemotecnica
6. Seed BIP39 (opcional)

Cada seccion incluye una linea de "Por que" para contexto pedagogico, metricas clave de bits y una tabla por palabra con posicion, bloque de 11 bits, indice y palabra final.

## Tests

```bash
pytest
```

Actualizar snapshots/golden de salida CLI (solo cuando el cambio de copy/estructura sea INTENCIONAL):

```bash
UPDATE_GOLDENS=1 pytest tests/test_cli.py
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
