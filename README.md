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

Desde HITO 11.4, este wizard es GUIADO por fases con validacion y confirmacion S/N entre pasos:

- Etapa 1: origen (`entropia automatica` / `entropia manual` / `mnemotecnica manual`).
- Etapa 2: passphrase (vacia permitida).
- Etapa 3: red (`mainnet`/`testnet`).
- Etapa 4: ruta HD (default sugerida por red o manual).
- Etapa 5: derivacion de direccion + resumen final.
- Al cerrar cada etapa: `Continuar al siguiente paso? (S/N)`.
- Si respondes `N`: puedes `[C]ancelar flujo` o `[E]ditar` esa etapa y reintentar.

Homogeneizacion HITO 11.4 (pipeline completo fase por fase):

- Se conserva intacta la fase BIP39 restaurada en 11.2.1 cuando el origen es entropia.
- Luego el wizard recorre TODO el pipeline con el mismo patron didactico (pedir input en la fase y mostrar resultado en la misma fase):
  - Fase B: Seed BIP39 (entrada: mnemonic+passphrase, operacion: PBKDF2, salida: seed completa en wizard).
  - Fase C: Master BIP32 (entrada: seed, operacion: HMAC-SHA512, salida: I/IL/IR + xprv/xpub completos y explicados).
  - Fase D: Ruta HD (entrada: ruta, operacion: derivacion nivel por nivel, salida: nodo derivado).
  - Fase E: Direccion (entrada: pubkey/red, operacion: HASH160+witness+bech32, salida: direccion final).
  - Fase F: Resumen final (inputs usados + outputs clave + advertencia).
- Entre cada fase se mantiene `Continuar al siguiente paso? (S/N)` con opcion de cancelar o editar/reintentar.

Nota UX del wizard: por solicitud del usuario, en modo interactivo se prioriza visibilidad completa de passphrase/seed/I/IL/IR/xprv/hash160 para aprendizaje. La politica segura por defecto permanece para `--full-journey`, `--tui` y modo no interactivo.

Correccion 11.2.1 (didactica BIP39 restaurada):

- Si eliges origen por entropia (auto/manual), el wizard vuelve a mostrar la fase BIP39 completa por subpasos:
  `Entropia -> Checksum -> Bits combinados -> Bloques de 11 bits/Indices -> Mnemotecnica`.
- Cada subpaso BIP39 tambien pide confirmacion S/N para continuar.
- Si eliges mnemotecnica manual, el wizard explica explicitamente que no puede reconstruir de forma fiable la entropia/checksum/bloques originales desde solo esa entrada.

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

Revelar secretos completos (SOLO laboratorio aislado):

```bash
seed-steps --entropy 00000000000000000000000000000000 --derive-bip32 --show-secrets
```

Forzar redaccion aunque alguien agregue `--show-secrets`:

```bash
seed-steps --entropy 00000000000000000000000000000000 --derive-bip32 --show-secrets --no-secrets
```

Derivar master node BIP32 desde mnemotecnica explicita:

```bash
seed-steps --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR --derive-bip32
```

Modo completo E2E (entropia -> direccion P2WPKH):

```bash
seed-steps --full-journey --entropy 00000000000000000000000000000000 --path "m/84'/0'/0'/0/0"
```

Modo completo con mnemotecnica explicita + passphrase:

```bash
seed-steps --full-journey --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR
```

Modo TUI educativa read-only (pipeline completo por paneles):

```bash
seed-steps --tui --entropy 00000000000000000000000000000000 --path "m/84'/0'/0'/0/0"
```

Modo TUI con secretos visibles (SOLO laboratorio aislado):

```bash
seed-steps --tui --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase TREZOR --show-secrets
```

Comparador pedagogico de passphrase (vacia vs valor):

```bash
seed-steps --full-journey --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --compare-passphrase TREZOR --path "m/84'/0'/0'/0/0"
```

Comparador pedagogico de ruta (ruta A vs ruta B):

```bash
seed-steps --full-journey --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --path "m/84'/0'/0'/0/0" --compare-path "m/84'/0'/0'/0/1"
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

En `--full-journey`, la narrativa incluye para cada etapa:

- Que es
- Por que importa
- Que se rompe si cambia

Y cierra con un resumen ejecutivo (red, ruta, mnemotecnica usada, resumen de seed, xpub derivada y direccion final) y advertencia visible:

`ADVERTENCIA: EDUCATIVO, NO CUSTODIA REAL`

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

Desde HITO 10, la salida CLI aplica POLITICA SEGURA POR DEFECTO:

- Seed BIP39 completa, `I` HMAC BIP32, private keys (master/derivadas), `xprv`, chain code y material derivable sensible se REDACTAN en stdout.
- Formato de redaccion: prefijo+suffix + huella `sha256` corta para comparacion pedagogica sin exponer el secreto completo.
- `--show-secrets` habilita exposicion completa y emite advertencia visible en pantalla.
- `--no-secrets` tiene prioridad sobre `--show-secrets` (fail-safe).

`xpub` y direccion final se muestran por defecto porque son artefactos de observacion/recepcion (NO de firma) y son necesarios para conservar el valor didactico del flujo.

RIESGO OPERATIVO: si usas `--show-secrets`, asume que terminal, capturas, logs del CI e historial del shell pueden persistir secretos. Trata esa salida como MATERIAL CUSTODIAL.
