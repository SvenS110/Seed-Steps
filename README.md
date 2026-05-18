# Seed Steps

De la entropia a una direccion Bitcoin, paso a paso.

> Seed Steps no intenta ocultar la magia: la abre, la separa en pasos y la muestra en la terminal.

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![pytest](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white)
![Bitcoin](https://img.shields.io/badge/Bitcoin-self--custody-F7931A?logo=bitcoin&logoColor=white)
![BIP39](https://img.shields.io/badge/BIP-39-111111)
![BIP32](https://img.shields.io/badge/BIP-32-111111)
![BIP84](https://img.shields.io/badge/BIP-84-111111)

## Demo rapida

```bash
seed-steps --entropy 00000000000000000000000000000000 --compact
```

Salida esperada (recortada):

```text
Seed Steps - De (BIP39) Entropia a la Direccion
==================================================
1. Resumen
   Entropia (hex):      00000000000000000000000000000000
   Bits entropia:       128
   Numero de palabras:  12
   Mnemonic:            abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

## Que es Seed Steps

Seed Steps es una CLI educativa para entender y auditar mentalmente el pipeline criptografico completo de una wallet HD moderna, desde la fuente de entropia hasta la direccion final de recepcion.

Incluye trazabilidad paso a paso de:

- BIP39: `entropia -> checksum -> bloques de 11 bits -> mnemotecnica`.
- Seed BIP39: `PBKDF2-HMAC-SHA512` con 2048 iteraciones.
- BIP32: nodo maestro (`xprv`/`xpub`) y derivacion por ruta.
- BIP84: flujo orientado a direcciones SegWit nativas.
- P2WPKH/Bech32: direccion final en `mainnet` o `testnet`.

## Que NO es

- NO es una wallet.
- NO firma transacciones.
- NO reemplaza hardware wallets ni software de custodia.
- NO debe usarse con semillas reales ni fondos reales.

## Mapa visual del flujo

```text
[A] ENTROPIA
    |
    v
[B] BIP39
    - checksum = SHA256(entropia)[0:ENT/32]
    - (ENT + CS) / 11 -> indices -> palabras
    |
    v
[C] SEED BIP39
    - seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048)
    |
    v
[D] BIP32/BIP84
    - I = HMAC-SHA512("Bitcoin seed", seed)
    - IL = master private key, IR = chain code
    - path (ej: m/84'/0'/0'/0/0)
    |
    v
[E] DIRECCION FINAL
    - P2WPKH/Bech32 (mainnet o testnet)
```

## Requisitos

- Python `3.11` o superior.
- Terminal con soporte UTF-8.
- `pip` disponible en el entorno.

## Instalacion

### 1) Clonar repositorio

```bash
git clone https://github.com/SvenS110/Seed-Steps.git
cd Seed-Steps
```

### 2) Crear entorno e instalar (por sistema)

#### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

seed-steps --wizard

```

#### macOS

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

seed-steps --wizard

```

#### WSL (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

seed-steps --wizard

```

> En Windows usamos `py -3.11` de forma explícita para evitar que el Python Launcher seleccione una versión antigua o el alias de Microsoft Store. Si `py -3.11 --version` falla, instala Python 3.11 o superior desde python.org y vuelve a ejecutar el comando.
>
> Diagnóstico opcional: `py -0p` lista las versiones detectadas por Python Launcher.

#### Windows PowerShell

```powershell
py -3.11 --version
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

seed-steps --wizard

```

Si PowerShell bloquea la activación del entorno virtual, ejecuta:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

```

Después repite:

```powershell
.\.venv\Scripts\Activate.ps1

```

#### Windows CMD

```bat
py -3.11 --version
py -3.11 -m venv .venv
.venv\Scripts\activate.bat
python --version

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

seed-steps --wizard

```

## Uso rapido con ejemplos reales

```bash
# 1) Flujo BIP39 detallado por defecto (entropia automatica de 128 bits)
seed-steps

# 2) Flujo BIP39 compacto
seed-steps --compact

# 3) Wizard interactivo
seed-steps --wizard

# 4) Modo meetup (condensado e interactivo)
seed-steps --tamariz

# 5) Pipeline completo: BIP39 -> seed -> BIP32 -> direccion
seed-steps --full-journey --path "m/84'/0'/0'/0/0" --network mainnet

# 6) Derivar seed y nodo maestro desde mnemotecnica explicita
seed-steps --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --derive-seed --derive-bip32
```

## Modo meetup

`--tamariz` activa una versión editorializada del wizard para demos en vivo: mantiene decisiones interactivas (origen, bits, passphrase, red y ruta), organiza la narrativa por fases A-F con contenido real por paso (Idea/Datos/Cálculo/Resultado) y reduce burocracia sin convertir todo en un resumen ultra-compacto.

```bash
seed-steps --tamariz
seed-steps --tamariz --no-color
seed-steps --tamariz --no-pause
```

## Ejemplo deterministico (entropia cero)

Comando:

```bash
seed-steps --entropy 00000000000000000000000000000000 --compact
```

Mnemonic esperada:

```text
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

## Opciones principales (flags reales)

| Flag                        | Tipo   | Descripcion                                          |
| --------------------------- | ------ | ---------------------------------------------------- |
| `--entropy`                 | `str`  | Entropia hex (`128/160/192/224/256` bits).           |
| `--compact`                 | switch | Salida compacta del flujo BIP39.                     |
| `--tui`                     | switch | Vista educativa por paneles (read-only).             |
| `--interactive`, `--wizard` | switch | Inicia asistente interactivo.                        |
| `--tamariz`                 | switch | Modo meetup: wizard condensado e interactivo.        |
| `--no-pause`                | switch | En wizard/tamariz, desactiva pausas entre fases.     |
| `--no-color`                | switch | Desactiva ANSI en toda la salida.                    |
| `--mnemonic`                | `str`  | Mnemotécnica explícita de entrada.                   |
| `--passphrase`              | `str`  | Passphrase BIP39 opcional.                           |
| `--derive-seed`             | switch | Deriva seed BIP39.                                   |
| `--derive-bip32`            | switch | Deriva master key BIP32.                             |
| `--path`                    | `str`  | Ruta HD (ej. `m/84'/0'/0'/0/0`).                     |
| `--path-steps`              | switch | Muestra derivacion por nivel para la ruta.           |
| `--network`                 | enum   | Red: `mainnet` o `testnet`.                          |
| `--full-journey`            | switch | Ejecuta flujo E2E completo.                          |
| `--compare-passphrase`      | `str`  | Compara passphrase vacia vs valor dado.              |
| `--compare-path`            | `str`  | Compara ruta principal vs alternativa.               |
| `--show-secrets`            | switch | Muestra secretos completos (RIESGO ALTO).            |
| `--no-secrets`              | switch | Fuerza redaccion de secretos.                        |
| `--summary-raw`             | switch | En wizard, agrega bloque final `key=value` sin ANSI. |

## Arquitectura interna

- `seed_steps/cli.py`:
  Orquesta CLI, prompts, flujo interactivo, cálculo del pipeline, masking con `show_secrets` y retornos de fases.
- `seed_steps/tamariz_renderer.py`:
  Renderiza únicamente la narrativa Tamariz por fases. No debe calcular cripto, no debe recibir objetos de dominio BIP32/P2WPKH y no debe decidir masking.
- `seed_steps/rendering.py`:
  Helpers compartidos de presentación: colores semánticos, formato de bits/hex, separadores y utilidades de render terminal.
- `seed_steps/explanations.py`:
  Textos pedagógicos estáticos usados por los renderers.
- `seed_steps/bip39.py`, `seed_steps/seed.py`, `seed_steps/bip32.py`, `seed_steps/bech32.py`:
  Núcleo de dominio/cripto. Deben mantenerse independientes del render terminal.

**Regla de mantenimiento:**

- `cli.py` prepara datos y aplica `_display_sensitive`.
- `tamariz_renderer.py` solo imprime datos ya preparados.
- `rendering.py` no debe importar `cli.py`.
- Los módulos cripto no deben depender de CLI ni render.

## Colores semanticos y `NO_COLOR`

- Entropía: cian.
- Checksum: rosa / magenta claro.
- Seed BIP39: amarillo brillante.
- Palabras de mnemonic: naranja.
- Passphrase: magenta.
- IL: azul.
- IR / chain code: morado.
- xprv: rojo.
- xpub: turquesa.
- Dirección final: blanco/brillante en el resumen, verde/brillante en vistas pedagógicas si aplica.

Desactivacion de color:

- Cross-platform: `--no-color`.
- Tambien soporta variable de entorno `NO_COLOR`.

Ejemplos por sistema:

```bash
# Linux/macOS/WSL
NO_COLOR=1 seed-steps --wizard
```

```powershell
# PowerShell
$env:NO_COLOR = "1"
seed-steps --wizard
```

```bat
:: CMD
set NO_COLOR=1
seed-steps --wizard
```

## Fases del wizard (A-F) con fórmulas

### A) Entropía

La entropía es la fuente inicial de aleatoriedad. BIP39 acepta longitudes concretas:

```text
ENT ∈ {128, 160, 192, 224, 256}
```

### B) BIP39: checksum, bloques e índices

BIP39 calcula un checksum desde `SHA256(entropía)` y lo añade al final de los bits de entropía.

```text
CS = ENT / 32
checksum = first_CS_bits(SHA256(entropy))
entropy_plus_checksum = entropy_bits + checksum_bits
word_count = (ENT + CS) / 11
index = int(block_11_bits, 2)
word = wordlist[index]
```

### C) Seed BIP39

La mnemonic no se usa directamente como seed. Primero se normaliza y después se introduce en PBKDF2-HMAC-SHA512.

```text
password = NFKD(mnemonic)
salt = "mnemonic" + NFKD(passphrase)
seed = PBKDF2-HMAC-SHA512(password, salt, iterations=2048, dklen=64)
```

### D) BIP32

La seed BIP39 alimenta el nodo maestro BIP32. La cadena `"Bitcoin seed"` es una constante ASCII definida por BIP32, no la seed del usuario.

```text
I = HMAC-SHA512(key="Bitcoin seed", data=seed)
IL = I[0:32]
IR = I[32:64]

master_private_key = parse256(IL)
master_chain_code = IR
```

### E) BIP84

En BIP84, la ruta típica para la primera dirección SegWit nativa de Bitcoin mainnet es:

```text
m/84'/0'/0'/0/0

84' = purpose BIP84
0'  = coin type Bitcoin mainnet
0'  = account 0
0   = external chain
0   = address index 0

hardened_index = index + 2^31
```

Nota: en rutas BIP84, el modo `--tamariz` muestra `zprv/zpub` en mainnet y `vprv/vpub` en testnet para wallets native SegWit; la clave y el chain code son los mismos, cambia la serializacion (version bytes).

### F) Dirección P2WPKH/Bech32

La clave pública comprimida del nodo derivado se transforma en una dirección SegWit nativa:

```text
hash160 = RIPEMD160(SHA256(pubkey_compressed))
witness_version = 0
witness_program = hash160
address = bech32_encode(hrp, witness_version, witness_program)

```

## Resumen plano con `--summary-raw`

Cuando usas wizard, puedes agregar al final un bloque plano sin ANSI para parsing o logging controlado:

```bash
seed-steps --wizard --summary-raw --no-color
```

## Ejecutar tests

```bash
pytest
```

## Ejecutar sin instalar comando

```bash
python -m seed_steps --wizard
```

## Desactivar venv

```bash
deactivate
```

## Solucion de problemas

### `seed-steps: command not found`

- Activa el entorno virtual.
- Reinstala en editable: `python -m pip install -e ".[dev]"`.

### `ERROR ENTRADA` con `--entropy`

- Debe ser hexadecimal valido.
- Longitudes permitidas: `32/40/48/56/64` caracteres hex.

### Error de wordlist BIP39

- Verifica `seed_steps/data/english.txt` en la instalacion.
- Debe tener exactamente `2048` palabras no vacias.

### Direccion final inesperada

- Verifica siempre: `mnemonic`, `passphrase`, `network`, `path`.
- Si cambia uno, cambia TODO el resultado.

### Colores ANSI ilegibles

- Usa `--no-color` o define `NO_COLOR`.

## Seguridad

ESTA HERRAMIENTA ES EDUCATIVA. NO ES PARA CUSTODIA REAL.

- Usa datos de laboratorio, nunca secretos reales.
- Una semilla que aparece en pantalla debe considerarse comprometida. Seed Steps enseña el proceso; no custodia valor.
- Evita terminales compartidas, sesiones grabadas e historiales persistentes.
- `--show-secrets` solo para analisis en entorno aislado y desechable.
- Si dudas, fuerza `--no-secrets`.

## Compatibilidad

| Plataforma         |         Estado | Notas                                  |
| ------------------ | -------------: | -------------------------------------- |
| Linux              |      Soportado | Recomendado                            |
| WSL                |      Soportado | Recomendado en Windows                 |
| macOS              |      Soportado | Python 3.11+                           |
| Windows PowerShell |      Soportado | Windows Terminal recomendado           |
| Windows CMD        |      Soportado | Usar `activate.bat`                    |
| Git Bash           | No prioritario | Puede funcionar, no objetivo principal |

## Estructura del proyecto

```text
seed-steps-python/
├── pyproject.toml
├── README.md
├── seed_steps/
│   ├── __main__.py
│   ├── cli.py
│   ├── bip39.py
│   ├── seed.py
│   ├── bip32.py
│   ├── bech32.py
│   ├── entropy.py
│   ├── terminal_style.py
│   └── data/
│       └── english.txt
└── tests/
    ├── test_cli.py
    ├── test_bip39.py
    ├── test_seed.py
    ├── test_bip32.py
    └── test_bech32.py
```

## Estado del proyecto

Proyecto funcional para aprendizaje guiado del flujo BIP39/BIP32/BIP84 en terminal, con cobertura de tests y foco en claridad pedagogica.

## Roadmap breve

- Mejorar exportes de resumen para integracion con herramientas externas.
- Agregar mas escenarios comparativos en modo `--full-journey`.
- Incrementar ejemplos documentados para rutas y redes.

## Contribuir

1. Crea una rama de trabajo.
2. Instala dependencias de desarrollo.
3. Ejecuta `pytest` antes de abrir PR.
4. Describe claramente el objetivo educativo del cambio.

## Licencia

Este proyecto se publica bajo licencia MIT. Consulta el archivo [LICENSE](LICENSE).

Seed Steps es una herramienta educativa. La licencia permite usar, estudiar,
modificar y redistribuir el código, pero el software se ofrece sin garantías.

## Desinstalación

La desinstalación depende de cómo instalaste la herramienta.

Antes de borrar carpetas, asegúrate de estar en la ruta correcta del proyecto.

### Si instalaste en modo editable desde el repo

```bash
python -m pip uninstall seed-steps
```

Opcionalmente, puedes borrar el entorno virtual local del proyecto:

```bash
rm -rf .venv
```

### Si instalaste con pip normal

```bash
python -m pip uninstall seed-steps
```

### Si solo clonaste el repositorio y creaste un entorno virtual

```bash
deactivate
rm -rf .venv
cd ..
rm -rf seed-steps-python
```

Notas:

- Eliminar `.venv` borra solo el entorno virtual local del proyecto.
- Borrar la carpeta del repositorio elimina tu copia local del código.
