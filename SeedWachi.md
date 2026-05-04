Quiero crear una herramienta educativa Bitcoin llamada Seed Steps.

Objetivo inicial:
Construir un prototipo CLI en Python que explique paso a paso cómo se transforma entropía en una mnemonic BIP39 de 12 palabras.

Esta primera fase NO debe implementar todavía BIP32, BIP84, claves privadas hijas, xprv/xpub ni direcciones Bitcoin. Solo BIP39.

Requisitos técnicos:

- Python 3.11 o superior.
- Usar solo librería estándar para la lógica BIP39.
- Usar pytest solo para tests.
- Separar lógica de presentación.
- Usar type hints.
- Código claro, pequeño y verificable.
- No usar semillas reales.
- No persistir datos sensibles.
- No añadir base de datos, backend web ni framework.

Estructura esperada del proyecto:

seed-steps-python/
├── seed_steps/
│ ├── **init**.py
│ ├── bip39.py
│ ├── cli.py
│ ├── entropy.py
│ └── format.py
│
├── data/
│ └── english.txt
│
├── tests/
│ └── test_bip39.py
│
├── pyproject.toml
└── README.md

Funcionalidad Fase 1:

1. Permitir ejecutar:

   python -m seed_steps.cli

   En ese caso debe generar 16 bytes de entropía usando secrets.token_bytes(16).

2. Permitir ejecutar:

   python -m seed_steps.cli --entropy 00000000000000000000000000000000

   En ese caso debe usar la entropía hexadecimal indicada por el usuario.

3. Validar longitudes BIP39 válidas:
   - 128 bits / 16 bytes
   - 160 bits / 20 bytes
   - 192 bits / 24 bytes
   - 224 bits / 28 bytes
   - 256 bits / 32 bytes

4. Rechazar entropía hexadecimal inválida.

5. Cargar la wordlist BIP39 inglesa desde:

   data/english.txt

6. Verificar que la wordlist tenga exactamente 2048 palabras.

7. Calcular:

   SHA256(entropía)

8. Calcular checksum BIP39:

   checksum_length = ENT / 32

   Para 128 bits debe ser 4 bits.

9. Convertir la entropía a binario.

10. Concatenar:

    entropy_bits + checksum_bits

11. Dividir el resultado en bloques de 11 bits.

12. Convertir cada bloque de 11 bits en un índice decimal 0–2047.

13. Mapear cada índice a una palabra del wordlist BIP39.

14. Mostrar por terminal una salida educativa con:
    - entropía hexadecimal
    - entropía binaria agrupada en bytes
    - SHA256(entropía)
    - checksum
    - entropía + checksum
    - bloques de 11 bits
    - tabla con:
      - posición de palabra
      - bloque de 11 bits
      - índice real 0–2047
      - posición visual 1–2048
      - palabra BIP39
    - mnemonic final

Test obligatorio:

Usar esta entropía:

00000000000000000000000000000000

La mnemonic esperada debe ser:

abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

También comprobar:

- checksum_bits == "0011"
- len(wordlist) == 2048
- wordlist[0] == "abandon"
- wordlist[2047] == "zoo"
- todos los bloques tienen 11 bits
- todos los índices están entre 0 y 2047

Contenido mínimo esperado:

1. pyproject.toml
   - nombre del proyecto: seed-steps
   - requiere Python >=3.11
   - dependencia opcional dev con pytest
   - configuración pytest con testpaths = ["tests"] y pythonpath = ["."]

2. seed_steps/format.py
   - bytes_to_hex(data: bytes) -> str
   - bytes_to_binary(data: bytes) -> str
   - split_every(value: str, size: int) -> list[str]
   - group_binary(value: str, size: int = 8) -> str

3. seed_steps/entropy.py
   - VALID_ENTROPY_BYTE_LENGTHS = {16, 20, 24, 28, 32}
   - generate_entropy(byte_length: int = 16) -> bytes
   - parse_entropy_hex(entropy_hex: str) -> bytes

4. seed_steps/bip39.py
   - dataclass Bip39WordStep
   - dataclass Bip39Breakdown
   - load_wordlist(path: Path) -> list[str]
   - build_bip39_breakdown(entropy: bytes, wordlist: list[str]) -> Bip39Breakdown

5. seed_steps/cli.py
   - argparse
   - argumento --entropy
   - carga data/english.txt
   - llama a build_bip39_breakdown
   - imprime salida educativa clara

6. tests/test_bip39.py
   - test con entropía cero
   - test de wordlist
   - test de bloques de 11 bits e índices válidos

7. README.md
   - explicación breve del proyecto
   - instalación
   - ejecución
   - ejemplo con entropía fija
   - ejecución de tests
   - advertencia: herramienta educativa, no usar semillas reales

Importante:

- Si falta data/english.txt, crea el archivo vacío con una nota en README indicando que debe copiarse ahí la wordlist oficial BIP39 inglesa de 2048 palabras antes de ejecutar.
- No inventes una wordlist parcial.
- No implementes todavía seed BIP39 con PBKDF2.
- No implementes todavía BIP32.
- No implementes todavía direcciones Bitcoin.
- Ejecuta pytest y corrige hasta que todos los tests pasen, salvo que falte la wordlist. En ese caso deja el error claro y documentado.
