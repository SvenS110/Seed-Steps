"""Textos pedagógicos para modos de presentación.

Este módulo contiene únicamente contenido textual reutilizable para la UX del
wizard (sin lógica criptográfica).
"""

from __future__ import annotations


MEETUP_INTRO = [
    "Seed Steps — Modo meetup",
    "",
    "Vamos a recorrer el viaje completo desde entropía hasta dirección Bitcoin.",
    "",
    "La idea no es memorizar fórmulas.",
    "La idea es ver cómo cada dato se transforma en el siguiente:",
    "",
    "entropía -> palabras -> seed -> nodo maestro -> ruta HD -> clave pública -> dirección",
    "",
    "Usa solo datos de prueba.",
    "Nunca uses una mnemotécnica, passphrase, seed o clave privada real en una demo.",
]

PHASE_A_INTRO = [
    "Fase A — BIP39: de entropía a palabras",
    "",
    "Aquí empieza todo.",
    "",
    "Bitcoin no crea primero palabras.",
    "Crea entropía: bytes aleatorios.",
    "",
    "BIP39 convierte esa entropía en una frase humana siguiendo un proceso determinista en 5 pasos:",
    "",
    "1. toma la entropía;",
    "2. calcula un pequeño checksum;",
    "3. añade ese checksum al final;",
    "4. divide el resultado en bloques de 11 bits;",
    "5. cada bloque apunta a una palabra de una lista de 2048.",
    "",
    "La frase resultante es más fácil de guardar, pero sigue representando datos binarios.",
]

PHASE_A_NOTES = [
    "Nota clave: el checksum BIP39 DETECTA errores de transcripción; NO corrige palabras por ti.",
    "Relación clave: la wordlist tiene 2048 palabras y 2048 = 2^11, por eso cada bloque usa 11 bits.",
]

PHASE_A_ENDIAN_NOTES = [
    "Cada bloque de 11 bits se lee en big-endian",
    "El bit de la izquierda pesa más",
    "Por eso 00000000011 se interpreta como 3",
    "Ese número es el índice dentro de la wordlist BIP39",
]

PHASE_B_INTRO = [
    "Fase B — BIP39: de palabras a seed",
    "",
    "Las palabras no se usan directamente como clave.",
    "",
    "BIP39 aplica PBKDF2-HMAC-SHA512.",
    "",
    "Su trabajo es tomar:",
    "- la mnemotécnica;",
    "- la passphrase opcional;",
    "",
    "y producir una seed de 64 bytes.",
    "",
    "Esa seed será la entrada para BIP32.",
    "",
    "En meetup lo veremos como fase 5/6 de BIP39:",
    "BIP39 5/6 — PBKDF2-HMAC-SHA512.",
]

PHASE_B_PBKDF2 = [
    "BIP39 no hace un único hash rápido.",
    "Ejecuta PBKDF2 con HMAC-SHA512 durante 2048 iteraciones.",
    "",
    "La idea es aumentar el coste de probar muchas passphrases o muchas frases candidatas.",
    "",
    "La mecánica es:",
    "U_1 = PRF(password, salt || INT_32_BE(1))",
    "U_i = PRF(password, U_{i-1})",
    "T_1 = U_1 XOR U_2 XOR ... XOR U_2048",
]

PHASE_B_STEPS = {
    "1_6": "BIP39 1/6 — Mnemotécnica de entrada",
    "2_6": "BIP39 2/6 — Normalización NFKD",
    "3_6": "BIP39 3/6 — Passphrase",
    "4_6": "BIP39 4/6 — Salt BIP39",
    "5_6": "BIP39 5/6 — PBKDF2-HMAC-SHA512",
    "6_6": "BIP39 6/6 — Seed final",
}

PHASE_C_STEPS = {
    "1_4": "BIP32 1/4 — Seed de entrada",
    "2_4": "BIP32 2/4 — HMAC maestro e I",
    "3_4": "BIP32 3/4 — Separar IL/IR",
    "4_4": "BIP32 4/4 — xprv/xpub master",
}

PHASE_D_STEPS = {
    "1_3": "Ruta HD 1/3 — Ruta elegida",
    "2_3": "Ruta HD 2/3 — Niveles y significado",
    "3_3": "Ruta HD 3/3 — Derivación y nodo final",
}

PHASE_E_STEPS = {
    "1_4": "Dirección 1/4 — Pubkey comprimida",
    "2_4": "Dirección 2/4 — HASH160 (incluye SHA256)",
    "3_4": "Dirección 3/4 — Witness + Bech32",
    "4_4": "Dirección 4/4 — Dirección final",
}

PHASE_C_INTRO = [
    "Fase C — BIP32: de seed a nodo maestro",
    "",
    "BIP39 termina en la seed.",
    "BIP32 empieza aquí.",
    "",
    "BIP32 usa esa seed para crear la raíz de un árbol HD en 4 momentos:",
    "1/4 HMAC, 2/4 digest I, 3/4 separación IL/IR, 4/4 nodo maestro.",
    "",
    "HD significa Hierarchical Deterministic:",
    "una sola raíz permite derivar muchas claves y direcciones de forma determinista.",
]

PHASE_C_IL_IR = [
    "El resultado del HMAC tiene 64 bytes.",
    "",
    "BIP32 lo parte en dos mitades:",
    "",
    "I = IL || IR",
    "",
    "IL son los primeros 32 bytes y se interpretan como master private key.",
    "IR son los últimos 32 bytes y se usan como master chain code.",
    "",
    "En BIP32 no basta con una clave.",
    "Cada nodo HD tiene:",
    "- una clave;",
    "- un chain code.",
]

PHASE_C_IL_IR_ENDIAN_NOTES = [
    "IL son 32 bytes",
    "Para convertir esos bytes en número privado usamos big-endian",
    "En criptografía de claves, normalmente escribimos el byte más significativo primero",
    "Así el hexadecimal visible coincide con la lectura humana habitual del número",
]

PHASE_C_SERIALIZATION_NOTES = [
    "xprv/xpub no son solo la clave codificada",
    "Incluyen versión, profundidad, fingerprint, índice, chain code y clave",
    "Esos campos se serializan en un orden exacto",
    "Si cambias el orden de bytes o el orden de campos, otra wallet no podrá interpretar el nodo",
]

PHASE_D_INTRO = [
    "Fase D — Ruta HD",
    "",
    "Una seed no genera una única dirección.",
    "Genera un árbol.",
    "",
    "La ruta HD indica qué rama del árbol queremos recorrer en 3 momentos:",
    "1/3 interpretar niveles, 2/3 hardened/normal, 3/3 derivar nodo objetivo.",
    "",
    "Cada nivel cambia la clave derivada.",
    "Cambiar un número en la ruta produce otra dirección.",
]

PHASE_D_HARDENED = [
    "El apóstrofo indica derivación hardened.",
    "",
    "Una derivación hardened usa material privado del padre.",
    "Una derivación normal permite derivar claves públicas hijas desde una xpub.",
    "",
    "En notación BIP32:",
    "- hardened: índice + 2^31",
    "- normal: índice directo",
]

PHASE_D_CKDPRIV_ENDIAN_NOTES = [
    "El índice del hijo se serializa como 4 bytes",
    "En BIP32 esos 4 bytes van en big-endian",
    "Ejemplo: index=1 se escribe como 00 00 00 01",
    "Si es hardened, antes se suma 2^31",
]

PHASE_BIG_LITTLE_ENDIAN_NOTE = [
    "En este recorrido BIP39/BIP32 casi todo lo visible se lee como big-endian o como bytes en orden natural",
    "En transacciones Bitcoin aparece mucho little-endian por serialización histórica",
    "Por eso a veces un mismo hash se ve “al revés” entre bytes internos y representación humana",
    "Lo veremos mejor cuando entremos en transacciones",
]

PHASE_E_INTRO = [
    "Fase E — De clave pública a dirección",
    "",
    "Una dirección no es una clave privada.",
    "",
    "Y normalmente tampoco es la clave pública escrita tal cual.",
    "",
    "En este caso usamos una dirección native SegWit P2WPKH.",
    "",
    "El camino será en 4 momentos:",
    "",
    "1/4 pubkey comprimida -> 2/4 HASH160 -> 3/4 witness/HRP -> 4/4 Bech32",
]

PHASE_E_HASH160 = [
    "HASH160 = RIPEMD160(SHA256(pubkey))",
    "",
    "SHA-256 no cifra.",
    "Resume datos de forma determinista.",
    "",
    "RIPEMD-160 reduce el resultado a 20 bytes.",
    "",
    "Este valor será el witness program de una dirección P2WPKH.",
]

PHASE_F_SUMMARY = [
    "Hemos recorrido todo el pipeline.",
    "",
    "Transformaciones (sin repetir detalle técnico):",
    "- BIP39 convirtió entropía en palabras.",
    "- PBKDF2 convirtió palabras + passphrase en seed.",
    "- BIP32 convirtió seed en nodo maestro.",
    "- La ruta HD derivó un nodo concreto.",
    "- La clave pública de ese nodo produjo una dirección.",
    "",
    "Advertencia:",
    "Esto es educativo.",
    "No uses datos reales en una demo.",
    "No compartas seeds, mnemotécnicas, passphrases, xprv ni claves privadas reales.",
]
