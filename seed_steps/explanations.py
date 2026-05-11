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
    "BIP39 convierte esa entropía en una frase humana siguiendo un proceso determinista:",
    "",
    "1. toma la entropía;",
    "2. calcula un pequeño checksum;",
    "3. añade ese checksum al final;",
    "4. divide el resultado en bloques de 11 bits;",
    "5. cada bloque apunta a una palabra de una lista de 2048.",
    "",
    "La frase resultante es más fácil de guardar, pero sigue representando datos binarios.",
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

PHASE_C_INTRO = [
    "Fase C — BIP32: de seed a nodo maestro",
    "",
    "BIP39 termina en la seed.",
    "BIP32 empieza aquí.",
    "",
    "BIP32 usa esa seed para crear la raíz de un árbol HD.",
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

PHASE_D_INTRO = [
    "Fase D — Ruta HD",
    "",
    "Una seed no genera una única dirección.",
    "Genera un árbol.",
    "",
    "La ruta HD indica qué rama del árbol queremos recorrer.",
    "",
    "Cada nivel cambia la clave derivada.",
    "Cambiar un número en la ruta produce otra dirección.",
]

PHASE_D_HARDENED = [
    "El apóstrofo indica derivación hardened.",
    "",
    "Una derivación hardened usa material privado del padre.",
    "Una derivación normal permite derivar claves públicas hijas desde una xpub.",
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
    "El camino será:",
    "",
    "pubkey comprimida -> HASH160 -> witness program -> Bech32 -> dirección",
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
    "Transformaciones:",
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
