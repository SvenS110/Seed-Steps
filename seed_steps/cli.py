"""CLI entrypoint for Seed Steps educational BIP39 walkthrough."""

from __future__ import annotations

import argparse
import hashlib
import sys
from importlib.resources import as_file, files
from pathlib import Path

from seed_steps.bip32 import (
    HARDENED_OFFSET,
    derive_p2wpkh_address_from_node,
    derive_bip32_master_node,
    derive_bip32_node_from_master,
    derive_bip32_path_from_node,
    parse_bip32_path,
)
from seed_steps.bip39 import build_bip39_breakdown, load_wordlist
from seed_steps.entropy import generate_entropy, parse_entropy_hex
from seed_steps.format import group_binary
from seed_steps.seed import build_bip39_seed_salt, derive_bip39_seed


def _error_message(error_type: str, cause: str, guide: str) -> str:
    return f"ERROR {error_type}: {cause}. Accion sugerida: {guide}."


def _mask_sensitive(value: str) -> str:
    if not value:
        return "(vacio)"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    if len(value) <= 16:
        return f"{value[:4]}...{value[-4:]} [sha256:{digest}]"
    return f"{value[:8]}...{value[-8:]} [sha256:{digest}]"


def _display_sensitive(value: str, *, show_secrets: bool) -> str:
    if show_secrets:
        return value
    return _mask_sensitive(value)


def _print_secrets_warning() -> None:
    print(
        "ADVERTENCIA DE SEGURIDAD: --show-secrets expone material sensible en terminal, logs e historial."
    )
    print("NO uses semillas o claves reales en este modo.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seed-steps",
        description="Educational BIP39 walkthrough from entropy to 12-word mnemonic.",
    )
    parser.add_argument(
        "--entropy",
        type=str,
        help="Hex entropy (128/160/192/224/256 bits). If omitted, generates 128-bit entropy.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Compact output with only key metrics and final mnemonic.",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Renderiza una vista educativa por paneles (read-only) del pipeline completo.",
    )
    parser.add_argument(
        "--interactive",
        "--wizard",
        dest="interactive",
        action="store_true",
        help="Inicia un asistente interactivo paso a paso.",
    )
    parser.add_argument(
        "--mnemonic",
        type=str,
        help="Mnemotecnica explicita para derivar seed BIP39.",
    )
    parser.add_argument(
        "--passphrase",
        type=str,
        default="",
        help="Passphrase opcional BIP39 (se normaliza NFKD).",
    )
    parser.add_argument(
        "--derive-seed",
        action="store_true",
        help="Deriva seed BIP39 desde mnemotecnica (explicativo).",
    )
    parser.add_argument(
        "--derive-bip32",
        action="store_true",
        help="Deriva master key BIP32 (xprv/xpub) desde seed disponible.",
    )
    parser.add_argument(
        "--path",
        type=str,
        help="Ruta HD BIP32 desde la master key (ej: m/84'/0'/0'/0/0).",
    )
    parser.add_argument(
        "--path-steps",
        action="store_true",
        help="Muestra derivacion por niveles para la ruta HD indicada.",
    )
    parser.add_argument(
        "--network",
        type=str,
        default="mainnet",
        choices=["mainnet", "testnet"],
        help="Red para direccion final (mainnet|testnet).",
    )
    parser.add_argument(
        "--full-journey",
        action="store_true",
        help="Ejecuta flujo E2E completo: entropia/mnemonic -> seed -> BIP32 -> ruta -> direccion.",
    )
    parser.add_argument(
        "--compare-passphrase",
        type=str,
        help="En modo completo, compara passphrase vacia vs este valor.",
    )
    parser.add_argument(
        "--compare-path",
        type=str,
        help="En modo completo, compara ruta principal (--path) contra esta ruta alternativa.",
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Muestra secretos completos (seed/xprv/private key/chain code). Riesgoso.",
    )
    parser.add_argument(
        "--no-secrets",
        action="store_true",
        help="Fuerza redaccion de secretos. Tiene prioridad sobre --show-secrets.",
    )
    return parser


def _print_header() -> None:
    print("Seed Steps - BIP39 Educational Breakdown")
    print("=" * 44)


def _print_stage_entropy(breakdown) -> None:
    print("1. Entropia")
    print("   Por que: Es la fuente de aleatoriedad que determina toda la semilla.")
    print(f"   Entropia (hex):      {breakdown.entropy_hex}")
    print(f"   Entropia (bits):     {group_binary(breakdown.entropy_bits, 8)}")
    print(f"   Tamano de entropia:  {len(breakdown.entropy_bits)} bits")


def _print_stage_checksum(breakdown) -> None:
    print("2. Checksum")
    print("   Por que: Detecta errores al escribir o transcribir la mnemotecnica.")
    print(f"   SHA256(entropia):    {breakdown.sha256_hex}")
    print(f"   Bits de checksum:    {breakdown.checksum_bits}")
    print(f"   Tamano checksum:     {len(breakdown.checksum_bits)} bits")


def _print_stage_combined_bits(breakdown) -> None:
    print("3. Bits combinados")
    print("   Por que: BIP39 une entropia y checksum antes de partir en bloques de 11.")
    print(f"   Entropia+checksum:   {breakdown.entropy_plus_checksum_bits}")
    print(f"   Total de bits:       {len(breakdown.entropy_plus_checksum_bits)} bits")


def _print_stage_indices(breakdown) -> None:
    print("4. Indices")
    print("   Por que: Cada bloque de 11 bits apunta a una palabra en la lista BIP39.")
    print(f"   Bloques de 11 bits:  {' | '.join(breakdown.bit_blocks)}")
    print(f"   Numero de palabras:  {len(breakdown.steps)}")


def _print_stage_mnemonic(breakdown) -> None:
    print("5. Mnemotecnica")
    print("   Por que: Es la representacion humana de la semilla binaria.")
    print("   Tabla por palabra:")
    print("   pos | bloque(11-bit) | indice | palabra")
    print("   ----+----------------+--------+----------")
    for step in breakdown.steps:
        print(
            f"   {step.position:>3} | {step.bit_block} | {step.index:>6} | {step.word}"
        )
    print(f"\nMnemonic: {breakdown.mnemonic}")


def _prompt_continue() -> None:
    input("\nPresiona Enter para continuar... ")


def _prompt_entropy_choice() -> bytes:
    while True:
        choice = (
            input("\nComo quieres la entropia? [A]utomatica / [M]anual: ")
            .strip()
            .lower()
        )

        if choice in {"a", "auto", "automatica", "automatic"}:
            return generate_entropy(16)

        if choice in {"m", "manual"}:
            while True:
                entropy_hex = input(
                    "Ingresa entropy hex (128/160/192/224/256 bits): "
                ).strip()
                try:
                    return parse_entropy_hex(entropy_hex)
                except ValueError as exc:
                    print(f"Entrada invalida: {exc}. Intenta nuevamente.")

        print("Opcion invalida. Escribe A para automatica o M para manual.")


def _prompt_yes_no(prompt: str) -> bool:
    while True:
        choice = input(prompt).strip().lower()
        if choice in {"s", "si", "y", "yes"}:
            return True
        if choice in {"n", "no"}:
            return False
        print("Entrada invalida. Responde S o N.")


def _prompt_continue_with_options() -> str:
    while True:
        if _prompt_yes_no("\nContinuar al siguiente paso? (S/N): "):
            return "continue"

        decision = (
            input("Elige: [C]ancelar flujo / [E]ditar esta etapa: ").strip().lower()
        )
        if decision in {"c", "cancelar"}:
            return "cancel"
        if decision in {"e", "editar", "r", "reintentar"}:
            return "retry"
        print("Opcion invalida. Escribe C para cancelar o E para editar.")


def _prompt_source_choice(wordlist: list[str]) -> tuple[bytes | None, str, str]:
    while True:
        choice = (
            input(
                "\nOrigen de mnemotecnica: [A] Entropia automatica / [E] Entropia manual / [M] Mnemotecnica manual: "
            )
            .strip()
            .lower()
        )

        if choice in {"a", "auto", "automatica", "automatic"}:
            entropy = generate_entropy(16)
            breakdown = build_bip39_breakdown(entropy, wordlist)
            return entropy, breakdown.mnemonic, "entropia automatica"

        if choice in {"e", "entropia", "entropia manual", "manual"}:
            while True:
                entropy_hex = input(
                    "Ingresa entropy hex (128/160/192/224/256 bits): "
                ).strip()
                try:
                    entropy = parse_entropy_hex(entropy_hex)
                    breakdown = build_bip39_breakdown(entropy, wordlist)
                    return entropy, breakdown.mnemonic, "entropia manual"
                except ValueError as exc:
                    print(f"Entrada invalida: {exc}. Intenta nuevamente.")

        if choice in {"m", "mnemonica", "mnemotecnica", "mnemonica manual"}:
            while True:
                mnemonic = input("Ingresa mnemotecnica BIP39 manual: ").strip()
                words = [word for word in mnemonic.split() if word]
                if len(words) not in {12, 15, 18, 21, 24}:
                    print(
                        "Entrada invalida: la mnemotecnica debe tener 12/15/18/21/24 palabras."
                    )
                    continue
                invalid_words = [word for word in words if word not in wordlist]
                if invalid_words:
                    print(
                        "Entrada invalida: hay palabras fuera de la wordlist BIP39 inglesa. "
                        f"Ejemplo invalido: {invalid_words[0]}."
                    )
                    continue
                return None, " ".join(words), "mnemotecnica manual"

        print("Opcion invalida. Escribe A, E o M.")


def _prompt_passphrase() -> str:
    return input("\nPassphrase BIP39 (Enter para vacia): ")


def _prompt_network() -> str:
    while True:
        network = input("\nRed objetivo [mainnet/testnet]: ").strip().lower()
        if network in {"mainnet", "m"}:
            return "mainnet"
        if network in {"testnet", "t"}:
            return "testnet"
        print("Entrada invalida. Escribe mainnet o testnet.")


def _prompt_hd_path(network: str) -> str:
    default_path = _default_path_for_network(network)
    while True:
        mode = (
            input(f"\nRuta HD: [D]efault sugerida ({default_path}) / [M]anual: ")
            .strip()
            .lower()
        )
        if mode in {"d", "default", ""}:
            return default_path
        if mode in {"m", "manual"}:
            path = input("Ingresa ruta HD (ej: m/84'/0'/0'/0/0): ").strip()
            try:
                parse_bip32_path(path)
                return path
            except ValueError as exc:
                print(f"Entrada invalida: {exc}. Intenta nuevamente.")
            continue
        print("Opcion invalida. Escribe D o M.")


def _prompt_show_secrets() -> bool:
    print("\nPolitica de seguridad: secretos REDACTADOS por defecto.")
    wants_reveal = _prompt_yes_no("Deseas revelar secretos en pantalla? (S/N): ")
    if not wants_reveal:
        return False

    print(
        "ADVERTENCIA CRITICA: revelar secretos puede exponer material custodial en logs e historial."
    )
    confirm = input("Escribe REVELAR para confirmar (o Enter para cancelar): ").strip()
    if confirm != "REVELAR":
        print("Revelacion cancelada. Se mantiene redaccion de secretos.")
        return False
    _print_secrets_warning()
    return True


def _run_bip39_guided_substeps(breakdown) -> str:
    """Render BIP39 didactic substeps with S/N confirmation.

    Returns: continue | retry | cancel
    """

    substeps = [
        ("Subpaso BIP39 1/5: Entropia", _print_stage_entropy),
        ("Subpaso BIP39 2/5: Checksum", _print_stage_checksum),
        ("Subpaso BIP39 3/5: Bits combinados", _print_stage_combined_bits),
        ("Subpaso BIP39 4/5: Indices (bloques de 11 bits)", _print_stage_indices),
        ("Subpaso BIP39 5/5: Mnemotecnica", _print_stage_mnemonic),
    ]

    index = 0
    while index < len(substeps):
        title, printer = substeps[index]
        print(f"\n{title}")
        printer(breakdown)

        action = _prompt_continue_with_options()
        if action == "cancel":
            return "cancel"
        if action == "retry":
            continue
        index += 1

    return "continue"


def _print_manual_mnemonic_limit_note() -> None:
    print("\nSubpaso BIP39 (entrada manual de mnemotecnica)")
    print(
        "No se puede reconstruir de forma fiable la entropia/checksum/bloques de 11 bits ORIGINALES "
        "a partir de solo la mnemotecnica ingresada."
    )
    print(
        "Alternativa educativa: continuar desde mnemotecnica -> seed -> BIP32 -> ruta -> direccion."
    )


def _print_detailed_breakdown(breakdown) -> None:
    _print_stage_entropy(breakdown)
    print()
    _print_stage_checksum(breakdown)
    print()
    _print_stage_combined_bits(breakdown)
    print()
    _print_stage_indices(breakdown)
    print()
    _print_stage_mnemonic(breakdown)


def _run_interactive(wordlist: list[str]) -> int:
    _print_header()
    print("Bienvenido al wizard guiado 11.2 de Seed Steps.")
    print("Cada etapa pide datos, valida entrada y confirma continuidad (S/N).")

    state: dict[str, object] = {
        "entropy": None,
        "mnemonic": "",
        "source_label": "",
        "passphrase": "",
        "network": "mainnet",
        "path": "",
        "show_secrets": False,
    }

    stage_index = 0
    while stage_index < 5:
        if stage_index == 0:
            entropy, mnemonic, source_label = _prompt_source_choice(wordlist)
            state["entropy"] = entropy
            state["mnemonic"] = mnemonic
            state["source_label"] = source_label
            print("\nEtapa 1/5 completada: origen seleccionado")
            print(f"- Origen: {source_label}")
            print(f"- Mnemotecnica: {mnemonic}")

            if entropy is not None:
                try:
                    breakdown = build_bip39_breakdown(entropy, wordlist)
                except ValueError as exc:
                    print(
                        _error_message(
                            "DOMINIO BIP39",
                            f"validacion de reglas BIP39 fallida ({exc})",
                            "revisa la entropia y la integridad de la wordlist",
                        ),
                        file=sys.stderr,
                    )
                    return 4

                b39_action = _run_bip39_guided_substeps(breakdown)
                if b39_action == "cancel":
                    print("Flujo cancelado por usuario. Salida limpia.")
                    return 0
                if b39_action == "retry":
                    continue
            else:
                _print_manual_mnemonic_limit_note()
                b39_action = _prompt_continue_with_options()
                if b39_action == "cancel":
                    print("Flujo cancelado por usuario. Salida limpia.")
                    return 0
                if b39_action == "retry":
                    continue

            stage_index += 1
            continue

        elif stage_index == 1:
            passphrase = _prompt_passphrase()
            state["passphrase"] = passphrase
            print("\nEtapa 2/5 completada: passphrase configurada")
            print(f"- Passphrase: {_display_sensitive(passphrase, show_secrets=False)}")

        elif stage_index == 2:
            network = _prompt_network()
            state["network"] = network
            print("\nEtapa 3/5 completada: red seleccionada")
            print(f"- Red: {network}")

        elif stage_index == 3:
            path = _prompt_hd_path(str(state["network"]))
            state["path"] = path
            print("\nEtapa 4/5 completada: ruta HD definida")
            print(f"- Ruta: {path}")

        else:
            show_secrets = _prompt_show_secrets()
            state["show_secrets"] = show_secrets
            print("\nEtapa 5/5 completada: politica de visualizacion")
            print("- Secretos: visibles" if show_secrets else "- Secretos: redactados")

        action = _prompt_continue_with_options()
        if action == "cancel":
            print("Flujo cancelado por usuario. Salida limpia.")
            return 0
        if action == "continue":
            stage_index += 1

    try:
        return _print_full_journey(
            entropy=state["entropy"],
            mnemonic=str(state["mnemonic"]),
            passphrase=str(state["passphrase"]),
            path=str(state["path"]),
            network=str(state["network"]),
            wordlist=wordlist,
            compare_passphrase=None,
            compare_path=None,
            show_secrets=bool(state["show_secrets"]),
        )
    except ValueError as exc:
        print(
            _error_message(
                "DOMINIO BIP32",
                f"no se pudo derivar flujo guiado ({exc})",
                "verifica mnemotecnica, passphrase, ruta y red",
            ),
            file=sys.stderr,
        )
        return 4


def _print_compact_breakdown(breakdown) -> None:
    print("1. Resumen")
    print("   Por que: Vista rapida para validar valores clave de BIP39.")
    print(f"   Entropia (hex):      {breakdown.entropy_hex}")
    print(f"   Bits entropia:       {len(breakdown.entropy_bits)}")
    print(f"   Bits checksum:       {len(breakdown.checksum_bits)}")
    print(f"   Bits totales:        {len(breakdown.entropy_plus_checksum_bits)}")
    print(f"   Numero de palabras:  {len(breakdown.steps)}")
    print(f"   Mnemonic:            {breakdown.mnemonic}")


def _print_seed_derivation(
    mnemonic: str, passphrase: str, *, show_secrets: bool
) -> None:
    seed_bytes = derive_bip39_seed(mnemonic, passphrase)
    salt = build_bip39_seed_salt(passphrase)

    print()
    print("6. Seed BIP39")
    print("   Por que: Convierte la mnemotecnica en semilla binaria para BIP32.")
    print(f"   Mnemonic usada:      {mnemonic}")
    if passphrase:
        print(f"   Passphrase:          {passphrase}")
    else:
        print("   Passphrase:          (vacia)")
    print("   Salt PBKDF2:         'mnemonic' + passphrase")
    print(f"   Salt efectivo:       {salt}")
    print("   KDF:                 PBKDF2-HMAC-SHA512, iteraciones=2048")
    print(
        f"   Seed (hex, 64 bytes): {_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)}"
    )


def _print_bip32_derivation(seed_bytes: bytes, *, show_secrets: bool) -> None:
    master = derive_bip32_master_node(seed_bytes)
    print()
    print("7. Master node BIP32")
    print(
        "   Por que: BIP32 separa secreto (master key) y ruta de derivacion (chain code)."
    )
    print(
        f"   I = HMAC-SHA512:     {_display_sensitive(master.hmac_i.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   IL (master key):     {_display_sensitive(master.master_private_key.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   IR (chain code):     {_display_sensitive(master.chain_code.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   Master private key:  {_display_sensitive(master.master_private_key.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   Chain code:          {_display_sensitive(master.chain_code.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   xprv (mainnet):      {_display_sensitive(master.xprv, show_secrets=show_secrets)}"
    )
    print(f"   xpub (mainnet):      {master.xpub}")


def _print_bip32_path_derivation(
    seed_bytes: bytes, path: str, show_steps: bool, network: str, *, show_secrets: bool
) -> None:
    parsed = parse_bip32_path(path)
    master = derive_bip32_master_node(seed_bytes)
    current = derive_bip32_node_from_master(master)

    print()
    print("8. Ruta HD BIP32")
    print("   Por que: Permite derivar cuentas/direcciones sin exponer la master key.")
    print(f"   Ruta solicitada:     {path}")

    if show_steps:
        print("   Pasos:")
        if not parsed:
            print("   - m (sin derivacion, se mantiene nodo master)")
        for step in parsed:
            current = derive_bip32_path_from_node(current, f"m/{step.token}")
            index_label = (
                step.child_number - HARDENED_OFFSET
                if step.hardened
                else step.child_number
            )
            hardened_label = "hardened" if step.hardened else "normal"
            print(
                f"   - {step.token}: index={index_label}, tipo={hardened_label}, depth={current.depth}, fp_padre={current.parent_fingerprint.hex()}"
            )
    else:
        current = derive_bip32_path_from_node(current, path)

    print(f"   Depth final:         {current.depth}")
    print(f"   Child number final:  {current.child_number}")
    print(f"   Parent fingerprint:  {current.parent_fingerprint.hex()}")
    print(
        f"   xprv derivado:       {_display_sensitive(current.xprv, show_secrets=show_secrets)}"
    )
    print(f"   xpub derivado:       {current.xpub}")

    p2wpkh = derive_p2wpkh_address_from_node(current, network)
    print()
    print("9. Direccion Bitcoin P2WPKH (Bech32)")
    print("   Por que: Convierte la pubkey derivada en direccion SegWit v0 utilizable.")
    print(f"   Red:                 {network} ({p2wpkh.hrp})")
    print(
        f"   Pubkey comprimida:   {_display_sensitive(p2wpkh.compressed_pubkey.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   HASH160(pubkey):     {_display_sensitive(p2wpkh.hash160.hex(), show_secrets=show_secrets)}"
    )
    print(
        f"   Witness program:     OP_{p2wpkh.witness_version} {p2wpkh.witness_program.hex()}"
    )
    print(f"   Direccion final:     {p2wpkh.address}")


def _default_path_for_network(network: str) -> str:
    if network == "testnet":
        return "m/84'/1'/0'/0/0"
    return "m/84'/0'/0'/0/0"


def _derive_path_artifacts(
    seed_bytes: bytes, path: str, network: str
) -> dict[str, str]:
    master = derive_bip32_master_node(seed_bytes)
    root = derive_bip32_node_from_master(master)
    node = derive_bip32_path_from_node(root, path)
    addr = derive_p2wpkh_address_from_node(node, network)
    return {
        "path": path,
        "xprv": node.xprv,
        "xpub": node.xpub,
        "address": addr.address,
    }


def _build_pipeline_artifacts(
    *,
    entropy: bytes | None,
    mnemonic: str,
    passphrase: str,
    path: str,
    network: str,
) -> dict[str, object]:
    seed_bytes = derive_bip39_seed(mnemonic, passphrase)
    master = derive_bip32_master_node(seed_bytes)
    root = derive_bip32_node_from_master(master)
    derived = derive_bip32_path_from_node(root, path)
    final_addr = derive_p2wpkh_address_from_node(derived, network)

    entropy_hex = entropy.hex() if entropy is not None else None
    return {
        "entropy_hex": entropy_hex,
        "mnemonic": mnemonic,
        "passphrase": passphrase,
        "seed_bytes": seed_bytes,
        "seed_fingerprint": hashlib.sha256(seed_bytes).hexdigest(),
        "salt": build_bip39_seed_salt(passphrase),
        "master": master,
        "derived": derived,
        "final_addr": final_addr,
        "path": path,
        "network": network,
    }


def _print_tui_read_only_panels(
    artifacts: dict[str, object], *, show_secrets: bool
) -> int:
    print("+--------------------------------------------------------------------+")
    print("| Seed Steps - TUI Educativa (READ-ONLY)                             |")
    print("+--------------------------------------------------------------------+")

    entropy_hex = artifacts["entropy_hex"]
    mnemonic = artifacts["mnemonic"]
    passphrase = artifacts["passphrase"]
    seed_bytes = artifacts["seed_bytes"]
    master = artifacts["master"]
    derived = artifacts["derived"]
    final_addr = artifacts["final_addr"]
    path = artifacts["path"]
    network = artifacts["network"]

    print("[Panel 1/3] Inputs usados")
    print(
        f"- entropy:    {entropy_hex if entropy_hex else '(no provista: entrada por --mnemonic)'}"
    )
    print(f"- mnemonic:   {mnemonic}")
    print(f"- passphrase: {passphrase or '(vacia)'}")
    print(f"- path:       {path}")
    print(f"- network:    {network}")
    print()

    print("[Panel 2/3] Resultado por etapa")
    print(f"- BIP39 mnemonic:  {mnemonic}")
    print(
        "- BIP39 seed:      "
        f"{_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)}"
    )
    print(
        "- BIP32 master:    "
        f"xprv={_display_sensitive(master.xprv, show_secrets=show_secrets)} | xpub={master.xpub}"
    )
    print(
        "- BIP32 ruta:      "
        f"xprv={_display_sensitive(derived.xprv, show_secrets=show_secrets)} | xpub={derived.xpub}"
    )
    print(f"- P2WPKH address:  {final_addr.address}")
    print()

    print("[Panel 3/3] Resumen ejecutivo")
    print(f"- red:             {network} ({final_addr.hrp})")
    print(f"- ruta final:      {path}")
    print(f"- salt PBKDF2:     {artifacts['salt']}")
    print(f"- seed sha256:     {artifacts['seed_fingerprint']}")
    print(f"- direccion final: {final_addr.address}")
    print("- politica:        secreto redactado por defecto")
    print("- advertencia:     EDUCATIVO, NO CUSTODIA REAL")
    return 0


def _print_full_journey(
    *,
    entropy: bytes | None,
    mnemonic: str,
    passphrase: str,
    path: str,
    network: str,
    wordlist: list[str],
    compare_passphrase: str | None,
    compare_path: str | None,
    show_secrets: bool,
) -> int:
    _print_header()
    print("Modo: Full Journey E2E (educativo guiado)")
    print()

    if entropy is not None:
        breakdown = build_bip39_breakdown(entropy, wordlist)
        print("1. Entropia -> Mnemotecnica (BIP39)")
        print("   Que es: Entropia cruda convertida a palabras mediante checksum.")
        print(
            "   Por que importa: La calidad de esta entropia define todo el arbol de claves."
        )
        print(
            "   Que se rompe si cambia: Cambia la mnemotecnica y TODO (seed/xprv/xpub/direcciones)."
        )
        print(f"   Entropia (hex):      {breakdown.entropy_hex}")
        print(f"   Checksum bits:       {breakdown.checksum_bits}")
        print(f"   Mnemotecnica:        {breakdown.mnemonic}")
    else:
        breakdown = None
        print("1. Entrada mnemotecnica explicita")
        print(
            "   Que es: Se recibe una mnemotecnica ya formada (no se recalcula entropia)."
        )
        print(
            "   Por que importa: Permite continuar el flujo sin exponer el origen de la entropia."
        )
        print(
            "   Que se rompe si cambia: Una sola palabra distinta cambia toda la seed y derivaciones."
        )
        print(f"   Mnemotecnica:        {mnemonic}")

    artifacts = _build_pipeline_artifacts(
        entropy=entropy,
        mnemonic=mnemonic,
        passphrase=passphrase,
        path=path,
        network=network,
    )
    seed_bytes = artifacts["seed_bytes"]
    seed_fingerprint = artifacts["seed_fingerprint"]
    master = artifacts["master"]
    derived = artifacts["derived"]
    final_addr = artifacts["final_addr"]

    print()
    print("2. Mnemotecnica -> Seed (BIP39 PBKDF2)")
    print("   Que es: KDF PBKDF2-HMAC-SHA512 (2048 iteraciones) sobre mnemonic + salt.")
    print(
        "   Por que importa: Endurece la derivacion y soporta passphrase como factor extra."
    )
    print("   Que se rompe si cambia: Passphrase distinta => seed totalmente distinta.")
    print(f"   Passphrase usada:    {passphrase or '(vacia)'}")
    print(f"   Salt efectivo:       {build_bip39_seed_salt(passphrase)}")
    print(
        f"   Seed (hex, 64 bytes): {_display_sensitive(seed_bytes.hex(), show_secrets=show_secrets)}"
    )

    print()
    print("3. Seed -> Master BIP32")
    print("   Que es: HMAC-SHA512('Bitcoin seed', seed) para obtener IL/IR.")
    print(
        "   Por que importa: IL inicia el secreto maestro y IR el chain code del arbol HD."
    )
    print(
        "   Que se rompe si cambia: Se altera todo el arbol de derivacion (xprv/xpub/hijos)."
    )
    print(
        f"   xprv master:         {_display_sensitive(master.xprv, show_secrets=show_secrets)}"
    )
    print(f"   xpub master:         {master.xpub}")

    print()
    print("4. Master -> Ruta derivada")
    print("   Que es: Aplicar la ruta HD para llegar a una clave hija concreta.")
    print("   Por que importa: Separa cuentas/ramas y evita reutilizacion de claves.")
    print(
        "   Que se rompe si cambia: Ruta diferente => xprv/xpub/direccion diferentes."
    )
    print(f"   Ruta usada:          {path}")
    print(
        f"   xprv derivado:       {_display_sensitive(derived.xprv, show_secrets=show_secrets)}"
    )
    print(f"   xpub derivado:       {derived.xpub}")

    print()
    print("5. Ruta derivada -> Direccion P2WPKH")
    print("   Que es: Pubkey comprimida -> HASH160 -> Bech32 SegWit v0.")
    print("   Por que importa: Es la direccion compatible para recibir BTC.")
    print("   Que se rompe si cambia: Pubkey/ruta/red distinta => direccion distinta.")
    print(f"   Red:                 {network} ({final_addr.hrp})")
    print(f"   Direccion final:     {final_addr.address}")

    if compare_passphrase:
        print()
        print("6. Comparador pedagogico: passphrase vacia vs valor")
        print(
            "   Que se compara: mismo mnemonic, passphrase='' frente a passphrase personalizada."
        )
        empty_seed = derive_bip39_seed(mnemonic, "")
        custom_seed = derive_bip39_seed(mnemonic, compare_passphrase)
        empty_artifacts = _derive_path_artifacts(empty_seed, path, network)
        custom_artifacts = _derive_path_artifacts(custom_seed, path, network)
        print(
            f"   Caso A (vacia) seed: {_display_sensitive(empty_seed.hex(), show_secrets=show_secrets)}"
        )
        print(
            f"   Caso B ('{compare_passphrase}') seed: {_display_sensitive(custom_seed.hex(), show_secrets=show_secrets)}"
        )
        print(
            f"   A xprv:              {_display_sensitive(empty_artifacts['xprv'], show_secrets=show_secrets)}"
        )
        print(
            f"   B xprv:              {_display_sensitive(custom_artifacts['xprv'], show_secrets=show_secrets)}"
        )
        print(f"   A xpub:              {empty_artifacts['xpub']}")
        print(f"   B xpub:              {custom_artifacts['xpub']}")
        print(f"   A direccion:         {empty_artifacts['address']}")
        print(f"   B direccion:         {custom_artifacts['address']}")

    if compare_path:
        print()
        print("7. Comparador pedagogico: ruta A vs ruta B")
        print("   Que se compara: misma seed, dos rutas HD distintas.")
        path_a = _derive_path_artifacts(seed_bytes, path, network)
        path_b = _derive_path_artifacts(seed_bytes, compare_path, network)
        print(f"   Ruta A:              {path_a['path']}")
        print(f"   Ruta B:              {path_b['path']}")
        print(
            f"   A xprv:              {_display_sensitive(path_a['xprv'], show_secrets=show_secrets)}"
        )
        print(
            f"   B xprv:              {_display_sensitive(path_b['xprv'], show_secrets=show_secrets)}"
        )
        print(f"   A xpub:              {path_a['xpub']}")
        print(f"   B xpub:              {path_b['xpub']}")
        print(f"   A direccion:         {path_a['address']}")
        print(f"   B direccion:         {path_b['address']}")

    print()
    print("Resumen ejecutivo")
    print(f"   Red:                 {network}")
    print(f"   Ruta final:          {path}")
    print(f"   Mnemotecnica usada:  {mnemonic}")
    print(f"   Seed resumen:        sha256={seed_fingerprint}")
    print(f"   xpub derivada:       {derived.xpub}")
    print(f"   Direccion final:     {final_addr.address}")
    print("   ADVERTENCIA: EDUCATIVO, NO CUSTODIA REAL")
    return 0


def run() -> int:
    parser = build_parser()
    args = parser.parse_args()

    wordlist_path = files("seed_steps").joinpath("data/english.txt")

    try:
        with as_file(wordlist_path) as resolved_path:
            wordlist = load_wordlist(resolved_path)
    except FileNotFoundError as exc:
        print(
            _error_message(
                "OPERATIVO",
                f"no se encontro la wordlist BIP39 ({exc})",
                "verifica que exista seed_steps/data/english.txt en la instalacion",
            ),
            file=sys.stderr,
        )
        return 3
    except ValueError as exc:
        print(
            _error_message(
                "CONFIGURACION",
                f"wordlist BIP39 invalida ({exc})",
                "asegura 2048 palabras no vacias en english.txt",
            ),
            file=sys.stderr,
        )
        return 3

    if args.interactive:
        return _run_interactive(wordlist)

    show_secrets = args.show_secrets and not args.no_secrets
    if show_secrets:
        _print_secrets_warning()
        print()

    if args.tui:
        if args.mnemonic:
            mnemonic = args.mnemonic
            entropy = None
        else:
            try:
                entropy = (
                    parse_entropy_hex(args.entropy)
                    if args.entropy
                    else generate_entropy(16)
                )
            except ValueError as exc:
                print(
                    _error_message(
                        "ENTRADA",
                        f"valor invalido en --entropy ({exc})",
                        "usa un hexadecimal valido de 128/160/192/224/256 bits",
                    ),
                    file=sys.stderr,
                )
                return 2
            try:
                breakdown = build_bip39_breakdown(entropy, wordlist)
            except ValueError as exc:
                print(
                    _error_message(
                        "DOMINIO BIP39",
                        f"validacion de reglas BIP39 fallida ({exc})",
                        "revisa la entropia y la integridad de la wordlist",
                    ),
                    file=sys.stderr,
                )
                return 4
            mnemonic = breakdown.mnemonic

        tui_path = args.path or _default_path_for_network(args.network)
        try:
            artifacts = _build_pipeline_artifacts(
                entropy=entropy,
                mnemonic=mnemonic,
                passphrase=args.passphrase,
                path=tui_path,
                network=args.network,
            )
            return _print_tui_read_only_panels(artifacts, show_secrets=show_secrets)
        except ValueError as exc:
            print(
                _error_message(
                    "DOMINIO BIP32",
                    f"no se pudo derivar flujo TUI ({exc})",
                    "verifica seed, ruta y red para la derivacion",
                ),
                file=sys.stderr,
            )
            return 4

    if args.full_journey:
        if args.mnemonic:
            mnemonic = args.mnemonic
            entropy = None
        else:
            try:
                entropy = (
                    parse_entropy_hex(args.entropy)
                    if args.entropy
                    else generate_entropy(16)
                )
            except ValueError as exc:
                print(
                    _error_message(
                        "ENTRADA",
                        f"valor invalido en --entropy ({exc})",
                        "usa un hexadecimal valido de 128/160/192/224/256 bits",
                    ),
                    file=sys.stderr,
                )
                return 2
            try:
                breakdown = build_bip39_breakdown(entropy, wordlist)
            except ValueError as exc:
                print(
                    _error_message(
                        "DOMINIO BIP39",
                        f"validacion de reglas BIP39 fallida ({exc})",
                        "revisa la entropia y la integridad de la wordlist",
                    ),
                    file=sys.stderr,
                )
                return 4
            mnemonic = breakdown.mnemonic

        full_path = args.path or _default_path_for_network(args.network)
        try:
            return _print_full_journey(
                entropy=entropy,
                mnemonic=mnemonic,
                passphrase=args.passphrase,
                path=full_path,
                network=args.network,
                wordlist=wordlist,
                compare_passphrase=args.compare_passphrase,
                compare_path=args.compare_path,
                show_secrets=show_secrets,
            )
        except ValueError as exc:
            print(
                _error_message(
                    "DOMINIO BIP32",
                    f"no se pudo derivar flujo completo ({exc})",
                    "verifica seed, ruta y red para la derivacion",
                ),
                file=sys.stderr,
            )
            return 4

    if args.mnemonic:
        _print_header()
        seed_bytes = derive_bip39_seed(args.mnemonic, args.passphrase)
        _print_seed_derivation(
            args.mnemonic, args.passphrase, show_secrets=show_secrets
        )
        if args.derive_bip32 or args.path:
            try:
                _print_bip32_derivation(seed_bytes, show_secrets=show_secrets)
                if args.path:
                    _print_bip32_path_derivation(
                        seed_bytes,
                        args.path,
                        args.path_steps,
                        args.network,
                        show_secrets=show_secrets,
                    )
            except ValueError as exc:
                print(
                    _error_message(
                        "DOMINIO BIP32",
                        f"no se pudo derivar master node ({exc})",
                        "verifica que la seed sea valida para BIP32",
                    ),
                    file=sys.stderr,
                )
                return 4
        return 0

    try:
        entropy = (
            parse_entropy_hex(args.entropy) if args.entropy else generate_entropy(16)
        )
    except ValueError as exc:
        print(
            _error_message(
                "ENTRADA",
                f"valor invalido en --entropy ({exc})",
                "usa un hexadecimal valido de 128/160/192/224/256 bits",
            ),
            file=sys.stderr,
        )
        return 2

    try:
        breakdown = build_bip39_breakdown(entropy, wordlist)
    except ValueError as exc:
        print(
            _error_message(
                "DOMINIO BIP39",
                f"validacion de reglas BIP39 fallida ({exc})",
                "revisa la entropia y la integridad de la wordlist",
            ),
            file=sys.stderr,
        )
        return 4

    _print_header()
    if args.compact:
        _print_compact_breakdown(breakdown)
    else:
        _print_detailed_breakdown(breakdown)

    seed_bytes = None
    if args.derive_seed or args.passphrase or args.derive_bip32 or args.path:
        seed_bytes = derive_bip39_seed(breakdown.mnemonic, args.passphrase)
        _print_seed_derivation(
            breakdown.mnemonic, args.passphrase, show_secrets=show_secrets
        )
    if args.derive_bip32 or args.path:
        try:
            _print_bip32_derivation(seed_bytes, show_secrets=show_secrets)
            if args.path:
                _print_bip32_path_derivation(
                    seed_bytes,
                    args.path,
                    args.path_steps,
                    args.network,
                    show_secrets=show_secrets,
                )
        except ValueError as exc:
            print(
                _error_message(
                    "DOMINIO BIP32",
                    f"no se pudo derivar master node ({exc})",
                    "verifica que la seed sea valida para BIP32",
                ),
                file=sys.stderr,
            )
            return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
