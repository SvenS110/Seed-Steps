import sys
import re
import os
from pathlib import Path

from seed_steps.cli import run


GOLDEN_DIR = Path(__file__).parent / "golden"
UPDATE_GOLDENS = "UPDATE_GOLDENS"


ERROR_PATTERN = re.compile(
    r"^ERROR (?P<type>[A-Z0-9 ]+): (?P<cause>.+)\. Accion sugerida: (?P<guide>.+)\.$"
)


def _assert_error_contract(
    captured, *, exit_code: int, expected_code: int, expected_type: str
) -> None:
    assert exit_code == expected_code
    assert captured.out == ""

    error_line = captured.err.strip()
    match = ERROR_PATTERN.match(error_line)
    assert match is not None
    assert match.group("type") == expected_type
    assert match.group("cause")
    assert match.group("guide")


def _normalize_output(output: str) -> str:
    normalized_lines = [line.rstrip() for line in output.splitlines()]

    while normalized_lines and normalized_lines[-1] == "":
        normalized_lines.pop()

    return "\n".join(normalized_lines) + "\n"


def _assert_matches_golden(output: str, filename: str) -> None:
    golden_path = GOLDEN_DIR / filename
    normalized_output = _normalize_output(output)

    if os.getenv(UPDATE_GOLDENS) == "1":
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(normalized_output, encoding="utf-8")

    expected = golden_path.read_text(encoding="utf-8")
    assert normalized_output == expected


def test_cli_detailed_output_by_default(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["seed-steps", "--entropy", "00000000000000000000000000000000"],
    )

    exit_code = run()
    captured = capsys.readouterr().out

    assert exit_code == 0
    _assert_matches_golden(captured, "detailed_default.txt")


def test_cli_compact_output_hides_detailed_table(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--entropy",
            "00000000000000000000000000000000",
            "--compact",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr().out

    assert exit_code == 0
    _assert_matches_golden(captured, "compact.txt")


def test_cli_fails_when_entropy_is_not_hex(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--entropy", "zzzz"])

    exit_code = run()
    captured = capsys.readouterr()

    _assert_error_contract(
        captured,
        exit_code=exit_code,
        expected_code=2,
        expected_type="ENTRADA",
    )
    assert "hexadecimal invalida" in captured.err


def test_cli_fails_when_entropy_length_is_invalid(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--entropy", "abcd"])

    exit_code = run()
    captured = capsys.readouterr()

    _assert_error_contract(
        captured,
        exit_code=exit_code,
        expected_code=2,
        expected_type="ENTRADA",
    )
    assert "Longitud de entropy invalida" in captured.err


def test_cli_fails_when_wordlist_file_is_missing(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["seed-steps", "--entropy", "00000000000000000000000000000000"],
    )

    def fake_load_wordlist(_: Path) -> list[str]:
        raise FileNotFoundError("Wordlist file not found: seed_steps/data/english.txt")

    monkeypatch.setattr("seed_steps.cli.load_wordlist", fake_load_wordlist)

    exit_code = run()
    captured = capsys.readouterr()

    _assert_error_contract(
        captured,
        exit_code=exit_code,
        expected_code=3,
        expected_type="OPERATIVO",
    )
    assert "wordlist BIP39" in captured.err


def test_cli_fails_when_wordlist_is_malformed(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["seed-steps", "--entropy", "00000000000000000000000000000000"],
    )

    def fake_load_wordlist(_: Path) -> list[str]:
        raise ValueError("Se esperaban 2048 palabras y llegaron 2000")

    monkeypatch.setattr("seed_steps.cli.load_wordlist", fake_load_wordlist)

    exit_code = run()
    captured = capsys.readouterr()

    _assert_error_contract(
        captured,
        exit_code=exit_code,
        expected_code=3,
        expected_type="CONFIGURACION",
    )
    assert "wordlist BIP39 invalida" in captured.err


def test_cli_fails_with_domain_validation_error(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["seed-steps", "--entropy", "00000000000000000000000000000000"],
    )

    def fake_build_breakdown(*_args, **_kwargs):
        raise ValueError("La wordlist debe contener exactamente 2048 palabras")

    monkeypatch.setattr("seed_steps.cli.build_bip39_breakdown", fake_build_breakdown)

    exit_code = run()
    captured = capsys.readouterr()

    _assert_error_contract(
        captured,
        exit_code=exit_code,
        expected_code=4,
        expected_type="DOMINIO BIP39",
    )
    assert "2048 palabras" in captured.err


def test_cli_interactive_guided_flow_happy_path(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--interactive"])

    inputs = iter(
        [
            "a",
            "128",
            "s",
            "s",
            "s",
            "s",
            "s",
            "",
            "s",
            "s",
            "mainnet",
            "d",
            "s",
            "s",
        ]
    )

    def fake_input(prompt=""):
        prompt_l = prompt.lower()
        try:
            return next(inputs)
        except StopIteration:
            if "red objetivo" in prompt_l:
                return "mainnet"
            if "ruta hd" in prompt_l:
                return "d"
            if "continuamos al siguiente" in prompt_l:
                return "s"
            return ""

    monkeypatch.setattr("builtins.input", fake_input)

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Bienvenido a Seed Steps by SvenS101" in captured.out
    assert "Etapa 1/5 completada: origen seleccionado" in captured.out
    assert "Subpaso BIP39 1/5: Entropia" in captured.out
    assert "Objetivo del paso:" in captured.out
    assert "Que debes observar:" in captured.out
    assert "Subpaso BIP39 4/5: Indices (bloques de 11 bits)" in captured.out
    assert "Subpaso BIP39 5/5: Mnemotecnica" in captured.out
    assert "Fase B) Seed BIP39" in captured.out
    assert "Micro-operacion 1" in captured.out
    assert "- Entrada:" in captured.out
    assert "- Operacion:" in captured.out
    assert "- Salida:" in captured.out
    assert "Fase C) Master BIP32" in captured.out
    assert "Fase D) Ruta HD" in captured.out
    assert "Fase E) Direccion" in captured.out
    assert "Fase F) Resumen final" in captured.out
    assert "Direccion final:" in captured.out
    assert "Nota docente: en el wizard se muestran valores COMPLETOS" in captured.out


def test_cli_interactive_guided_retries_invalid_inputs(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--wizard"])

    inputs = iter(
        [
            "x",
            "e",
            "zzzz",
            "00000000000000000000000000000000",
            "s",
            "s",
            "s",
            "s",
            "s",
            "",
            "s",
            "s",
            "devnet",
            "testnet",
            "m",
            "84'/0'/0'/0/0",
            "m",
            "m/84'/1'/0'/0/0",
            "s",
            "s",
        ]
    )

    def fake_input(prompt=""):
        prompt_l = prompt.lower()
        try:
            return next(inputs)
        except StopIteration:
            if "red objetivo" in prompt_l:
                return "testnet"
            if "ruta hd" in prompt_l:
                return "d"
            if "continuamos al siguiente" in prompt_l:
                return "s"
            return ""

    monkeypatch.setattr("builtins.input", fake_input)

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Opcion invalida. Escribe A, E o M." in captured.out
    assert "Entrada invalida: Entropy hexadecimal invalida" in captured.out
    assert "Subpaso BIP39 2/5: Checksum" in captured.out
    assert "Fase B) Seed BIP39" in captured.out
    assert "Fase F) Resumen final" in captured.out
    assert "Direccion final:" in captured.out
    assert "tb1" in captured.out


def test_cli_interactive_guided_continue_no_can_cancel_flow(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--interactive"])

    inputs = iter(["a", "128", "n", "c"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Flujo cancelado por usuario. Salida limpia." in captured.out
    assert "Modo: Full Journey E2E" not in captured.out


def test_cli_interactive_guided_manual_mnemonic_explains_bip39_limit(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--wizard"])

    inputs = iter(
        [
            "m",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "s",
            "",
            "s",
            "s",
            "mainnet",
            "d",
            "s",
            "s",
        ]
    )

    def fake_input(prompt=""):
        prompt_l = prompt.lower()
        try:
            return next(inputs)
        except StopIteration:
            if "red objetivo" in prompt_l:
                return "mainnet"
            if "ruta hd" in prompt_l:
                return "d"
            if "continuamos al siguiente" in prompt_l:
                return "s"
            return ""

    monkeypatch.setattr("builtins.input", fake_input)

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert (
        "No se puede reconstruir de forma fiable la entropia/checksum/bloques de 11 bits ORIGINALES"
        in captured.out
    )
    assert "Objetivo del paso: aclarar el limite didactico" in captured.out
    assert "Fase B) Seed BIP39" in captured.out


def test_cli_derives_seed_from_explicit_mnemonic(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--passphrase",
            "TREZOR",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "6. Seed BIP39" in captured.out
    assert "Salt efectivo:       mnemonicTREZOR" in captured.out
    assert "Seed (hex, 64 bytes): c55257c3..." in captured.out
    assert "[sha256:" in captured.out


def test_cli_derives_seed_from_generated_mnemonic(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--entropy",
            "00000000000000000000000000000000",
            "--derive-seed",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert (
        "Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        in captured.out
    )
    assert "6. Seed BIP39" in captured.out
    assert "Passphrase:          (vacia)" in captured.out
    assert "Salt efectivo:       mnemonic" in captured.out


def test_cli_derives_bip32_from_explicit_mnemonic(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--passphrase",
            "TREZOR",
            "--derive-bip32",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "7. Master node BIP32" in captured.out
    assert "I = HMAC-SHA512:" in captured.out
    assert "xprv (mainnet):      xprv9s21..." in captured.out
    assert "[sha256:" in captured.out
    assert "xpub (mainnet):      xpub661MyMwAqRbcG" in captured.out


def test_cli_derives_bip32_from_entropy_flow(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--entropy",
            "00000000000000000000000000000000",
            "--derive-bip32",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert (
        "Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        in captured.out
    )
    assert "6. Seed BIP39" in captured.out
    assert "7. Master node BIP32" in captured.out


def test_cli_derives_bip32_path_from_mnemonic(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--passphrase",
            "TREZOR",
            "--path",
            "m/84'/0'/0'/0/0",
            "--path-steps",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "7. Master node BIP32" in captured.out
    assert "8. Ruta HD BIP32" in captured.out
    assert "Ruta solicitada:     m/84'/0'/0'/0/0" in captured.out
    assert "Pasos:" in captured.out
    assert "xprv derivado:       xprv" in captured.out
    assert "xpub derivado:       xpub" in captured.out
    assert "9. Direccion Bitcoin P2WPKH (Bech32)" in captured.out
    assert "Pubkey comprimida:" in captured.out
    assert "HASH160(pubkey):" in captured.out
    assert "Witness program:" in captured.out
    assert "Direccion final:     bc1" in captured.out


def test_cli_derives_testnet_address_from_entropy_to_path(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--entropy",
            "00000000000000000000000000000000",
            "--path",
            "m/84'/1'/0'/0/0",
            "--network",
            "testnet",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "6. Seed BIP39" in captured.out
    assert "7. Master node BIP32" in captured.out
    assert "8. Ruta HD BIP32" in captured.out
    assert "9. Direccion Bitcoin P2WPKH (Bech32)" in captured.out
    assert "Red:                 testnet (tb)" in captured.out
    assert "Direccion final:     tb1" in captured.out


def test_cli_fails_when_bip32_path_is_invalid(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--path",
            "84'/0'/0'/0/0",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 4
    match = ERROR_PATTERN.match(captured.err.strip())
    assert match is not None
    assert match.group("type") == "DOMINIO BIP32"
    assert "Ruta BIP32 invalida" in captured.err


def test_cli_full_journey_entropy_to_p2wpkh_has_narrative_and_summary(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--full-journey",
            "--entropy",
            "00000000000000000000000000000000",
            "--path",
            "m/84'/0'/0'/0/0",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Modo: Full Journey E2E (educativo guiado)" in captured.out
    assert "1. Entropia -> Mnemotecnica (BIP39)" in captured.out
    assert "2. Mnemotecnica -> Seed (BIP39 PBKDF2)" in captured.out
    assert "3. Seed -> Master BIP32" in captured.out
    assert "4. Master -> Ruta derivada" in captured.out
    assert "5. Ruta derivada -> Direccion P2WPKH" in captured.out
    assert "Resumen ejecutivo" in captured.out
    assert "ADVERTENCIA: EDUCATIVO, NO CUSTODIA REAL" in captured.out
    assert "xpub derivada:" in captured.out
    assert "Direccion final:     bc1" in captured.out


def test_cli_full_journey_with_explicit_mnemonic_and_passphrase(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--full-journey",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--passphrase",
            "TREZOR",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "1. Entrada mnemotecnica explicita" in captured.out
    assert "Passphrase usada:    TREZOR" in captured.out
    assert "Ruta final:          m/84'/0'/0'/0/0" in captured.out


def test_cli_full_journey_passphrase_comparator_shows_semantic_differences(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--full-journey",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--compare-passphrase",
            "TREZOR",
            "--path",
            "m/84'/0'/0'/0/0",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Comparador pedagogico: passphrase vacia vs valor" in captured.out
    assert "Caso A (vacia) seed:" in captured.out
    assert "Caso B ('TREZOR') seed:" in captured.out
    assert "[sha256:" in captured.out
    assert "A xprv:" in captured.out
    assert "B xprv:" in captured.out
    assert "A xpub:" in captured.out
    assert "B xpub:" in captured.out
    assert "A direccion:" in captured.out
    assert "B direccion:" in captured.out


def test_cli_full_journey_path_comparator_shows_semantic_differences(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--full-journey",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--path",
            "m/84'/0'/0'/0/0",
            "--compare-path",
            "m/84'/0'/0'/0/1",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Comparador pedagogico: ruta A vs ruta B" in captured.out
    assert "Ruta A:              m/84'/0'/0'/0/0" in captured.out
    assert "Ruta B:              m/84'/0'/0'/0/1" in captured.out
    assert "A xprv:" in captured.out
    assert "B xprv:" in captured.out
    assert "A xpub:" in captured.out
    assert "B xpub:" in captured.out
    assert "A direccion:" in captured.out
    assert "B direccion:" in captured.out


def test_cli_redacts_sensitive_material_by_default(capsys, monkeypatch) -> None:
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--mnemonic",
            mnemonic,
            "--passphrase",
            "TREZOR",
            "--derive-bip32",
            "--path",
            "m/84'/0'/0'/0/0",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "c55257c360c07c72029aebc1b53c05ed" not in captured.out
    assert "cbedc75b0d6412c8479" not in captured.out
    assert "xprv9s21ZrQH143K3" not in captured.out
    assert "[sha256:" in captured.out


def test_cli_reveals_sensitive_material_with_show_secrets(capsys, monkeypatch) -> None:
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--mnemonic",
            mnemonic,
            "--passphrase",
            "TREZOR",
            "--derive-bip32",
            "--show-secrets",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "ADVERTENCIA DE SEGURIDAD: --show-secrets" in captured.out
    assert (
        "Seed (hex, 64 bytes): c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        in captured.out
    )
    assert "xprv (mainnet):      xprv9s21ZrQH143K3" in captured.out


def test_cli_no_secrets_has_priority_over_show_secrets(capsys, monkeypatch) -> None:
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--mnemonic",
            mnemonic,
            "--passphrase",
            "TREZOR",
            "--derive-bip32",
            "--show-secrets",
            "--no-secrets",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "ADVERTENCIA DE SEGURIDAD: --show-secrets" not in captured.out
    assert "xprv9s21ZrQH143K3" not in captured.out
    assert "[sha256:" in captured.out


def test_cli_tui_smoke_has_three_panels_and_summary(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tui",
            "--entropy",
            "00000000000000000000000000000000",
            "--path",
            "m/84'/0'/0'/0/0",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Seed Steps - TUI Educativa (READ-ONLY)" in captured.out
    assert "[Panel 1/3] Inputs usados" in captured.out
    assert "[Panel 2/3] Resultado por etapa" in captured.out
    assert "[Panel 3/3] Resumen ejecutivo" in captured.out
    assert "- BIP39 seed:" in captured.out
    assert "[sha256:" in captured.out
    assert "- P2WPKH address:  bc1" in captured.out


def test_cli_tui_show_secrets_reuses_security_semantics(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tui",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--passphrase",
            "TREZOR",
            "--show-secrets",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "ADVERTENCIA DE SEGURIDAD: --show-secrets" in captured.out
    assert (
        "- BIP39 seed:      c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        in captured.out
    )
    assert "- BIP32 master:    xprv=xprv9s21ZrQH143K3" in captured.out
