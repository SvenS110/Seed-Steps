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


def test_cli_interactive_auto_mode_guides_all_stages(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--interactive"])

    inputs = iter(["a", "", "", "", "", ""])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Bienvenido al modo wizard de Seed Steps." in captured.out
    assert "1. Entropia" in captured.out
    assert "2. Checksum" in captured.out
    assert "3. Bits combinados" in captured.out
    assert "4. Indices" in captured.out
    assert "5. Mnemotecnica" in captured.out


def test_cli_interactive_manual_entropy_retries_on_invalid_input(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--wizard"])

    inputs = iter(
        [
            "manual",
            "zzzz",
            "00000000000000000000000000000000",
            "",
            "",
            "",
            "",
            "",
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Entrada invalida:" in captured.out
    assert "Entropia (hex):      00000000000000000000000000000000" in captured.out
    assert (
        "Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        in captured.out
    )


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
    assert (
        "Seed (hex, 64 bytes): c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        in captured.out
    )


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
    assert "xprv (mainnet):      xprv9s21ZrQH143K3" in captured.out
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
