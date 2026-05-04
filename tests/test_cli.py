import sys
from pathlib import Path

from seed_steps.cli import run


def test_cli_detailed_output_by_default(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["seed-steps", "--entropy", "00000000000000000000000000000000"],
    )

    exit_code = run()
    captured = capsys.readouterr().out

    assert exit_code == 0
    assert "1. Entropia" in captured
    assert "2. Checksum" in captured
    assert "3. Bits combinados" in captured
    assert "4. Indices" in captured
    assert "5. Mnemotecnica" in captured
    assert "Tamano de entropia:  128 bits" in captured
    assert "Tamano checksum:     4 bits" in captured
    assert "Total de bits:       132 bits" in captured
    assert "Numero de palabras:  12" in captured
    assert "pos | bloque(11-bit) | indice | palabra" in captured
    assert "Mnemonic: abandon abandon" in captured


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
    assert "1. Resumen" in captured
    assert "Bits entropia:       128" in captured
    assert "Bits checksum:       4" in captured
    assert "Bits totales:        132" in captured
    assert "Numero de palabras:  12" in captured
    assert "Mnemonic:" in captured
    assert "5. Mnemotecnica" not in captured
    assert "pos | bloque(11-bit) | indice | palabra" not in captured


def test_cli_fails_when_entropy_is_not_hex(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--entropy", "zzzz"])

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "ERROR ENTRADA:" in captured.err
    assert "Accion sugerida:" in captured.err
    assert "hexadecimal invalida" in captured.err


def test_cli_fails_when_entropy_length_is_invalid(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--entropy", "abcd"])

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "ERROR ENTRADA:" in captured.err
    assert "Accion sugerida:" in captured.err
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

    assert exit_code == 3
    assert "ERROR OPERATIVO:" in captured.err
    assert "wordlist BIP39" in captured.err
    assert "Accion sugerida:" in captured.err


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

    assert exit_code == 4
    assert "ERROR DOMINIO BIP39:" in captured.err
    assert "2048 palabras" in captured.err
    assert "Accion sugerida:" in captured.err
