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
