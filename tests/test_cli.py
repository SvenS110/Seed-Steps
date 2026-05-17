import sys
import re
import os
from pathlib import Path

import seed_steps.cli as cli
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
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["seed-steps", "--entropy", "00000000000000000000000000000000"],
    )

    exit_code = run()
    captured = capsys.readouterr().out

    assert exit_code == 0
    _assert_matches_golden(captured, "detailed_default.txt")


def test_colorize_checksum_by_global_position_inserts_ansi_after_entropy(
    monkeypatch,
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    cli.ts.set_enabled(True)

    rendered = cli._colorize_checksum_by_global_position(
        "00000000 0011",
        bit_offset=124,
        entropy_bits_len=128,
    )

    assert cli.COLOR_CHECKSUM != cli.COLOR_SEED
    assert "0000" in rendered
    assert cli.COLOR_CHECKSUM in rendered
    assert f"{cli.COLOR_CHECKSUM}0{cli.COLOR_RESET}" in rendered
    assert (
        f"{cli.COLOR_CHECKSUM}1{cli.COLOR_RESET}{cli.COLOR_CHECKSUM}1{cli.COLOR_RESET}"
        in rendered
    )


def test_colorize_checksum_by_global_position_without_color_returns_plain_text() -> (
    None
):
    cli.ts.set_enabled(False)

    rendered = cli._colorize_checksum_by_global_position(
        "00000000 0011",
        bit_offset=124,
        entropy_bits_len=128,
    )

    assert rendered == "00000000 0011"
    assert cli.COLOR_CHECKSUM not in rendered
    cli.ts.set_enabled(True)


def test_colorize_bit_prefix_colors_only_first_n_bits(monkeypatch) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    cli.ts.set_enabled(True)

    rendered = cli._colorize_bit_prefix(
        "00000000 11111111",
        prefix_len=4,
        color=cli.COLOR_CHECKSUM,
    )

    assert rendered.count(cli.COLOR_CHECKSUM) == 1
    assert f"{cli.COLOR_CHECKSUM}0000{cli.COLOR_RESET}" in rendered
    assert "11111111" in rendered


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
    assert "Bienvenido a " in captured.out
    assert " by SvenS101" in captured.out
    assert "Etapa 1/5 completada: origen seleccionado" in captured.out
    assert "Subpaso BIP39 1/5 — Entropia" in captured.out
    assert "Objetivo" in captured.out
    assert "Que es" in captured.out
    assert "Subpaso BIP39 4/5 — Bloques de 11 bits" in captured.out
    assert "Subpaso BIP39 5/5 — Indices y palabras" in captured.out
    assert "Fase B) Seed BIP39" in captured.out
    assert "Micro-operacion" not in captured.out
    assert "ENTER para ejecutar micro-operacion" not in captured.out
    assert "Fase C) Master BIP32" in captured.out
    assert "Fase D) Ruta HD" in captured.out
    assert "Fase E) Direccion" in captured.out
    assert "Fase F) Resumen final" in captured.out
    assert "direccion final =" in captured.out
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
    assert "Subpaso BIP39 2/5 — Checksum" in captured.out
    assert "Fase B) Seed BIP39" in captured.out
    assert "Fase F) Resumen final" in captured.out
    assert "direccion final =" in captured.out
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


def test_cli_parser_accepts_tamariz_and_shows_meetup_header(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tamariz",
            "--no-pause",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-color",
        ],
    )

    inputs = iter(["", "mainnet", "d"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Seed Steps — Modo meetup" in captured.out
    assert "BIP39 1/5 — Entropía" in captured.out
    assert "BIP39 5/5 — Índices y palabras" in captured.out


def test_cli_wizard_without_tamariz_keeps_previous_intro(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--wizard"])

    inputs = iter(["a", "128", "n", "c"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Modo meetup activado" not in captured.out
    assert "Subpaso BIP39 1/5" in captured.out


def test_cli_tamariz_keeps_network_and_manual_path_decisions(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tamariz",
            "--no-pause",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-color",
        ],
    )

    inputs = iter(["", "testnet", "m", "m/84'/1'/0'/0/1"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "- network = testnet" in captured.out
    assert "- path = m/84'/1'/0'/0/1" in captured.out
    assert "direccion final = tb1" in captured.out


def test_cli_tamariz_no_pause_has_zero_pause_prompts(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tamariz",
            "--no-pause",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-color",
        ],
    )

    inputs = iter(["", "mainnet", "d"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Listo este paso. Continuamos al siguiente?" not in captured.out
    assert "Presiona Enter para continuar..." not in captured.out
    assert "Subpaso BIP39 1/5" not in captured.out
    assert "BIP39 1/5 — Entropía" in captured.out
    assert "Pulsa Enter para ver la fase" not in captured.out


def test_cli_tamariz_shows_phase_narrative_and_hides_removed_micro_substeps(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tamariz",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-color",
            "--no-pause",
        ],
    )

    inputs = iter(["", "mainnet", "d"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "BIP39 1/5 — Entropía" in captured.out
    assert "BIP39 2/5 — Checksum" in captured.out
    assert "BIP39 3/5 — Entropía + checksum" in captured.out
    assert "entropy_bits" in captured.out
    assert "entropy_hex" in captured.out
    assert "SHA256(entropy)_bits" in captured.out
    assert "checksum =" in captured.out
    assert "BIP39 4/5 — Bloques de 11 bits" in captured.out
    assert "checksum_bits" in captured.out
    assert "entropy_plus_checksum" in captured.out
    assert "bloque[01]" in captured.out
    assert "BIP39 5/5 — Índices y palabras" in captured.out
    assert "pos | bloque(11-bit) | indice | palabra" in captured.out
    assert "Cada bloque de 11 bits se lee en big-endian" in captured.out
    assert "BIP39 1/6 — Mnemotécnica de entrada" in captured.out
    assert "BIP39 5/6 — PBKDF2-HMAC-SHA512" in captured.out
    assert "BIP39 6/6 — Seed final" in captured.out
    assert "BIP32 1/4 — Seed de entrada" in captured.out
    assert "BIP32 3/4 — Separar IL/IR" in captured.out
    assert "BIP32 4/4 — xprv/xpub master" in captured.out
    assert "Ruta HD 1/3 — Ruta elegida" in captured.out
    assert "Ruta HD 2/3 — Niveles y significado" in captured.out
    assert "Ruta HD 3/3 — Derivación y nodo final" in captured.out
    assert "index=1 se escribe como 00 00 00 01" in captured.out
    assert "Dirección 1/4 — Pubkey comprimida" in captured.out
    assert "Dirección 2/4 — HASH160 (incluye SHA256)" in captured.out
    assert "Dirección 3/4 — Witness + Bech32" in captured.out
    assert "Dirección 4/4 — Dirección final" in captured.out
    assert "Etapa 1/5 completada" not in captured.out
    assert "Fase B) Seed BIP39" not in captured.out
    assert "Fase B — BIP39: de palabras a seed" in captured.out
    assert "Fase C — BIP32: de seed a nodo maestro" in captured.out
    assert "Fase D — Ruta HD" in captured.out
    assert "Fase E — De clave pública a dirección" in captured.out
    assert "Fase F — Resumen final" in captured.out
    assert "En transacciones Bitcoin aparece mucho little-endian" in captured.out
    assert "Las palabras no se usan directamente como clave" in captured.out
    assert "BIP39 termina en la seed" in captured.out
    assert "Una dirección no es una clave privada" in captured.out
    assert "Payload xprv" not in captured.out
    assert "Payload xpub" not in captured.out
    assert "SHA256(pubkey)" in captured.out
    assert "HASH160 = RIPEMD160(SHA256(pubkey))" in captured.out
    assert "direccion = " in captured.out
    assert "iteracion 0001 -> U_1:" in captured.out
    assert "iteracion 0002 -> U_2:" in captured.out
    assert "iteracion 0003 -> U_3:" in captured.out
    assert "iteracion 2046 -> U_2046" in captured.out
    assert "iteracion 2047 -> U_2047" in captured.out
    assert "iteracion 2048 -> U_2048:" in captured.out


def test_cli_tamariz_phase_pauses_are_oriented_by_phase(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["seed-steps", "--tamariz", "--no-color"])

    phase_calls: list[str] = []

    def _fake_pause_for_meetup_phase(*, phase_label: str, no_pause: bool) -> None:
        phase_calls.append(f"{phase_label}|{no_pause}")

    monkeypatch.setattr(
        "seed_steps.cli._pause_for_meetup_phase", _fake_pause_for_meetup_phase
    )

    inputs = iter(["a", "128", "n", "mainnet", "d"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert phase_calls == [
        "ver la fase A: BIP39 de entropía a palabras|False",
        "ver la fase B: palabras a seed|False",
        "entrar en la fase C: seed a nodo maestro BIP32|False",
        "recorrer la fase D: ruta HD|False",
        "ver la fase E: clave pública a dirección|False",
        "ver la fase F: resumen final|False",
    ]


def test_cli_tamariz_without_network_still_prompts_network(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tamariz",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-color",
            "--no-pause",
        ],
    )

    calls = {"network": 0}

    def _fake_prompt_network() -> str:
        calls["network"] += 1
        return "mainnet"

    monkeypatch.setattr("seed_steps.cli._prompt_network", _fake_prompt_network)
    inputs = iter(["", "d"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert calls["network"] == 1


def test_cli_tamariz_network_override_skips_network_prompt(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tamariz",
            "--network",
            "testnet",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-color",
            "--no-pause",
        ],
    )

    def _boom_prompt_network() -> str:
        raise AssertionError(
            "_prompt_network no debe llamarse con --network en --tamariz"
        )

    monkeypatch.setattr("seed_steps.cli._prompt_network", _boom_prompt_network)
    inputs = iter(["", "d"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "- network = testnet" in captured.out


def test_cli_tamariz_path_override_skips_path_prompt(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tamariz",
            "--path",
            "m/84'/1'/0'/0/0",
            "--network",
            "testnet",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-color",
            "--no-pause",
        ],
    )

    def _boom_prompt_path(_network: str) -> str:
        raise AssertionError("_prompt_hd_path no debe llamarse con --path en --tamariz")

    monkeypatch.setattr("seed_steps.cli._prompt_hd_path", _boom_prompt_path)
    inputs = iter([""])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "- path = m/84'/1'/0'/0/0" in captured.out


def test_cli_tamariz_bip84_mainnet_shows_zprv_zpub_in_phase_d(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tamariz",
            "--path",
            "m/84'/0'/0'/0/0",
            "--network",
            "mainnet",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-color",
            "--no-pause",
        ],
    )

    inputs = iter([""])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "- xprv derivado (nodo hoja /0/0, no account) = xprv" in captured.out
    assert "- xpub derivado (nodo hoja /0/0, no account) = xpub" in captured.out
    assert "- zprv derivado (nodo hoja /0/0, no account) = zprv" in captured.out
    assert "- zpub derivado (nodo hoja /0/0, no account) = zpub" in captured.out


def test_cli_tamariz_bip84_testnet_shows_vprv_vpub_in_phase_d(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--tamariz",
            "--path",
            "m/84'/1'/0'/0/0",
            "--network",
            "testnet",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-color",
            "--no-pause",
        ],
    )

    inputs = iter([""])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "- vprv derivado (nodo hoja /0/0, no account) = vprv" in captured.out
    assert "- vpub derivado (nodo hoja /0/0, no account) = vpub" in captured.out


def test_cli_wizard_no_pause_entropy_zero_shows_known_bip39_math_trace(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--wizard",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-pause",
            "--no-color",
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
    assert "CHECKSUM = prefijo del digest SHA-256 de la entropia" in captured.out
    assert "ENT = 128 bits" in captured.out
    assert "CS = 4 bits" in captured.out
    assert "checksum = 0011" in captured.out
    assert "full_bits_length = 132 bits" in captured.out
    assert "wordlist[3] = about" in captured.out
    assert captured.out.count("00000000000") >= 11
    assert "00000000011" in captured.out
    assert (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        in captured.out
    )
    assert "Traza 1)" not in captured.out
    assert "Traza " not in captured.out
    assert "Micro-operacion" not in captured.out
    assert "master_private_key = parse256(IL)" in captured.out
    assert "hardened_index = index + 2^31" in captured.out
    assert "k_child = (parse256(IL) + k_parent) mod n" in captured.out
    assert "data_5bit = convertbits" in captured.out
    assert "iterations = 2048" in captured.out
    assert "iteracion 0001" in captured.out
    assert "iteracion 0002" in captured.out
    assert "iteracion 0003" in captured.out
    assert "2042 iteraciones intermedias omitidas" in captured.out
    assert "iteracion 2046" in captured.out
    assert "iteracion 2047" in captured.out
    assert "iteracion 2048" in captured.out
    assert "T_1 = U_1 XOR U_2 XOR ... XOR U_2048" in captured.out
    assert "len(seed) = 64 bytes" in captured.out


def test_cli_wizard_phase_d_has_single_clean_substep_flow(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--wizard",
            "--entropy",
            "00000000000000000000000000000000",
            "--no-pause",
            "--no-color",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.count("Subpaso 4/6 — Derivacion CKDpriv") == 1
    assert "Micro-operacion" not in captured.out
    assert "Entrada: entrada" not in captured.out
    assert "Operacion:" not in captured.out
    assert "Salida: salida" not in captured.out


def test_cli_wizard_summary_and_bip32_hmac_key_narrative_no_color(
    capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--wizard",
            "--entropy",
            "00000000000000000000000000000000",
            "--passphrase",
            "TREZOR",
            "--no-pause",
            "--no-color",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "\x1b[" not in captured.out
    assert "Bienvenido a Seed Steps by SvenS101" in captured.out
    assert "Subpaso 1/1 — Consolidado final" not in captured.out
    assert "Inputs usados:" in captured.out
    assert "Outputs clave:" in captured.out
    assert 'hmac_key = "Bitcoin seed"' in captured.out
    assert (
        '"Bitcoin seed" NO es la seed del usuario ni contrasena; es cadena ASCII fija BIP32.'
        in captured.out
    )
    assert (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        in captured.out
    )
    assert "- direccion final = bc1" in captured.out
    assert "- direccion final =\n" not in captured.out
    assert "- 1 | 00000000000 |" not in captured.out
    assert "Caso hardened:" in captured.out
    assert "Caso normal:" in captured.out
    assert "hardened_index = index + 2^31" in captured.out
    assert "- seed = c55257c360c07c72029aebc1b53c05ed" in captured.out
    assert (
        "- mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        in captured.out
    )
    assert "- IL master = cbedc75b0d6412c85c79" in captured.out
    assert "- IR master = a3fa8c983223306d" in captured.out
    assert "- xprv master = xprv9s21ZrQH143K3" in captured.out
    assert "- xpub master = xpub661MyMwAqRbcG" in captured.out
    assert "-   " not in captured.out
    assert "Listo este paso. Continuamos al siguiente?" not in captured.out


def test_cli_wizard_summary_raw_appends_plain_block(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed-steps",
            "--wizard",
            "--entropy",
            "00000000000000000000000000000000",
            "--passphrase",
            "TREZOR",
            "--no-pause",
            "--no-color",
            "--summary-raw",
        ],
    )

    exit_code = run()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "seed=" in captured.out
    assert "il_master=" in captured.out
    assert "ir_master=" in captured.out
    assert "xprv_master=" in captured.out
    assert "xpub_master=" in captured.out
    assert "xprv_derived=" in captured.out
    assert "xpub_derived=" in captured.out
    assert "address=" in captured.out


def test_cli_colors_respect_no_color_and_default_mode(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    base_argv = [
        "seed-steps",
        "--wizard",
        "--entropy",
        "00000000000000000000000000000000",
        "--no-pause",
    ]

    monkeypatch.setattr(sys, "argv", base_argv)
    exit_code_color = run()
    output_color = capsys.readouterr().out

    assert exit_code_color == 0
    assert "\x1b[" in output_color

    monkeypatch.setattr(sys, "argv", base_argv + ["--no-color"])
    exit_code_no_color = run()
    output_no_color = capsys.readouterr().out

    assert exit_code_no_color == 0
    assert "\x1b[" not in output_no_color


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
