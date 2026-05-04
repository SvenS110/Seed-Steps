from pathlib import Path

from seed_steps.bip39 import build_bip39_breakdown, load_wordlist


def test_zero_entropy_vector_128_bits() -> None:
    wordlist = load_wordlist(Path("data/english.txt"))
    entropy = bytes.fromhex("00000000000000000000000000000000")

    breakdown = build_bip39_breakdown(entropy, wordlist)

    assert breakdown.checksum_bits == "0011"
    assert breakdown.mnemonic == (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )


def test_wordlist_shape_and_known_edges() -> None:
    wordlist = load_wordlist(Path("data/english.txt"))
    assert len(wordlist) == 2048
    assert wordlist[0] == "abandon"
    assert wordlist[2047] == "zoo"


def test_blocks_and_indices_are_valid() -> None:
    wordlist = load_wordlist(Path("data/english.txt"))
    entropy = bytes.fromhex("00000000000000000000000000000000")

    breakdown = build_bip39_breakdown(entropy, wordlist)

    assert all(len(block) == 11 for block in breakdown.bit_blocks)
    assert all(0 <= step.index <= 2047 for step in breakdown.steps)
