from seed_steps.seed import derive_bip39_seed


def test_bip39_seed_vector_abandon_about_trezor() -> None:
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed_hex = derive_bip39_seed(mnemonic, "TREZOR").hex()
    assert seed_hex == (
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    )


def test_bip39_seed_vector_legal_winner_trezor() -> None:
    mnemonic = (
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    )
    seed_hex = derive_bip39_seed(mnemonic, "TREZOR").hex()
    assert seed_hex == (
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
        "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
    )


def test_bip39_seed_uses_nfkd_normalization() -> None:
    mnemonic_composed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    mnemonic_decomposed = mnemonic_composed
    passphrase_composed = "páss"
    passphrase_decomposed = "pa\u0301ss"

    seed_1 = derive_bip39_seed(mnemonic_composed, passphrase_composed)
    seed_2 = derive_bip39_seed(mnemonic_decomposed, passphrase_decomposed)

    assert seed_1 == seed_2
