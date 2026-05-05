from seed_steps.bip32 import base58check_encode, derive_bip32_master_node


def test_bip32_master_vector_1_matches_expected_xprv_xpub() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    master = derive_bip32_master_node(seed)

    assert master.master_private_key.hex() == (
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    )
    assert master.chain_code.hex() == (
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    )
    assert master.xprv == (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
        "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    )
    assert master.xpub == (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29E"
        "SFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    )


def test_bip32_master_fails_when_il_is_zero(monkeypatch) -> None:
    import seed_steps.bip32 as bip32

    class _DummyHmac:
        @staticmethod
        def digest() -> bytes:
            return b"\x00" * 64

    monkeypatch.setattr(bip32.hmac, "new", lambda *_args, **_kwargs: _DummyHmac())

    try:
        bip32.derive_bip32_master_node(b"seed")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "fuera de rango secp256k1" in str(exc)


def test_base58check_encode_known_vector() -> None:
    payload = bytes.fromhex("00010966776006953d5567439e5e39f86a0d273bee")
    assert base58check_encode(payload) == "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
