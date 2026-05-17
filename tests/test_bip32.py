from seed_steps.bip32 import (
    HARDENED_OFFSET,
    base58check_encode,
    derive_p2wpkh_address_from_node,
    derive_bip32_master_node,
    derive_bip32_node_from_master,
    derive_bip32_path_from_node,
    parse_bip32_path,
    serialize_bip84_extended_keys,
)
from seed_steps.seed import derive_bip39_seed


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


def test_parse_bip32_path_accepts_m_only() -> None:
    assert parse_bip32_path("m") == []


def test_parse_bip32_path_accepts_mixed_hardened_and_normal_levels() -> None:
    steps = parse_bip32_path("m/84'/0'/0'/0/0")
    assert len(steps) == 5
    assert steps[0].child_number == HARDENED_OFFSET + 84
    assert steps[1].child_number == HARDENED_OFFSET
    assert steps[2].child_number == HARDENED_OFFSET
    assert steps[3].child_number == 0
    assert steps[4].child_number == 0


def test_parse_bip32_path_rejects_invalid_inputs() -> None:
    invalid_cases = [
        "",
        " ",
        "n/0",
        "m//0",
        "m/0h",
        "m/0''",
        "m/2147483648",
    ]
    for invalid in invalid_cases:
        try:
            parse_bip32_path(invalid)
            assert False, f"Expected ValueError for: {invalid}"
        except ValueError as exc:
            assert "Ruta BIP32" in str(exc)


def test_bip32_path_vector_1_m_0h_matches_expected_xprv_xpub() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    master = derive_bip32_master_node(seed)
    root = derive_bip32_node_from_master(master)

    node = derive_bip32_path_from_node(root, "m/0'")
    assert node.depth == 1
    assert node.child_number == HARDENED_OFFSET
    assert node.xprv == (
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL"
        "5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    )
    assert node.xpub == (
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwB"
        "ZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
    )


def test_bip32_path_vector_1_deep_route_matches_expected_xprv_xpub() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    master = derive_bip32_master_node(seed)
    root = derive_bip32_node_from_master(master)

    node = derive_bip32_path_from_node(root, "m/0'/1/2'/2/1000000000")
    assert node.depth == 5
    assert node.child_number == 1000000000
    assert node.xprv == (
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScG"
        "pWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
    )
    assert node.xpub == (
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJ"
        "S2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    )


def test_p2wpkh_address_mainnet_known_vector() -> None:
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed = derive_bip39_seed(mnemonic, "")
    master = derive_bip32_master_node(seed)
    root = derive_bip32_node_from_master(master)
    node = derive_bip32_path_from_node(root, "m/84'/0'/0'/0/0")

    p2wpkh = derive_p2wpkh_address_from_node(node, "mainnet")
    assert p2wpkh.hrp == "bc"
    assert p2wpkh.compressed_pubkey.hex() == (
        "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
    )
    assert p2wpkh.address == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_p2wpkh_address_testnet_known_vector() -> None:
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed = derive_bip39_seed(mnemonic, "")
    master = derive_bip32_master_node(seed)
    root = derive_bip32_node_from_master(master)
    node = derive_bip32_path_from_node(root, "m/84'/1'/0'/0/0")

    p2wpkh = derive_p2wpkh_address_from_node(node, "testnet")
    assert p2wpkh.hrp == "tb"
    assert p2wpkh.compressed_pubkey.hex() == (
        "02e7ab2537b5d49e970309aae06e9e49f36ce1c9febbd44ec8e0d1cca0b4f9c319"
    )
    assert p2wpkh.address == "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"


def test_serialize_bip84_extended_keys_uses_expected_prefixes_by_network() -> None:
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed = derive_bip39_seed(mnemonic, "")
    master = derive_bip32_master_node(seed)
    root = derive_bip32_node_from_master(master)

    mainnet_node = derive_bip32_path_from_node(root, "m/84'/0'/0'/0/0")
    zprv, zpub = serialize_bip84_extended_keys(mainnet_node, "mainnet")
    assert zprv.startswith("zprv")
    assert zpub.startswith("zpub")

    testnet_node = derive_bip32_path_from_node(root, "m/84'/1'/0'/0/0")
    vprv, vpub = serialize_bip84_extended_keys(testnet_node, "testnet")
    assert vprv.startswith("vprv")
    assert vpub.startswith("vpub")
