from seed_steps.bech32 import bech32_decode, bech32_encode, convertbits


def test_convertbits_roundtrip_8_to_5_and_back() -> None:
    payload = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    five_bit = convertbits(payload, 8, 5, pad=True)
    recovered = bytes(convertbits(five_bit, 5, 8, pad=False))
    assert recovered == payload


def test_bech32_encode_decode_known_p2wpkh_vector() -> None:
    hrp = "bc"
    witness_program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    data = [0] + convertbits(witness_program, 8, 5, pad=True)
    address = bech32_encode(hrp, data)

    assert address == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

    decoded_hrp, decoded_data = bech32_decode(address)
    assert decoded_hrp == hrp
    assert decoded_data[0] == 0
    decoded_program = bytes(convertbits(decoded_data[1:], 5, 8, pad=False))
    assert decoded_program == witness_program


def test_bech32_decode_rejects_mixed_case() -> None:
    try:
        bech32_decode("bC1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "mezcla mayusculas" in str(exc)
