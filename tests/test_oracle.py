from bleichenbacher.oracle import Oracle
from bleichenbacher.rsa import RSA
from bleichenbacher.converter import int_to_hex, hex_to_int
from bleichenbacher.pkcs import decode


def test_oracle_encrypt() -> None:
    # RSA Oracle
    oracle = Oracle(bits=1024)

    # Plaintext
    plaintext = b"encrypt me"

    # Ciphertext
    ciphertext = oracle.encrypt(plaintext=plaintext)

    assert decode(
        message=oracle.decrypt(ciphertext=ciphertext),
        n_size=oracle.parameters.size_in_bytes()
    ) == plaintext


def test_oracle_decrypt() -> None:
    # RSA Oracle
    oracle = Oracle(bits=1024)

    # Plaintext
    plaintext = b"decrypt me"

    # Ciphertext
    ciphertext = oracle.encrypt(plaintext=plaintext)

    assert decode(
        message=oracle.decrypt(ciphertext=ciphertext),
        n_size=oracle.parameters.size_in_bytes()
    ) == plaintext
