from bleichenbacher.rsa import RSA
from bleichenbacher.converter import int_to_hex, hex_to_int


def test_rsa_encrypt() -> None:
    # RSA
    rsa = RSA(bits=1024)

    # Plaintext (int)
    plaintext = hex_to_int(hexadecimal=b"encrypt me", byteorder="big")

    # Ciphertext (int)
    ciphertext = rsa.encrypt(plaintext=plaintext)

    assert rsa.encrypt(plaintext=plaintext) == ciphertext


def test_rsa_decrypt() -> None:
    # RSA
    rsa = RSA(bits=1024)

    # Plaintext (int)
    plaintext = hex_to_int(hexadecimal=b"decrypt me", byteorder="big")

    # Ciphertext (int)
    ciphertext = rsa.encrypt(plaintext=plaintext)

    assert rsa.decrypt(ciphertext=ciphertext) == plaintext

