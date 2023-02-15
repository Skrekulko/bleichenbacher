from bleichenbacher.oracle import Oracle
from bleichenbacher.bleichenbacher import bleichenbacher_chosen_plaintext
from bleichenbacher.pkcs import decode


def test_bleichenbacher() -> None:
    # RSA Oracle
    oracle = Oracle(bits=256)

    # Message
    message = b"RSA256"

    # Ciphertext
    ciphertext = oracle.encrypt(plaintext=message)

    # Recovered Message
    recovered_message = bleichenbacher_chosen_plaintext(oracle=oracle, ciphertext=ciphertext)

    assert message == decode(message=recovered_message, n_size=oracle.parameters.size_in_bytes())
