import re
from bleichenbacher.pkcs import encode, decode


def test_encode() -> None:
    # Public Modulus Size (bytes)
    n_size = 32

    # Message
    message = b"encode me"

    # Encoded Message
    encoded_message = encode(message=message, n_size=n_size)

    # Parse The Encoded Message
    r = re.compile(b"(\x00\x02)(.+)\x00(.+)", re.DOTALL)
    m = r.match(encoded_message)

    assert m


def test_decode() -> None:
    # Public Modulus Size (bytes)
    n_size = 32

    # Message
    message = b"encode me"

    # Encoded Message
    encoded_message = b"\x00\x02\xf7\xeds\xa4=k\xfe^\x94\xae\xc19A\xd09\x07\xfb~\xa1\x03\x00encode me"

    # Decoded Message
    decoded_message = decode(message=encoded_message, n_size=n_size)

    assert decoded_message == message
