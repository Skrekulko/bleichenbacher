import re
from Crypto.Random import get_random_bytes


def encode(message: bytes, n_size: int) -> bytes:
    """
    Implementation of EME-PKCS1-v1_5 encoding from RFC 8017.

    Keyword arguments:
    message -- message to encode
    n_size  -- size of public modulus in bits
    """

    # Message Length
    message_length = len(message)

    # Check Message Length
    if message_length > n_size - 11:
        raise Exception("Wrong message length.")

    # Check Padding String Length And Null Byte
    padding_string_length = n_size - message_length - 3
    if not padding_string_length >= 8:
        raise Exception("Wrong padding string length.")

    # Padding String (PS)
    while True:
        padding_string = get_random_bytes(padding_string_length)

        # Check Padding String For Null Byte
        if b"\x00" not in padding_string:
            break

    # Encoded Message (EM)
    encoded_message = b"\x00\x02" + padding_string + b"\x00" + message

    return encoded_message


def decode(message: bytes, n_size: int) -> bytes:
    """
    Implementation of EME-PKCS1-v1_5 decoding from RFC 8017.

    Keyword arguments:
    message -- message to encode
    n_size  -- size of public modulus in bits
    """

    # Check Encoded Message Length
    if len(message) != n_size:
        raise Exception("Wrong encoded message length.")

    # Parse The Encoded Message
    r = re.compile(b"(\x00\x02)(.+)\x00(.+)", re.DOTALL)
    m = r.match(message)

    # No Match At All
    if not m:
        raise Exception("No match found.")

    # Check The Groups
    if m.group(1) != b"\x00\x02" or len(m.group(2)) < 8:
        raise Exception("Groups did not match.")

    return m.group(3)
