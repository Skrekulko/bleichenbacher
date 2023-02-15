import sys


def int_to_hex(integer: int, byteorder=None) -> bytes:
    """
    Converts an integer to bytes.

    Keyword arguments:
    integer   -- integer to convert
    byteorder -- byte order of the output bytes
    """

    integer_len = (max(integer.bit_length(), 1) + 7) // 8

    return integer.to_bytes(integer_len, byteorder=(sys.byteorder if byteorder is None else byteorder))


def hex_to_int(hexadecimal: bytes, byteorder=None) -> int:
    """
    Converts bytes to an integer.

    Keyword arguments:
    hexadecimal -- bytes to correct
    byteorder   -- byte order of the output bytes
    """

    return int.from_bytes(bytes=hexadecimal, byteorder=(sys.byteorder if byteorder is None else byteorder))
