def mod_pow(b: int, e: int, m: int) -> int:
    """
    Binary modular exponentiation.

    Keyword arguments:
    b -- base
    e -- exponent
    m -- modulus
    """

    x = 1

    while e > 0:
        b, e, x = (
            b * b % m,
            e // 2,
            b * x % m if e % 2 else x
        )

    return x


def floor(a: int, b: int) -> int:
    """
    Floor division for large integers.

    Keyword arguments:
    a -- nominator
    b -- denominator
    """

    return a // b


def ceil(a: int, b: int) -> int:
    """
    Ceil division for large integers.

    Keyword arguments:
    a -- nominator
    b -- denominator
    """

    return a // b + (a % b > 0)
