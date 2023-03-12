from collections import namedtuple
from timeit import default_timer as timer
from datetime import timedelta
from random import randint
from bleichenbacher.oracle import Oracle
from bleichenbacher.converter import int_to_hex, hex_to_int
from bleichenbacher.math import mod_pow, floor, ceil

Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])


def bleichenbacher_chosen_plaintext(oracle: Oracle, ciphertext: bytes, conforming=True) ->\
        dict[str, bytes, timedelta, int]:
    """
    Implementation of Bleichenbacher's chosen ciphertext attack.

    Keyword arguments:
    oracle     -- oracle used to test the PKCS conformity
    ciphertext -- ciphertext to decipher
    conforming -- flag indicating the conformity of the input ciphertext
    """

    # Start Recording The Time
    start_time = timer()

    # Start Recording Calls To The Oracle
    calls_to_oracle = 0

    # Oracle's Parameters
    n = oracle.parameters.n
    n_size = oracle.parameters.size_in_bytes()
    e = oracle.parameters.e

    # Initial Parameters
    c = hex_to_int(hexadecimal=ciphertext, byteorder="big")
    B = 2 ** (8 * (n_size - 2))
    intervals = [Interval(2 * B, 3 * B - 1)]

    # Step 1: Blinding (Only If Ciphertext Is Not PKCS Conforming)
    if not conforming:
        s, calls_to_oracle = step_1(oracle=oracle, n=n, e=e, c=c, calls_to_oracle=calls_to_oracle)
    else:
        s = 1

    # Step 2.a: Starting The Search
    s, calls_to_oracle = step_2a(oracle=oracle, n=n, e=e, c=c, l=ceil(n, 3 * B), calls_to_oracle=calls_to_oracle)

    # Step 3: Narrowing The Set Of Solutions
    intervals = step_3(n=n, b_range=B, s=s, intervals=intervals)

    while True:
        # Step 2.b: Searching With More Than One Interval Left
        if len(intervals) >= 2:
            s, calls_to_oracle = step_2a(oracle=oracle, n=n, e=e, c=c, l=s + 1, calls_to_oracle=calls_to_oracle)
        # Step 2.c: Searching With One Interval Left AND Step 4: Computing The Solution
        elif len(intervals) == 1:
            a, b = intervals[0]

            # Step 4: Computing The Solution
            if a == b:
                # Stop Recording The Time
                end_time = timer()

                return dict(
                    recovered_message=b"\x00" + int_to_hex(integer=a % n, byteorder="big"),
                    time=timedelta(seconds=end_time - start_time),
                    calls=calls_to_oracle
                )

            # Step 2.c: Searching With One Interval Left
            s, calls_to_oracle = step_2c(
                oracle=oracle, n=n, e=e, c=c, a=a, b=b, prev_s=s, b_range=B, calls_to_oracle=calls_to_oracle
            )

        # Step 3: Narrowing The Set Of Solutions
        intervals = step_3(n=n, b_range=B, s=s, intervals=intervals)


def step_1(oracle: Oracle, n: int, e: int, c: int, calls_to_oracle: int) -> [int, int]:
    """
    Step 1: Blinding.

    Keyword arguments:
    oracle -- oracle used to test the PKCS conformity
    n      -- RSA public modulus
    e      -- RSA public exponent
    c      -- ciphertext to decipher
    """

    while True:
        # Generate Random Number 's'
        s = randint(0, n - 1)

        # Compute Ciphertext 'c_unknown'
        c_unknown = (c * mod_pow(b=s, e=e, m=n)) % n

        # Check For PKCS Conformity
        try:
            calls_to_oracle += 1
            oracle.decrypt(ciphertext=int_to_hex(integer=c_unknown, byteorder="big"))
            return s, calls_to_oracle
        except (Exception,):
            pass


def step_2a(oracle: Oracle, n: int, e: int, c: int, l: int, calls_to_oracle: int) -> [int, int]:
    """
    Step 2.a: Starting the search.

    Keyword arguments:
    oracle -- oracle used to test the PKCS conformity
    n      -- RSA public modulus
    e      -- RSA public exponent
    c      -- ciphertext to decipher
    l      -- lower bound
    """

    # Lower Bound
    s = l

    while True:
        # Compute Ciphertext 'c_unknown'
        c_unknown = (c * mod_pow(b=s, e=e, m=n)) % n

        # Check For PKCS Conformity
        try:
            calls_to_oracle += 1
            oracle.decrypt(ciphertext=int_to_hex(integer=c_unknown, byteorder="big"))
            return s, calls_to_oracle
        except (Exception,):
            s += 1


def step_2c(
        oracle: Oracle, n: int, e: int, c: int, a: int, b: int, prev_s: int, b_range: int, calls_to_oracle: int
) -> [int, int]:
    """
    Step 2.c: Searching with one interval left.

    Keyword arguments:
    oracle  -- oracle used to test the PKCS conformity
    n       -- RSA public modulus
    e       -- RSA public exponent
    c       -- ciphertext to decipher
    a       -- parameter
    b       -- parameter
    prev_s  -- previous parameter
    b_range -- basic range constant
    """

    ri = ceil(2 * (b * prev_s - 2 * b_range), n)

    while True:
        si_lower = ceil(2 * b_range + ri * n, b)
        si_upper = ceil(3 * b_range + ri * n, a)

        for si in range(si_lower, si_upper):
            # Compute Ciphertext 'c_unknown'
            c_unknown = (c * mod_pow(b=si, e=e, m=n)) % n

            # Check For PKCS Conformity
            try:
                calls_to_oracle += 1
                oracle.decrypt(ciphertext=int_to_hex(integer=c_unknown, byteorder="big"))
                return si, calls_to_oracle
            except (Exception,):
                pass

        # Increment 'ri' By One
        ri += 1


def step_3(n: int, b_range: int, s: int, intervals: [Interval]) -> [Interval]:
    """
    Step 3: Narrowing the set of solutions.

    Keyword arguments:
    oracle    -- oracle used to test the PKCS conformity
    b_range   -- basic range constant
    s         -- parameter
    intervals -- intervals of possible solutions
    """

    intervals_new = []

    for a, b in intervals:
        r_lower = ceil(a * s - 3 * b_range + 1, n)
        r_upper = ceil(b * s - 2 * b_range, n)

        for r in range(r_lower, r_upper):
            lower_bound = max(a, ceil(2 * b_range + r * n, s))
            upper_bound = min(b, floor(3 * b_range - 1 + r * n, s))

            interval = Interval(lower_bound, upper_bound)

            intervals_new = insert_interval(intervals_new, interval)

    intervals.clear()

    return intervals_new


def insert_interval(intervals: [Interval], interval: Interval) -> [Interval]:
    """
    Inserts a new interval into already existing intervals of solutions.

    Keyword arguments:
    intervals -- intervals of possible solutions
    interval  -- interval to insert
    """

    for i, (a, b) in enumerate(intervals):
        # Construct The Larger Interval If There Are Any Overlaps
        if b >= interval.lower_bound and a <= interval.upper_bound:
            lower_bound = interval.lower_bound
            upper_bound = interval.upper_bound

            intervals[i] = Interval(lower_bound, upper_bound)

            return intervals

    # Insert The New Interval If There Are No Overlaps
    intervals.append(interval)

    return intervals
