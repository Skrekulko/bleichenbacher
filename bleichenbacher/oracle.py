import re
from Crypto.Random import get_random_bytes
from bleichenbacher.rsa import RSA
from bleichenbacher.converter import int_to_hex, hex_to_int
from bleichenbacher.pkcs import encode, decode


class Oracle(RSA):
    """
    Oracle simulating a server for RSA based on RFC 8017.

    Keyword arguments:
    bits -- size of public modulus in bits
    e    -- RSA public exponent
    """

    def __init__(self, bits=2048, e=65537, simple_check=False) -> None:
        # Initialize RSA
        super().__init__(bits=bits, e=e)

        self.simple_check = simple_check

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Implementation of RSAES-PKCS1-v1_5 encryption operation from RFC 8017.

        Keyword arguments:
        plaintext -- message to encrypt
        """

        # Encoded Message (EM)
        encoded_message = encode(message=plaintext, n_size=self.parameters.size_in_bytes())

        # Encrypt The Encoded Message
        return int_to_hex(
            integer=super().encrypt(
                plaintext=hex_to_int(
                    hexadecimal=encoded_message,
                    byteorder="big"
                )
            ), byteorder="big"
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Implementation of RSAES-PKCS1-v1_5 decryption operation from RFC 8017.

        Keyword arguments:
        ciphertext -- ciphertext to decrypt
        """

        # Check Ciphertext Length
        if len(ciphertext) != self.parameters.size_in_bytes() or self.parameters.size_in_bytes() < 11:
            raise Exception("Wrong ciphertext length.")

        # Encoded Message
        encoded_message = b"\x00" + int_to_hex(
            integer=super().decrypt(
                ciphertext=hex_to_int(
                    hexadecimal=ciphertext,
                    byteorder="big"
                )
            ), byteorder="big"
        )

        # Simple PKCS Conformity Check
        if self.simple_check:
            if len(encoded_message) == self.parameters.size_in_bytes() and encoded_message[:2] == b"\x00\x02":
                return encoded_message
            else:
                raise Exception("Not PKCS conforming.")
        else:
            decode(message=encoded_message, n_size=self.parameters.size_in_bytes())
            return encoded_message
