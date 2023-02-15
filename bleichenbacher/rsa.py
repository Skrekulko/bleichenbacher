from Crypto.PublicKey.RSA import generate
from bleichenbacher.math import mod_pow


class RSA:
    """RSA implementation.

    Keyword arguments:
    bits -- size of the public modulus in bits
    e    -- RSA public exponent
    """

    def __init__(self, bits=2048, e=65537) -> None:
        # Generate RSA Parameters
        self.parameters = generate(bits=bits, e=e)

    def encrypt(self, plaintext: int) -> int:
        """Encrypts the plaintext using the public key.

        Keyword arguments:
        plaintext -- plaintext message represented by an integer
        """

        return mod_pow(
            b=plaintext,
            e=self.parameters.e,
            m=self.parameters.n
        )

    def decrypt(self, ciphertext: int) -> int:
        """Decrypts the ciphertext using private key.

        Keyword arguments:
        ciphertext -- ciphertext message represented by an integer
        """

        return mod_pow(
            b=ciphertext,
            e=self.parameters.d,
            m=self.parameters.n
        )
