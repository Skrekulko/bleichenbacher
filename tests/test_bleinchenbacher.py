from bleichenbacher.oracle import Oracle
from bleichenbacher.bleichenbacher import bleichenbacher_chosen_plaintext
from bleichenbacher.pkcs import decode


def test_bleichenbacher() -> None:
    # RSA Sizes
    #rsa_sizes = [256, 512, 1024, 2048, 4096]
    rsa_sizes = [256]

    # Check Difficulty (Simple, Advanced)
    #check_types = [True, False]
    check_types = [True]

    # Number Of Cycles
    #n_cycles = 20
    n_cycles = 5

    # Test For Different RSA Sizes
    for rsa_size in rsa_sizes:
        # Test For Different Check Difficulty
        for check_type in check_types:
            # For 'n' Cycles
            for _ in range(n_cycles):
                # RSA Oracle
                oracle = Oracle(bits=rsa_size, simple_check=check_type)

                # Message
                message = b"RSA" + bytes(str(rsa_size), "ascii")

                # Ciphertext
                ciphertext = oracle.encrypt(plaintext=message)

                # Run The Attack
                data = bleichenbacher_chosen_plaintext(oracle=oracle, ciphertext=ciphertext, conforming=True)

                with open("test_results.txt", "a", encoding="utf-8") as file:
                    file.write(f"rsa_{rsa_size}:\n")
                    file.write(f"\tsimple={check_type}\n")
                    file.write(f"\ttime={data['time']}\n")
                    file.write(f"\tcalls={data['calls']}\n")
                    file.write(f"\toriginal={decode(message=data['recovered_message'], n_size=oracle.parameters.size_in_bytes())}\n\n")

                    file.close()

                assert message == decode(message=data['recovered_message'], n_size=oracle.parameters.size_in_bytes())
