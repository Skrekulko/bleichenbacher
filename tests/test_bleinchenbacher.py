from datetime import datetime
from bleichenbacher.oracle import Oracle
from bleichenbacher.bleichenbacher import bleichenbacher_chosen_plaintext
from bleichenbacher.pkcs import decode


def test_bleichenbacher() -> None:
    # RSA Sizes
    rsa_sizes = [256, 512, 1024, 2048, 4096]

    # Check Difficulty (Simple, Advanced)
    check_types = [True, False]

    # Number Of Cycles
    n_cycles = 20

    # Test For Different RSA Sizes
    for rsa_size in rsa_sizes:
        # Test For Different Check Difficulty
        for check_type in check_types:
            # For 'n' Cycles
            for n in range(n_cycles):
                print(f"\nRSA-{rsa_size} | Simple PKCS Check ({check_type}) | Cycle {n + 1}")

                # RSA Oracle
                oracle = Oracle(bits=rsa_size, simple_check=check_type)

                # Message
                message = b"RSA" + bytes(str(rsa_size), "ascii")

                # Ciphertext
                ciphertext = oracle.encrypt(plaintext=message)

                # Run The Attack
                data = bleichenbacher_chosen_plaintext(oracle=oracle, ciphertext=ciphertext, conforming=True)

                assert message == decode(message=data['recovered_message'], n_size=oracle.parameters.size_in_bytes())

                # Create A New Test File
                file = open("test_results.txt", "a", encoding="utf-8")

                # Write The Results To File
                file.write(f"{datetime.now()}\n")
                file.write(f"\trsa_{rsa_size}:\n")
                file.write(f"\t\tsimple={check_type}\n")
                file.write(f"\t\ttime={data['time']}\n")
                file.write(f"\t\tcalls={data['calls']}\n")
                file.write(
                    f"\t\trecovered="
                    f"{decode(message=data['recovered_message'], n_size=oracle.parameters.size_in_bytes())}\n\n"
                )

                # Close The File
                file.close()
