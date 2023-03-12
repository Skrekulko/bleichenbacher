import csv
from time import strftime
from bleichenbacher.oracle import Oracle
from bleichenbacher.bleichenbacher import bleichenbacher_chosen_plaintext
from bleichenbacher.pkcs import decode


def test_bleichenbacher() -> None:
    # RSA Sizes
    rsa_sizes = [256, 512, 1024, 2048, 4096]

    # PKCS Conformity Check (Simple, Advanced)
    conformity_checks = [True, False]

    # Number Of Cycles
    n_cycles = 20

    # Create A New CSV Test File
    file = open(f"tests/test_{strftime('%Y_%m_%d-%H_%M_%S')}.csv", "w", encoding="utf-8")

    # Create A CSV Handle
    writer = csv.writer(file)

    # Add CSV File Header
    writer.writerow(["rsa_size", "simple", "time", "calls", "recovered"])

    # Test For Different RSA Sizes
    for rsa_size in rsa_sizes:
        # Test For Different Check Difficulty
        for conformity_check in conformity_checks:
            # For 'n' Cycles
            for n in range(n_cycles):
                print(f"\nRSA-{rsa_size} | Simple PKCS Check ({conformity_check}) | Cycle {n + 1}")

                # RSA Oracle
                oracle = Oracle(bits=rsa_size, simple_check=conformity_check)

                # Message
                message = b"RSA" + bytes(str(rsa_size), "ascii")

                # Ciphertext
                ciphertext = oracle.encrypt(plaintext=message)

                # Run The Attack
                data = bleichenbacher_chosen_plaintext(oracle=oracle, ciphertext=ciphertext, conforming=True)

                assert message == decode(message=data['recovered_message'], n_size=oracle.parameters.size_in_bytes())

                # Write The Results To The CSV File
                writer.writerow([rsa_size, conformity_check, data['time'], data['calls'], data['recovered_message']])

    # Close The File
    file.close()
