# Bleichenbacher's Chosen Ciphertext Attack Against Protocols Based on the RSA Encryption Standard PKCS #1

## What It Is

[Bleichenbacher's CCA](https://link.springer.com/chapter/10.1007/BFb0055716) (Chosen Ciphertext Attack) attack is a type of cryptographic attack that targets the RSA-based encryption scheme known as [PKCS#1 v1.5](https://www.rfc-editor.org/rfc/rfc8017). The attack takes advantage of a weakness in the padding scheme used by PKCS#1 v1.5, allowing an attacker to decrypt ciphertexts without knowing the private key.

To carry out the attack, the attacker first sends carefully crafted ciphertexts to the target system, which decrypts them and returns an error message if the padding is invalid. By analyzing the error messages, the attacker can learn information about the structure of the ciphertext and use it to gradually deduce the original plaintext.

Bleichenbacher's CCA attack was first discovered by Swiss cryptographer Daniel Bleichenbacher in 1998, and since then, several variations of the attack have been developed. The original attack required tens of thousands of queries to decrypt a single ciphertext, but later variations have been able to accomplish the same task with fewer queries.

To prevent this attack, it is recommended to use a more secure padding scheme such as OAEP (Optimal Asymmetric Encryption Padding). Additionally, careful implementation of PKCS#1 v1.5 can also mitigate the risk of this attack. For example, the error message returned by the decryption function can be made constant-time, so that attackers cannot use it to gain information about the plaintext.

## Structure

```
    .
    ├── bleichenbacher
    │   ├── bleichenbacher.py
    │   ├── converter.py
    │   ├── math.py
    │   ├── oracle.py
    │   ├── pkcs.py
    │   └── rsa.py
    ├── tests
    │   ├── test_bleichenbacher.py
    │   ├── test_converter.py
    │   ├── test_math.py
    │   ├── test_oracle.py
    │   ├── test_pkcs.py
    │   └── test_rsa.py
    ├── LICENSE
    ├── README.md
    └── requirements.txt
```

### Modules

As seen above, in the repository structure, there are six main modules:

- **bleichenbacher** - Actual implementation of the Bleichenbacher's attack.

- **converter** - Functions to convert integer to hexadecimal bytes object.

- **math** - Binary modular exponentiation function, and floor and ceil functions for large integers.

- **oracle** - Code for simulating a server (oracle) with RSA and PKCS #1 standard.

- **pkcs** - Implementation of the PKCS #1 standard.

- **rsa** - Implementation of RSA.

### Tests

Test for each corresponding module has a "**test\_**" prefix added to it, e.g. test for the *bleichenbacher.py* module is **test\_bleichenbacher.py**.

## How To Run

### Virtual Environment

A Python virtual environment is being used for running the tests, with a small guide on how to set it up here:

#### Installation And Activation

```shell
# Install virtualenv If Not Already Installed
$ pip install virtualenv

# Create The Virtual Environment
$ virtualenv -p python3 venv

# Activate The Virtual Environment
$ source venv/bin/activate
```

#### Deactivation

```shell
# Deactivate The Virtual Environment After Being Done Running This Project
(venv) $ deactivate
```

### Dependencies

The dependencies must be installed for everything to work properly by running the following command:

```python
# Install The Dependencies For The Virtual Environment
(venv) $ pip install -r requirements.txt
```

### Use Smaller RSA

To use smaller RSA than 1024 bits, a very minor changes must be made to the Crypto library. A few lines of code that are listed below must be ***commented out***. Be aware that this *technique* has weaknesses and will only allow you to use RSA with a minimum of 256 bits.

The Crypto module will most likely be located in *bleichenbacher\venv\lib\python3.10\site-packages*.

#### Crypto\Public\RSA.py

```python
#if bits < 1024:
    #raise ValueError("RSA modulus length must be >= 1024")
```

#### Crypto\Math\Primality.py

```python
#if exact_bits < 160:
    #raise ValueError("Prime number is not big enough.")
```

### Tests

#### Running The Tests

To run the tests for the solutions, run the pytest command:

```bash
# Run pytest With The Verbosity Flag
(venv) $ pytest -vv

tests/test_bleinchenbacher.py::test_bleichenbacher PASSED                                                           [ 10%]
tests/test_converter.py::test_integer_to_bytes PASSED                                                               [ 20%]
tests/test_converter.py::test_bytes_to_integer PASSED                                                               [ 30%]
tests/test_math.py::test_math_mod_pow PASSED                                                                        [ 40%]
tests/test_oracle.py::test_oracle_encrypt PASSED                                                                    [ 50%]
tests/test_oracle.py::test_oracle_decrypt PASSED                                                                    [ 60%]
tests/test_pkcs.py::test_encode PASSED                                                                              [ 70%]
tests/test_pkcs.py::test_decode PASSED                                                                              [ 80%]
tests/test_rsa.py::test_rsa_encrypt PASSED                                                                          [ 90%]
tests/test_rsa.py::test_rsa_decrypt PASSED                                                                          [100%]
```

#### Configuring The Bleichenbacher's Test

The configuration options for the test that runs the Bleichenbacher's implementation includes: different RSA key sizes, a simple or advanced PKCS #1 compliance check, and the number of cycles for each attack.

##### RSA Sizes

Due to the limitations of the Crypto library from PyCryptodome, the minimal required size for RSA is 256. As usual, the bigger the RSA size, the more it takes to crack it, so don't expect to break RSA-4096 in a few seconds.

```python
# RSA Sizes
rsa_sizes = [256, 512, 1024, 2048, 4096]
```

##### PKCS #1 Compliance Check

Various PKCS #1 conformance check implementations lead to varying times for the attack to break the ciphertext, since some potential candidates for the plaintext can pass the check even if their encoding is not correct. The simple check only looks at the encoded message's size and the first two bytes (**0x00 || 0x02**). The more advanced one verifies everything in accordance with the previously mentioned RFC.

```python
# PKCS Conformity Check (Simple, Advanced)
conformity_checks = [True, False]
```

##### Number Of Cycles

How many times the attack with the current settings should be repeated is indicated by the number of cycles.

```python
# Number Of Cycles
n_cycles = 20
```

## License
Everything in this repository is released under the terms of the MIT License. For more information, please see the file "LICENSE".
