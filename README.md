# Bleichenbacher's Chosen Ciphertext Attack Against Protocols Based on the RSA Encryption Standard PKCS #1

 TODO: theory

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

Users who want to use RSA in sizes less than 1024 bits must make very minor changes to the Crypto module. A few lines of code that are listed below must be commented out. Be aware that this *technique* has weaknesses and will only allow you to use RSA with a minimum of 256 bits.

#### RSA.py

```python
#if bits < 1024:
    #raise ValueError("RSA modulus length must be >= 1024")
```

#### Primality.py

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

Due to the limitations of the Crypto module from PyCryptodome, the minimal required size for RSA is 256. As usual, the bigger the RSA size, the more it takes to crack it, so don't expect to break RSA-4096 in a few seconds.

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
