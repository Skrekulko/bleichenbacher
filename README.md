# Bleichenbacher's Chosen Ciphertext Attack Against Protocols Based on the RSA Encryption Standard PKCS #1

## Introduction

### Project Decription

In the Cryptography course, the task is to carry out an independent project focused on the field of cryptanalysis of ciphertext in any programming language. The main task is to describe the basic types of cryptanalytic attacks on cryptosystems, to define cryptosystems susceptible to chosen-ciphertext attack, to implement chosen-ciphertext attack on PKCS #1 standard, to determine its computational and time complexity and to implement measures preventing the execution of the attack.

### Objectives Of The Project

The main goal of this project is to implement the original Bleichenbacher attack with ciphertext option on the RSA encryption standard PKCS #1 and then to analyze its computational and time requirements and implement measures to prevent the execution of this attack. Another objective is to learn and define the basic types of cryptosystem attacks, and to define cryptosystems susceptible to the ciphertext-option attack.

## Theory

### Cryptographic Systems And Cryptanalytic Attacks

Cryptosystems are an important part of modern communication. They are used to protect sensitive information by providing a secure means of communication between parties. Cryptography deals with the creation and use of cryptosystems, which include cryptographic algorithms.

A cryptographic algorithm is a mathematical function used to encrypt and decrypt data. Encryption transforms plain text into cipher text that cannot be understood without the appropriate key. Decryption, on the other hand, is the process of transforming cipher text back into plain text using an appropriate key.

There are two basic types of cryptosystems: symmetric and asymmetric. Symmetric cryptosystems use the same key for both encryption and decryption, while asymmetric cryptosystems use two different keys, one for encryption and one for decryption.

Symmetric encryption algorithms are usually faster than asymmetric algorithms and are used to encrypt large amounts of data. Examples of symmetric encryption algorithms include the Advanced Encryption Standard (AES) and the Data Encryption Standard (DES).

Asymmetric encryption algorithms are used for key exchange and digital signatures that require a public and private key. The public key is shared with others while the private key is kept secret. An example of an asymmetric encryption algorithm is RSA.

Although cryptosystems are designed to be secure, they are not completely invulnerable to attacks. Cryptanalytic attacks are a type of attack that aims to break cryptosystems by exploiting weaknesses in their design or implementation. Cryptanalytic attacks can be divided into two types: passive attacks and active attacks.

Passive attacks are those in which the attacker intercepts and analyses encrypted messages without modifying or altering them. The goal of these attacks is usually to obtain information about the plaintext of the message or the key used for encryption.

Active attacks, on the other hand, are those in which the attacker actively seeks to modify or alter encrypted messages. Active attacks can be further divided into three subcategories: known plaintext attacks, chosen plaintext attacks and chosen ciphertext attacks.

A known plaintext attack is an active attack in which the attacker has access to both the plaintext and ciphertext of a message. This type of attack can be used to derive the key used for encryption.

A chosen plaintext attack is an active attack in which the attacker can choose the plaintext that is encrypted. The goal of this attack is to obtain information about the key used for encryption.

A chosen-ciphertext attack is an active attack in which the attacker has access to a decryption oracle that can decrypt the chosen ciphertext. This type of attack can be used to obtain information about a secret key even if the key is securely generated and stored.

In addition to active attacks, cryptosystems are also vulnerable to side-channel attacks, in which an attacker obtains information about the secret key by analyzing physical properties of the system, such as power consumption or electromagnetic radiation. Side-channel attacks pose a problem for systems that rely on physical devices such as smart cards or hardware security modules.

Another type of attack to which cryptosystems are vulnerable is the algebraic attack. In this attack, an attacker uses the algebraic structure of the cryptosystem to derive a secret key.

### Cryptosystems Vulnerable To Chosen Ciphertext Attacks

Cryptosystems vulnerable to chosen ciphertext attacks are those that allow an attacker to obtain information about the secret key by choosing a ciphertext and obtaining its decryption. These attacks exploit weaknesses in the design or implementation of the cryptosystem and can be used to gain unauthorised access to sensitive data, compromise systems or steal information.

One of the main reasons why a cryptosystem may be vulnerable to a chosen ciphertext attack is the use of a weak or insecure encryption algorithm. For example, some encryption algorithms use predictable patterns or weak keys that can be easily identified and exploited by an attacker. In addition, some cryptosystems use insufficient key size or a poorly designed key generation process, which can make it easy for an attacker to guess or derive a secret key.

Another reason why a cryptosystem may be vulnerable to a chosen ciphertext attack is poor implementation practices. For example, some cryptosystems may not properly handle errors or exceptions that occur during the encryption or decryption process. This can lead to an attacker being able to obtain information about the secret key by sending specially crafted ciphertexts and analysing the resulting error messages.

Some cryptosystems may be vulnerable to chosen ciphertext attacks due to flaws in the design of their cryptographic protocols. For example, some protocols may use predictable patterns or rely on the same key for multiple encryption operations, which may make it easier for an attacker to derive the secret key. In addition, some protocols may not properly verify the authenticity or integrity of encrypted messages, which may allow an attacker to modify ciphertexts and obtain information about the secret key.

### PKCS #1: RSAES-PKCS1-v1_5

RSAES-PKCS1-v1_5 is a widely used encryption standard based on the RSA cryptosystem. It is defined in PKCS #1 v2.1 and is commonly used in many applications, including secure email, secure file transfer, and SSL/TLS.

The RSAES-PKCS1-v1_5 standard defines how to securely encrypt messages using RSA. The encryption process involves four steps: key generation, message completion, encryption, and decryption.

Key generation involves selecting two large prime numbers and calculating the modulus and associated value. The modulus and associated value are used to generate a public key that can be disclosed and a private key that must be kept secret.
A crucial step in RSA encryption is the completion of a message to prevent certain types of attacks. RSAES-PKCS1-v1_5 uses a specific padding scheme known as PKCS #1 v1.5 padding. This padding scheme involves adding a fixed header and footer to the plaintext message, as well as random additional bytes that pad the message to the size of the module. This padding scheme ensures that each message is unique, even if the plaintext is the same, and makes it more difficult for attackers to perform a chosen ciphertext attack.

Encryption involves increasing the message's plaintext to a power of the modulo public key. This produces a ciphertext that can be sent securely over an insecure channel.

Decryption is the opposite process to encryption and involves incrementing the ciphertext to a power of the modulo modulo private key. From the decrypted ciphertext, the original open message text can be recovered.

The RSAES-PKCS1-v1_5 cipher has several advantages, including simplicity and widespread use. It is also highly interoperable, which means that different implementations can work together seamlessly. However, it is important to note that the standard is vulnerable to some attacks, such as the Bleichenbacher attack. Therefore, it is recommended to use more modern encryption standards such as RSA-OAEP or ECC when possible.

### Bleichenbacher Attack With Ciphertext Selection

The Bleichenbacher attack, also known as the RSA-CRT attack, is an attack on the chosen ciphertext (CCA) of the RSAES-PKCS1-v1_5 encryption standard. This attack was discovered in 1998 by Daniel Bleichenbacher and is still considered a serious threat to RSA implementations using this standard.

Bleichenbacher's attack exploits vulnerabilities in the way RSAES-PKCS1-v1_5 handles padding errors during decryption. The attack requires an oracle that can be used to check that a given ciphertext is correctly aligned. The oracle is a black box that receives the ciphertext and prints a message indicating whether or not the ciphertext was correctly decrypted.

The attack proceeds as follows:

1. The attacker selects ciphertext C and presents it to the oracle for decryption.

2.	If the ciphertext is correctly formatted, the oracle returns a success message.

3.	If the ciphertext is not correctly formatted, the oracle returns a "failure" message.

4. The attacker then modifies the ciphertext by adding a small value and resends it to the oracle.

5.	If the modified ciphertext is correctly formatted, the oracle returns a success message.

6.	If the modified ciphertext is still not correctly formatted, the oracle returns a "failure" message.

By repeating this process and using the binary search algorithm, an attacker can recover the open text. The attack relies on the fact that the PKCS #1 v1.5 formatting scheme reveals information about the decrypted message when decryption fails due to incorrect formatting. An attacker can use this information to reduce the range of possible plaintexts and retrieve the original message.

To defend against the Bleichenbacher attack, RSA implementations can use more secure formatting schemes such as RSA-OAEP, which provides stronger security guarantees against chosen ciphertext attacks. Alternatively, countermeasures such as limiting the number of decryption attempts or randomly padding the plaintext can also be used to make the attack more difficult.

## Diagram

The left side of the diagram illustrates the different steps involved in Bleichenbacher's attack, which allows an attacker to decrypt encrypted messages by repeatedly sending carefully crafted ciphertexts and analyzing the server's responses. The right side of this diagram provides an overview of the entire program that implements Bleichenbacher's attack.

This diagram serves as a visual aid to help understand the flow and interactions of Bleichenbacher's attack, providing a clear representation of how the different steps and components are connected in the attack process.

![diagram](diagram.svg)

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

### Running (Only) The Bleichenbacher's Attack

To run only the test for the Bleichenbacher's attack, run the pytest command:

```bash
# Run pytest With The Verbosity Flag
(venv) $ pytest -vv tests/test_bleinchenbacher.py

tests/test_bleinchenbacher.py::test_bleichenbacher PASSED                                                           [100%]
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

## Conclusion

From the analyzed data, it was found that as the size of RSA increased and also with the use of more sophisticated format control (strict), the time required and the number of accesses to the oracle to retrieve the original message increased significantly. An element of chance was detected from the analysis, where on some attempts the time and number of accesses differed significantly from the average values. As the time and computational requirements were expected to be higher, data collection was carried out on a virtual machine provided by Cyber Arena.

As a security measure to prevent the Bleichenbacher attack, a simple and a strict version of the PKCS-based format checking were tried, and it was found that the strict version increased the computational and time requirements for the attacker, which reduces the attractiveness of the retrieved messages, since the computational complexity of retrieving a given message represents a certain amount of time for the attacker, after which the messages may already be obsolete.

In conclusion, the main goal of the semester project has been accomplished. The original Bleichenbacher attack with ciphertext option on the RSA encryption standard PKCS #1 has been successfully implemented and thoroughly analyzed in terms of computational and time requirements. Measures have also been implemented to effectively prevent the execution of this attack, ensuring the security of the RSA encryption scheme. Additionally, a deep understanding of the basic types of cryptosystem attacks has been gained, and cryptosystems susceptible to the ciphertext-option attack have been identified. This project has provided valuable insights into the vulnerabilities and defenses of modern cryptographic systems, contributing to the knowledge and skills in the field of information security. Overall, the objectives of the project have been fully achieved, meeting all the defined goals.

## References

[1] BLEICHENBACHER, Daniel. Chosen ciphertext attacks against protocols based on the RSA encryption standard PKCS# 1. Advances in Cryptology—CRYPTO'98: 18th Annual International Cryptology Conference Santa Barbara, California, USA August 23–27, 1998. Proceedings 18. Springer Berlin Heidelberg, 1998, 1-12.

[2] CRAMER, Ronald a Victor SHOUP. Design and analysis of practical public-key encryption schemes secure against adaptive chosen ciphertext attack. SIAM Journal on Computing, 2003, 33.1., 167-226.

[3] BÖCK, H., J. SOMOROVSKY a C. YOUNG. Return Of Bleichenbacher's Oracle Threat (ROBOT). In 27th USENIX Security Symposium (USENIX Security 18), 2018, 817-849.

[4] RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2 [online]. NOVEMBER 2016 [cit. 2023-03-23]. Available at: https://www.rfc-editor.org/info/rfc8017

## License
Everything in this repository is released under the terms of the MIT License. For more information, please see the file "LICENSE".
