# Key Management and Encryption Techniques

## Introduction
This project covers various aspects of information system security, including the generation and management of cryptographic keys, encryption and decryption, and message authentication. The project is implemented using Python and the `cryptography` library.

## Public-Private Key Generation
We generated an RSA key pair (1024 bits) and ECC-DH key pairs using the `cryptography` module in Python. The keys are stored securely and can be used for encryption, decryption, and digital signatures.

## Symmetric Key Generation
Symmetric keys are generated using Python and the `cryptography` library. The process involves creating keys, generating salt values, and using RSA for secure encryption and decryption.

## Digital Signature Generation and Verification
We generated RSA public and private keys to sign and verify digital signatures. The process includes:
1. Generating keys.
2. Calculating the hash of an image.
3. Verifying the digital signature.
4. Encoding the result in base64.

## AES Encryption
We implemented AES encryption and decryption in various modes:
- **CBC Mode with 128-bit Key**: Encryption and decryption with key size of 128 bits.
- **CBC Mode with 256-bit Key**: Encryption and decryption with key size of 256 bits.
- **CTR Mode with 256-bit Key**: Encryption and decryption with key size of 256 bits.

## Message Authentication Codes (MACs)
We generated two symmetric keys using PBKDF2-HMAC-SHA256 with random salts and specified key lengths. HMAC-SHA256 MACs were calculated for a sample text message. A new 256-bit key was derived using HMAC-SHA256, and the results were printed as hexadecimal strings.

## Execution
To run the project, ensure you have Python installed along with the `cryptography` library. Follow these steps:

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd <repository-directory>
    ```

2. Install the required Python packages:
    ```sh
    pip install cryptography
    ```

3. Run the Python scripts for each section:
    ```sh
    python generate_keys.py
    python generate_symmetric_keys.py
    python digital_signature.py
    python aes_encryption.py
    python mac_generation.py
    ```

## Conclusion
This project demonstrates the practical implementation of key generation, encryption, decryption, and message authentication in Python. It provides a foundation for understanding and applying cryptographic techniques in information system security.



