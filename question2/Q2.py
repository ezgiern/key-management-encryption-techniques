from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import ec
import os

#Function to generate symmetric keys using PBKDF2
def generate_symmetric_key(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000, # You can adjust the number of iterations based on your security requirements
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

# Generate random salt values
salt1 = os.urandom(16)
salt2 = os.urandom(16)

# Generate symmetric keys
K1 = generate_symmetric_key(b"password", salt1, 16)  # 128-bit key
K2 = generate_symmetric_key(b"password", salt2, 32)  # 256-bit key

print("Symmetric Key K1 (128-bit):", K1.hex())
print("Symmetric Key K2 (256-bit):", K2.hex())

#Encrypt K1 and K2 using RSA public key
rsa_public_key_bytes = open("public_key.pem", "rb").read()
rsa_public_key = serialization.load_pem_public_key(rsa_public_key_bytes, backend=default_backend())

cipher_rsa_K1 = rsa_public_key.encrypt(
    K1,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
cipher_rsa_K2 = rsa_public_key.encrypt(
    K2,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Encrypted Symmetric Key K1 with RSA:", cipher_rsa_K1.hex())
print("Encrypted Symmetric Key K2 with RSA:", cipher_rsa_K2.hex())

#Decrypt K1 and K2 using RSA private key
rsa_private_key_bytes = open("private_key.pem", "rb").read()
rsa_private_key = serialization.load_pem_private_key(rsa_private_key_bytes, password=None, backend=default_backend())

decipher_rsa_K1 = rsa_private_key.decrypt(
    cipher_rsa_K1,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
decipher_rsa_K2 = rsa_private_key.decrypt(
    cipher_rsa_K2,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Decrypted Symmetric Key K1 with RSA:", decipher_rsa_K1.hex())
print("Decrypted Symmetric Key K2 with RSA:", decipher_rsa_K2.hex())

#Generate symmetric key using Elliptic Curve Diffie-Hellman
ecdh_key1_private_bytes = open("private_key_kb.pem", "rb").read()
ecdh_key2_public_bytes = open("public_key_kc.pem", "rb").read()

ecdh_key1_private = serialization.load_pem_private_key(ecdh_key1_private_bytes, password=None, backend=default_backend())
ecdh_key2_public = serialization.load_pem_public_key(ecdh_key2_public_bytes, backend=default_backend())

shared_key = ecdh_key1_private.exchange(ec.ECDH(), ecdh_key2_public)

#Generate HMAC keys from shared key
hmac_key = shared_key[:32]  



#Generate symmetric key using Elliptic Curve Diffie-Hellman
ecdh_key3_private_bytes = open("private_key_kc.pem", "rb").read()
ecdh_key4_public_bytes = open("public_key_kb.pem", "rb").read()

ecdh_key3_private = serialization.load_pem_private_key(ecdh_key3_private_bytes, password=None, backend=default_backend())
ecdh_key4_public = serialization.load_pem_public_key(ecdh_key4_public_bytes, backend=default_backend())

shared_key2 = ecdh_key3_private.exchange(ec.ECDH(), ecdh_key4_public)

#Generate HMAC keys from shared key
hmac_key2 = shared_key[:32]  




print("HMAC Key (256-bit) generated using ECDH with Kc+ and Kb-:", hmac_key.hex())
print("HMAC Key (256-bit) generated using ECDH with Kc- and Kb+:", hmac_key2.hex())
print("Both keys are the same.") if hmac_key == hmac_key2 else print("Keys are different.")
