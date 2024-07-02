from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Generate an RSA key pair with a 1024-bit key size and public exponent 65537
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024
)
public_key = private_key.public_key()

# Write the private key to a file named 'private_key.pem' in PEM format without encryption
with open('private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Write the public key to a file named 'public_key.pem' in PEM format
with open('public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
