from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Generate an Elliptic Curve Diffie-Hellman (ECDH) key pair using the SECP256R1 curve
private_key_kb = ec.generate_private_key(ec.SECP256R1())
public_key_kb = private_key_kb.public_key()

private_key_kc = ec.generate_private_key(ec.SECP256R1())
public_key_kc = private_key_kc.public_key()

# Print the private and public keys of the key pairs
print("KB+ Private Key:", private_key_kb.private_numbers().private_value)
print("KB+ Public Key:", public_key_kb.public_numbers().x, public_key_kb.public_numbers().y)

print("KC+ Private Key:", private_key_kc.private_numbers().private_value)
print("KC+ Public Key:", public_key_kc.public_numbers().x, public_key_kc.public_numbers().y)

# Write the public key to a file  in PEM format
with open('public_key_kb.pem', 'wb') as f:
    f.write(public_key_kb.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Write the public key to a file  in PEM format
with open('public_key_kc.pem', 'wb') as f:
    f.write(public_key_kc.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

with open('private_key_kc.pem', 'wb') as f:
    f.write(private_key_kc.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open('private_key_kb.pem', 'wb') as f:
    f.write(private_key_kb.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))