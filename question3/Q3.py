from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import base64

#RSA private key
private_key_bytes = open("private_key.pem", "rb").read()
private_key = load_pem_private_key(private_key_bytes, password=None, backend=default_backend())

#RSA public key
public_key_bytes = open("public_key.pem", "rb").read()
public_key = load_pem_public_key(public_key_bytes, backend=default_backend())

#Reading image file
image_file_path = "resim.png"         
with open(image_file_path, "rb") as f:
    image_data = f.read()

#Calculating hash of the image data
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(image_data)
hashed_message = digest.finalize()

#Encrypting hashed message 
signature = private_key.sign(
    hashed_message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

#Verifying digital signature
try:
    public_key.verify(
        signature,
        hashed_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Digital signature verified successfully.")
except:
    print("Failed to verify digital signature.")

#Encoding hashed message and signature as base64 for printing
hashed_message_b64 = base64.b64encode(hashed_message).decode('utf-8')
signature_b64 = base64.b64encode(signature).decode('utf-8')

#Printing hashed message and digital signature
print("SHA256 Hash of the image (H(m)): ", hashed_message_b64)
print("Digital Signature (encrypted hash): ", signature_b64)
