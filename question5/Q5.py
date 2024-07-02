from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac, hashes
import os

# Generating message writing code using symmetric keys HMAC-SHA256
def generate_message_authentication_code(message, key):
    hmac_code = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac_code.update(message.encode('utf-8'))
    return hmac_code.finalize()

# Used the symmetric keys you created previously
K1 = b'hmac_key'
K2 = b'hmac_key2'

# Example text message
text_message = "This is a sample text message for HMAC-SHA256."

# Generating HMAC-SHA256 verification code with K1
mac_K1 = generate_message_authentication_code(text_message, K1)
print("Message Authentication Code with K1 (HMAC-SHA256):", mac_K1.hex())

# Generating HMAC-SHA256 verification code with K2
mac_K2 = generate_message_authentication_code(text_message, K2)
print("Message Authentication Code with K2 (HMAC-SHA256):", mac_K2.hex())

# Generating a new 256-bit key using HMAC-SHA256
new_key_hmac = hmac.HMAC(K2, hashes.SHA256(), backend=default_backend())
new_key_hmac.update(mac_K1)
new_generated_key = new_key_hmac.finalize()

# Display the new key
print("New 256-bit key generated using HMAC-SHA256 with K2:", new_generated_key.hex())
