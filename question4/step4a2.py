from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import time

def encrypt_aes256_cbc(data, key, iv):
    # PKCS7 padding application
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Creating Cipher and Encryptor for encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Don't encrypt on a block basis
    encrypted_blocks = []
    for i in range(0, len(padded_data), algorithms.AES.block_size):
        block = padded_data[i:i + algorithms.AES.block_size]
        encrypted_blocks.append(encryptor.update(block))

    encrypted_blocks.append(encryptor.finalize())  # Finalize should only be called once
    return b"".join(encrypted_blocks)

# Reading the file contents
with open("image5.png", "rb") as file:
    file_content = file.read()

# Key and IV creation (256 bit)
key_aes256 = os.urandom(32)
iv_aes256 = os.urandom(16)

# Performing encryption operation (256 bit key)
start_time = time.time()
encrypted_data_aes256_cbc = encrypt_aes256_cbc(file_content, key_aes256, iv_aes256)
end_time = time.time()

# Calculate the time taken for encryption (256 bit key)
elapsed_time_aes256_cbc = end_time - start_time

# Determining the name and path of the encrypted file
encrypted_file_path_aes256_cbc = "encrypted_image_aes256_cbc.png"

# Writing encrypted data to disk
with open(encrypted_file_path_aes256_cbc, "wb") as encrypted_file_aes256_cbc:
    encrypted_file_aes256_cbc.write(encrypted_data_aes256_cbc)

print("AES (256 bit key) encryption in CBC mode is complete.")
print("Elapsed time:", elapsed_time_aes256_cbc, "second.")
print("Encrypted file:", encrypted_file_path_aes256_cbc)
