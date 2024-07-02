from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import time


# Reading the file contents
with open("image5.png", "rb") as file:
    file_content = file.read()

# AES (128 bit key) encryption in CBC mode
def encrypt_aes128_cbc(data, key, iv):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_blocks = []
    for i in range(0, len(padded_data), algorithms.AES.block_size):
        block = padded_data[i:i + algorithms.AES.block_size]
        encrypted_blocks.append(encryptor.update(block))

    encrypted_blocks.append(encryptor.finalize())  # Finalize should only be called once
    return b"".join(encrypted_blocks)

# Key and IV creation
key_aes128 = b'\xc4\x08\x9a\x02\xf4\xd4s\x86\xea\xae\x85@\x8d\xc6\xcf\x80'
iv_aes128 = b'\x95#\xb8\xa0\x9e\x8e\xb9j\x9d\xdc\x8b\x89\x90T\x04\xfb'

# Performing the encryption process
start_time = time.time()
encrypted_data_aes128_cbc = encrypt_aes128_cbc(file_content, key_aes128, iv_aes128)
end_time = time.time()

# Calculating the time taken for encryption
elapsed_time_aes128_cbc = end_time - start_time

# Determining the name and path of the encrypted file
encrypted_file_path = "encrypted_image_aes128_cbc.png"

# Writing encrypted data to disk
with open(encrypted_file_path, "wb") as encrypted_file:
    encrypted_file.write(encrypted_data_aes128_cbc)

print("AES (128 bit key) encryption in CBC mode is complete.")
print("Elapsed time:", elapsed_time_aes128_cbc, "second.")
print("Encrypted file:", encrypted_file_path)
