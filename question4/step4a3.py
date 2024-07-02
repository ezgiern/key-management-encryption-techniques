from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import time

def encrypt_aes256_ctr(data, key, nonce):
    # Creating a Cipher for encryption
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Performing the encryption process
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data

# Reading the file contents
with open("image5.png", "rb") as file:
    file_content = file.read()

# Key and nonce generation (256 bit)
key_aes256_ctr = os.urandom(32)
nonce_aes256_ctr = os.urandom(16)

# Performing encryption operation (256 bit key)
start_time = time.time()
encrypted_data_aes256_ctr = encrypt_aes256_ctr(file_content, key_aes256_ctr, nonce_aes256_ctr)
end_time = time.time()

# Calculate the time taken for encryption (256 bit key)
elapsed_time_aes256_ctr = end_time - start_time

# Determining the name and path of the encrypted file
encrypted_file_path_aes256_ctr = "encrypted_image_aes256_ctr.png"

# Writing encrypted data to disk
with open(encrypted_file_path_aes256_ctr, "wb") as encrypted_file_aes256_ctr:
    encrypted_file_aes256_ctr.write(encrypted_data_aes256_ctr)

print("AES (256 bit key) encryption in CTR mode is complete.")
print("Elapsed time:", elapsed_time_aes256_ctr, "second.")
print("Encrypted file:", encrypted_file_path_aes256_ctr)

