from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import hashlib

# Decryption function
def decrypt_aes128_cbc(encrypted_data, key, iv):
    # Creating Cipher and Decryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Performing the decryption process
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

# Determining the name and path of the encrypted file
encrypted_file_path_aes128_cbc = "encrypted_image_aes128_cbc.png"

# Reading the encrypted file
with open(encrypted_file_path_aes128_cbc, "rb") as encrypted_file_aes128_cbc:
    encrypted_data_aes128_cbc = encrypted_file_aes128_cbc.read()

# Determining the key and IV values (these values must be the values used during encryption)
key_aes128 = b'\xc4\x08\x9a\x02\xf4\xd4s\x86\xea\xae\x85@\x8d\xc6\xcf\x80'
iv_aes128 = b'\x95#\xb8\xa0\x9e\x8e\xb9j\x9d\xdc\x8b\x89\x90T\x04\xfe'

# Performing the decryption process
decrypted_data_aes128_cbc = decrypt_aes128_cbc(encrypted_data_aes128_cbc, key_aes128, iv_aes128)

# Determining the name and path of the solved file
decrypted_file_path_aes128_cbc = "decrypted_image_aes128_cbc.png"

# Write the decrypted data to disk
with open(decrypted_file_path_aes128_cbc, "wb") as decrypted_file_aes128_cbc:
    decrypted_file_aes128_cbc.write(decrypted_data_aes128_cbc)

print("The encrypted file was decoded in AES (128 bit key) CBC mode and the decoded file was stored on disk.")
print("Decrypted file:", decrypted_file_path_aes128_cbc)

def compare_files_hex(file_path1, file_path2):
    with open(file_path1, "rb") as file1, open(file_path2, "rb") as file2:
        content1 = file1.read()
        content2 = file2.read()
        hex_content1 = content1.hex()
        hex_content2 = content2.hex()
        
        for i in range(len(hex_content1)):
            if hex_content1[i] != hex_content2[i]:
                print(f"Hex offset {i}: {hex_content1[i]} vs {hex_content2[i]}")
                break
        else:
            print("The files match.")

compare_files_hex("image5.png", "decrypted_image_aes128_cbc.png")
