from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Decryption function
def decrypt_aes256_ctr(encrypted_data, key, nonce):
    # Creating Cipher and Decryptor
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()

    # Performing the decryption process
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

# Determining the name and path of the encrypted file
encrypted_file_path_aes256_ctr = "encrypted_image_aes256_ctr.png"

# Reading the encrypted file
with open(encrypted_file_path_aes256_ctr, "rb") as encrypted_file_aes256_ctr:
    encrypted_data_aes256_ctr = encrypted_file_aes256_ctr.read()

# Key and IV creation (256 bit)
key_aes256_ctr = os.urandom(32)
nonce_aes256_ctr = os.urandom(16)

# Performing the decryption process
decrypted_data_aes256_ctr = decrypt_aes256_ctr(encrypted_data_aes256_ctr, key_aes256_ctr, nonce_aes256_ctr)

# Determining the name and path of the solved file
decrypted_file_path_aes256_ctr = "decrypted_image_aes256_ctr.png"

# Write the decrypted data to disk
with open(decrypted_file_path_aes256_ctr, "wb") as decrypted_file_aes256_ctr:
    decrypted_file_aes256_ctr.write(decrypted_data_aes256_ctr)

print("The encrypted file was decoded in AES (256 bit key) CBC mode and the decoded file was stored on disk.")
print("Decrypted file:", decrypted_file_path_aes256_ctr)

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