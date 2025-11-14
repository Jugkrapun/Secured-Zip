import os
import shutil
import AES as AES
import SecureZip as zip

# -------------------------------------------------
# ENCRYPT / DECRYPT USING AES
# -------------------------------------------------

def encrypt_file(input_path, output_path):
    """
    Encrypt a file using AES and save the encrypted content with IV
    """
    file_key = os.urandom(32)  # 256-bit AES key

    # Read original data
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # AES encrypt
    iv, ciphertext = AES.aes_encrypt_cbc(plaintext, file_key)

    # Write output: store IV and ciphertext
    with open(output_path, 'wb') as f:
        f.write(iv)                           # 16 bytes IV
        f.write(ciphertext)                   # bulk encrypted data

    return file_key  # Return the AES key for decryption


def decrypt_file(encrypted_path, extract_path, file_key):
    """
    Decrypt a file using AES and unzip the extracted data
    """
    with open(encrypted_path, 'rb') as f:
        blob = f.read()

    # Extract IV and ciphertext from the encrypted file
    iv = blob[:16]  # First 16 bytes are the IV
    ciphertext = blob[16:]  # Rest is the ciphertext

    # AES decryption
    plaintext = AES.aes_decrypt_cbc(iv, ciphertext, file_key)

    # Write the plaintext to a zip file
    with open(extract_path + '.zip', 'wb') as f:
        f.write(plaintext)

    # Clear terminal folder if exists
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)

    # Unzip the extracted file
    zip.unzip_file(extract_path + '.zip', extract_path)

    # (optional) Remove restored zip file
    os.remove(extract_path + '.zip')