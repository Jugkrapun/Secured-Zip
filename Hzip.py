import zipfile
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def zip_directory(directory_path, output_zip):
    with zipfile.ZipFile(output_zip, 'w') as zipf:
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, directory_path)
                zipf.write(file_path, arcname=arcname)
    print(f"Directory zipped into {output_zip}")

def unzip_file(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(extract_to)
    print(f"Files extracted to {extract_to}")

def derive_key(password: str, salt: bytes) -> bytes:
    # PBKDF2-HMAC-SHA256 that has adjustable iterations
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # 32 bytes = 256-bit key
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file_aes(input_path, output_path, password):
    # 1) Generate 16 salt randomly
    salt = os.urandom(16)

    # 2) Create key from password + salt
    key = derive_key(password, salt)

    # 3) Create 16 bytes IV randomly (AES block size)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 4) Read raw data
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # 5) Pad inside a 16 bytes block
    padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes block
    padded = padder.update(plaintext) + padder.finalize()

    # 6) Encrpytion
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # 7) Write the result: [salt][iv][ciphertext]
    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print("Encrypted file written to:", output_path)
    print("Store this salt (hex) so you can decrypt:", salt.hex())


def decrypt_file_aes(encrypted_path, output_path, password):
    with open(encrypted_path, 'rb') as f:
        data = f.read()

    # Pull salt, iv, ciphertext back
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    # Create new key from password + salt
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Write original zip
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print("Decrypted zip written to:", output_path)

if __name__ == "__main__":
    print("Choose an option:")
    print("1. Zip + Encrypt")
    print("2. Decrypt + Unzip")
    choice = input("Enter 1 or 2: ")

    if choice == "1":
        # --- ZIP + ENCRYPT ---
        folder = input("Enter folder path to zip: ")
        output_zip = input("Enter output zip file name (e.g., output.zip): ")

        # zip the folder
        zip_directory(folder, output_zip)
        print(f"Zipped folder into {output_zip}")

        # ask for password to encrypt
        password = input("Enter password to encrypt this zip: ")

        encrypted_path = output_zip + ".enc"
        encrypt_file_aes(output_zip, encrypted_path, password)
        print(f"Encrypted zip saved as: {encrypted_path}")

    elif choice == "2":
        # --- DECRYPT + UNZIP ---
        encrypted_file = input("Enter encrypted file path (e.g., output.zip.enc): ")
        restored_zip = input("Enter name for decrypted zip (e.g., restored.zip): ")

        # ask for password to decrypt
        password = input("Enter password to decrypt: ")

        # decrypt .enc -> .zip
        decrypt_file_aes(encrypted_file, restored_zip, password)
        print(f"Decrypted zip saved as: {restored_zip}")

        # now unzip
        extract_to = input("Enter folder to extract to: ")
        unzip_file(restored_zip, extract_to)
        print(f"Decrypted zip extracted to: {extract_to}")

    else:
        print("Invalid choice. Please enter 1 or 2.")