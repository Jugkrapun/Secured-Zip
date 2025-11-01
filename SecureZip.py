import zipfile
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympadding

import RSA_Management as RSAM
import AES as AES
import Encrpyt_Decrypt as EN_DE

# -------------------------------------------------
# ZIP / UNZIP
# -------------------------------------------------

def zip_directory(directory_path, output_zip, public_key_path="public_key.pem"):
    # load public key
    public_key = RSAM.load_public_key(public_key_path)
    
    if public_key is None:
        print(f"Error: Could not load the public key. Skipping encryption.")
        return
    
    with zipfile.ZipFile(output_zip, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, directory_path)
                zipf.write(file_path, arcname=arcname)
    encrypted_path = output_zip + ".enc"
    EN_DE.encrypt_file_rsa(output_zip, encrypted_path)

    print(f"Encrypted zip saved as: {encrypted_path}")

    # (optional) remove original zip
    os.remove(output_zip)


def unzip_file(zip_path, extract_to, private_key_path="private_key.pem"):
    # load private key
    private_key = RSAM.load_public_key(private_key_path)
    
    if private_key is None:
        print(f"Error: Could not load the private key. Can not decryption.")
        return

    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(extract_to)
    print(f"Files extracted to {extract_to}")

# -------------------------------------------------
# MAIN MENU FLOW
# -------------------------------------------------

if __name__ == "__main__":
    print("Choose an option:")
    print("0. Generate RSA keypair (run once first)")
    print("1. Zip + Encrypt")
    print("2. Decrypt + Unzip")
    choice = input("Enter 0, 1 or 2: ").strip()

    if choice == "0":
        # create private_key.pem / public_key.pem
        RSAM.generate_rsa_keypair()

    elif choice == "1":
        # ZIP + ENCRYPT
        folder = input("Enter folder path to zip: ").strip()
        output_zip = input("Enter output zip file name (e.g., output.zip): ").strip()
        zip_directory(folder, output_zip)

    elif choice == "2":
        # DECRYPT + UNZIP
        encrypted_file = input("Enter encrypted file path (e.g., output.zip.enc): ").strip()
        restored_path = input("Enter name for extract path: ").strip()
        EN_DE.decrypt_file_rsa(encrypted_file, restored_path)

    else:
        print("Invalid choice. Please enter 0, 1, or 2.")