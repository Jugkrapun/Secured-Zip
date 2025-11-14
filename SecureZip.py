import zipfile
import os
import AES as AES
import Encrpyt_Decrypt as EN_DE

# -------------------------------------------------
# ZIP / UNZIP
# -------------------------------------------------

def zip_directory(directory_path, output_zip):
    """
    Zip a directory and encrypt the resulting zip file
    """
    with zipfile.ZipFile(output_zip, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, directory_path)
                zipf.write(file_path, arcname=arcname)

    # Encrypt the zip file after it's created
    encrypted_path = output_zip + ".enc"
    file_key = EN_DE.encrypt_file(output_zip, encrypted_path)
    # Save file_key
    with open(output_zip + ".key", 'wb') as key_file:
        key_file.write(file_key)
    print(f"Encrypted zip saved as: {encrypted_path}")

    # (optional) Remove original zip file
    os.remove(output_zip)

def unzip_file(zip_path, extract_to):
    """
    Decrypt and unzip a file
    """
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(extract_to)
    print(f"Files extracted to {extract_to}")

# -------------------------------------------------
# MAIN MENU FLOW
# -------------------------------------------------

if __name__ == "__main__":
    print("Choose an option:")
    print("1. Zip + Encrypt")
    print("2. Decrypt + Unzip")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        # ZIP + ENCRYPT
        folder = input("Enter folder path to zip: ").strip()
        output_zip = input("Enter output zip file name (e.g., output.zip): ").strip()
        zip_directory(folder, output_zip)

    elif choice == "2":
        # DECRYPT + UNZIP
        encrypted_file = input("Enter encrypted file path (e.g., output.zip.enc): ").strip()
        restored_path = input("Enter name for extract path: ").strip()
        #load file_key
        with open(encrypted_file.replace('.enc', '.key'), 'rb') as key_file:
            file_key = key_file.read()
        EN_DE.decrypt_file(encrypted_file, restored_path, file_key)

    else:
        print("Invalid choice. Please enter 1 or 2.")