import zipfile
import os
import struct
import shutil

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asympadding
from cryptography.hazmat.primitives import serialization


# -------------------------------------------------
# RSA KEY MANAGEMENT
# -------------------------------------------------

def generate_rsa_keypair(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    """
    Create a pair of RSA bite at a time and then save it in  .pem file
    firsttime call before real usage
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("RSA keypair generated:")
    print(" - Private key:", private_key_path)
    print(" - Public  key:", public_key_path)


def load_public_key(public_key_path="public_key.pem"):
    with open(public_key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def load_private_key(private_key_path="private_key.pem"):
    with open(private_key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


# -------------------------------------------------
# AES HELPERS (CBC + PKCS7)
# -------------------------------------------------

def aes_encrypt_cbc(plaintext_bytes: bytes, key: bytes):
    """
    เข้ารหัสข้อมูลจริงด้วย AES-256-CBC
    return iv, ciphertext
    """
    iv = os.urandom(16)  # 16-byte IV
    padder = padding.PKCS7(128).padder()  # block size 128 bits = 16 bytes
    padded = padder.update(plaintext_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv, ciphertext


def aes_decrypt_cbc(iv: bytes, ciphertext: bytes, key: bytes):
    """
    ถอดรหัส AES-256-CBC + เอา PKCS7 padding ออก
    return plaintext_bytes
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


# -------------------------------------------------
# ZIP / UNZIP
# -------------------------------------------------

def zip_directory(directory_path, output_zip):
    """
    สร้างไฟล์ .zip จากโฟลเดอร์ จากนั้นเข้ารหัส zip อัตโนมัติด้วย RSA envelope
    """
    with zipfile.ZipFile(output_zip, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, directory_path)
                zipf.write(file_path, arcname=arcname)
    print(f"Directory zipped into {output_zip}")

    encrypted_path = output_zip + ".enc"
    encrypt_file_rsa(output_zip, encrypted_path)

    print(f"Encrypted zip saved as: {encrypted_path}")

    # (optional) ลบไฟล์ zip เดิมเพื่อไม่ทิ้ง plaintext
    # os.remove(output_zip)


def unzip_file(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(extract_to)
    print(f"Files extracted to {extract_to}")


# -------------------------------------------------
# ENCRYPT / DECRYPT USING RSA ENVELOPE
# -------------------------------------------------

def encrypt_file_rsa(input_path, output_path, public_key_path="public_key.pem"):
    """
    เข้ารหัสไฟล์ zip แบบไม่ต้องใช้ password จาก user
    Steps:
      1) สุ่ม file_key (AES-256) สำหรับไฟล์นี้ไฟล์เดียว
      2) เข้ารหัสเนื้อหาไฟล์ด้วย AES-CBC(file_key)
      3) เข้ารหัส file_key ด้วย RSA public key (OAEP)
      4) เขียนผลลัพธ์รวมเป็นไฟล์เดียว:
         [2 bytes len_key][encrypted_file_key][iv(16)][ciphertext...]
    """

    # โหลด public key
    public_key = load_public_key(public_key_path)

    # สุ่มกุญแจ AES สำหรับไฟล์นี้
    file_key = os.urandom(32)  # 256-bit AES key

    # อ่านข้อมูลต้นฉบับ
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # AES encrypt
    iv, ciphertext = aes_encrypt_cbc(plaintext, file_key)

    # เข้ารหัส file_key ด้วย RSA public key
    encrypted_file_key = public_key.encrypt(
        file_key,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # เตรียมเขียนออก: เราจะเก็บขนาด encrypted_file_key 2 bytes (big-endian unsigned short)
    key_len = len(encrypted_file_key)
    if key_len > 65535:
        raise ValueError("encrypted_file_key too large to store in 2 bytes length header")

    with open(output_path, 'wb') as f:
        # [ key_len ][ encrypted_file_key ][ iv ][ ciphertext ]
        f.write(struct.pack(">H", key_len))   # 2 bytes
        f.write(encrypted_file_key)           # RSA-wrapped AES key
        f.write(iv)                           # 16 bytes IV
        f.write(ciphertext)                   # bulk encrypted data

    print("Encrypted file written to:", output_path)
    print(" - per-file AES key is protected by RSA public key")

def decrypt_file_rsa(encrypted_path, extract_path, private_key_path="private_key.pem"):
    """
    ถอดรหัสไฟล์ .enc ที่ถูกสร้างจาก encrypt_file_rsa
    Steps:
      1) อ่าน header เอา encrypted_file_key / iv / ciphertext
      2) ใช้ private key ถอด encrypted_file_key -> file_key เดิม
      3) ใช้ file_key+iv ถอด AES-CBC
      4) เขียน zip ออกมาเป็นไฟล์ปลายทาง (.zip)
    """

    private_key = load_private_key(private_key_path)

    with open(encrypted_path, 'rb') as f:
        blob = f.read()

    # อ่านความยาวกุญแจที่ถูก RSA wrap
    if len(blob) < 2:
        raise ValueError("Invalid encrypted file (too short)")

    key_len = struct.unpack(">H", blob[0:2])[0]

    # ตัด encrypted_file_key
    start_key = 2
    end_key = 2 + key_len
    encrypted_file_key = blob[start_key:end_key]

    # iv 16 bytes ถัดไป
    start_iv = end_key
    end_iv = start_iv + 16
    iv = blob[start_iv:end_iv]

    # ที่เหลือคือ ciphertext
    ciphertext = blob[end_iv:]

    # ใช้ private key คลาย file_key ออกมา
    file_key = private_key.decrypt(
        encrypted_file_key,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # ถอด AES
    plaintext = aes_decrypt_cbc(iv, ciphertext, file_key)

    # เขียน zip ออกมา
    with open(extract_path + '.zip', 'wb') as f:
        f.write(plaintext)

    print("Decrypted zip written to:", extract_path)

    # extract_to = input("Enter folder to extract to: ").strip()

    # ล้างโฟลเดอร์ปลายทางถ้ามีอยู่ เพื่อความสะอาด
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)

    unzip_file(extract_path + '.zip', extract_path)
    print(f"Decrypted zip extracted to: {extract_path}")

    # (optional) ลบ restored_zip เพื่อไม่เหลือ zip plaintext
    os.remove(extract_path + '.zip')


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
        # สร้าง private_key.pem / public_key.pem หนึ่งครั้ง
        generate_rsa_keypair()

    elif choice == "1":
        # ZIP + ENCRYPT
        folder = input("Enter folder path to zip: ").strip()
        output_zip = input("Enter output zip file name (e.g., output.zip): ").strip()

        zip_directory(folder, output_zip)
        # หมายเหตุ: zip_directory() จะเรียก encrypt_file_rsa() ให้อัตโนมัติแล้ว
        # และจะสร้างไฟล์ output.zip.enc

    elif choice == "2":
        # DECRYPT + UNZIP
        encrypted_file = input("Enter encrypted file path (e.g., output.zip.enc): ").strip()
        restored_path = input("Enter name for extract path: ").strip()

        # ถอดรหัส .enc -> .zip
        decrypt_file_rsa(encrypted_file, restored_path)
        print(f"Decrypted zip saved as: {restored_path}")

    else:
        print("Invalid choice. Please enter 0, 1, or 2.")
