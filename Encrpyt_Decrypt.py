import os
import struct
import shutil
import RSA_Management as RSAM
import AES as AES
import SecureZip as zip
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympadding

# -------------------------------------------------
# ENCRYPT / DECRYPT USING RSA ENVELOPE
# -------------------------------------------------

def encrypt_file_rsa(input_path, output_path, public_key_path="public_key.pem"):
    # load public key
    public_key = RSAM.load_public_key(public_key_path)
    if public_key is None:
        print("Error: Could not load the public key. Exiting encryption process.")
        return

    # random AES key
    file_key = os.urandom(32)  # 256-bit AES key

    # read original data
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # AES encrypt
    iv, ciphertext = AES.aes_encrypt_cbc(plaintext, file_key)

    # encrypt file_key with RSA public key
    encrypted_file_key = public_key.encrypt(
        file_key,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # prepare to write output: keep encrypted_file_key 2 bytes (big-endian unsigned short)
    key_len = len(encrypted_file_key)
    if key_len > 65535:
        raise ValueError("encrypted_file_key too large to store in 2 bytes length header")

    with open(output_path, 'wb') as f:
        # [ key_len ][ encrypted_file_key ][ iv ][ ciphertext ]
        f.write(struct.pack(">H", key_len))   # 2 bytes
        f.write(encrypted_file_key)           # RSA-wrapped AES key
        f.write(iv)                           # 16 bytes IV
        f.write(ciphertext)                   # bulk encrypted data

def decrypt_file_rsa(encrypted_path, extract_path, private_key_path="private_key.pem"):
    private_key = RSAM.load_private_key(private_key_path)
    if private_key is None:
        print("Error: Could not load the public key. Exiting encryption process.")
        return

    with open(encrypted_path, 'rb') as f:
        blob = f.read()

    # read how long of key which wraped by RSA
    if len(blob) < 2:
        raise ValueError("Invalid encrypted file (too short)")

    key_len = struct.unpack(">H", blob[0:2])[0]

    # cut encrypted_file_key
    start_key = 2
    end_key = 2 + key_len
    encrypted_file_key = blob[start_key:end_key]

    # next iv 16 bytes
    start_iv = end_key
    end_iv = start_iv + 16
    iv = blob[start_iv:end_iv]

    #ciphertext
    ciphertext = blob[end_iv:]

    # use private key to produce file_key
    file_key = private_key.decrypt(
        encrypted_file_key,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # take off AES
    plaintext = AES.aes_decrypt_cbc(iv, ciphertext, file_key)

    # write zip
    with open(extract_path + '.zip', 'wb') as f:
        f.write(plaintext)

    # clear terminal folder
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)

    zip.unzip_file(extract_path + '.zip', extract_path)

    # (optional) remove restored_zip
    os.remove(extract_path + '.zip')