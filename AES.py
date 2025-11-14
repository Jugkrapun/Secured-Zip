import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_encrypt_cbc(plaintext_bytes: bytes, key: bytes):
    """
    Encrypt with AES-256-CBC
    Returns iv and ciphertext
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
    Decrypt AES-256-CBC + remove PKCS7 padding
    Returns plaintext bytes
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext
