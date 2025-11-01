import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
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
    if not os.path.exists(public_key_path):
        print(f"Public key file '{public_key_path}' not found. Please ensure the file exists.")
        return None
    with open(public_key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def load_private_key(private_key_path="private_key.pem"):
    if not os.path.exists(private_key_path):
        print(f"Private key file '{private_key_path}' not found. Please ensure the file exists.")
        return None
    with open(private_key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())