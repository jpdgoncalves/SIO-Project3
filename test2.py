
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

SUPPORTED_HASHES = {
    hashes.SHA256.name : hashes.SHA256,
    hashes.SHA512.name : hashes.SHA512
}

def buildDigestFunction(algorithm_name = "SHA512",backend = default_backend()):
    if not algorithm_name in SUPPORTED_HASHES:
        raise ValueError(f"{algorithm_name} is not supported")

    algorithm = SUPPORTED_HASHES[algorithm_name]()

    return hashes.Hash(algorithm,backend)

def generateAssymetricKey():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_bytes,public_bytes

def getPrivateKeyFromBytes(private_bytes: bytes):
    return serialization.load_pem_private_key(
        data=private_bytes,
        password=None,
        backend=default_backend()
    )

def getPublicKeyFromBytes(public_bytes: bytes):
    return serialization.load_pem_public_key(
        data=public_bytes,
        backend=default_backend()
    )

'''
Key exchange algorithms come into play in shared_key message signature algorithms such as HMAC or CMAC.
Because of this is advisable to rotate the keys time to time.
Since there is nothing about supporting multiple assymetric algorithms we will use RSA by default.
'''