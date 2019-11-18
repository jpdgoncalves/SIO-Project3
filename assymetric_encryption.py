
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding,PKCS1v15
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

SUPPORTED_HASHES = {
    hashes.SHA256.name : hashes.SHA256,
    hashes.SHA512.name : hashes.SHA512
}

def buildDigestFunction(algorithm_name = "sha512",backend = default_backend()):
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

def getPublicBytesFromKey(public_key: rsa.RSAPublicKey, encoding=serialization.Encoding.PEM, ser_format=serialization.PublicFormat.SubjectPublicKeyInfo) -> bytes:
    return public_key.public_bytes(
        encoding=encoding,
        format=ser_format
    )

def getPrivateKeyFromBytes(private_bytes: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(
        data=private_bytes,
        password=None,
        backend=default_backend()
    )

def getPublicKeyFromBytes(public_bytes: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(
        data=public_bytes,
        backend=default_backend()
    )

def getSignature(private_key: rsa.RSAPrivateKey, data: bytes, padding: AsymmetricPadding=PKCS1v15(), algorithm: HashAlgorithm=buildDigestFunction()) -> bytes:
    return private_key.sign(
        data,
        padding,
        algorithm
    )

def verifySignature(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes, padding: AsymmetricPadding=PKCS1v15(), algorithm: HashAlgorithm=buildDigestFunction()) -> bool:
    try:
        public_key.verify(signature,data,padding,algorithm)
    except InvalidSignature:
        return False
    return True

def encrypt(public_key: rsa.RSAPublicKey, data: bytes, padding: AsymmetricPadding=PKCS1v15()) -> bytes:
    return public_key.encrypt(data,padding)

def decrypt(private_key: rsa.RSAPrivateKey, data: bytes, padding: AsymmetricPadding=PKCS1v15()) -> bytes:
    return private_key.decrypt(data,padding)

'''
Key exchange algorithms come into play in shared_key message signature algorithms such as HMAC or CMAC.
Because of this is advisable to rotate the keys time to time.
Since there is nothing about supporting multiple assymetric algorithms we will use RSA by default.
'''