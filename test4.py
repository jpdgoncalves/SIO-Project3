
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

SUPPORTED_HASHES = {
    hashes.SHA256.name : hashes.SHA256,
    hashes.SHA512.name : hashes.SHA512
}

def buildHMAC(key: bytes,hash_algorithm_name: str="sha512"):

    if not hash_algorithm_name in SUPPORTED_HASHES:
        raise ValueError(f"{hash_algorithm_name} is not supported")

    return hmac.HMAC(
        key=key,
        algorithm=SUPPORTED_HASHES[hash_algorithm_name](),
        backend=default_backend
    )