
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SUPPORTED_HASHES = {
    hashes.SHA256.name : hashes.SHA256,
    hashes.SHA512.name : hashes.SHA512
}

def buildDigest(algorithm_name = "SHA512",backend = default_backend()):
    if not algorithm_name in SUPPORTED_HASHES:
        raise ValueError(f"{algorithm_name} is not supported")

    algorithm = SUPPORTED_HASHES[algorithm_name]()

    return hashes.Hash(algorithm,backend)

'''
Key exchange algorithms come into play in shared_key message signature algorithms such as HMAC or CMAC.
Because of this is advisable to rotate the keys time to time.
'''