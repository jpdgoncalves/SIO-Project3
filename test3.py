
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

SUPPORTED_HASHES = {
    hashes.SHA256.name : hashes.SHA256,
    hashes.SHA512.name : hashes.SHA512
}

DERIVATION_INFO = b"VERY FUN STUFF - SIO 2019"

def generateKeyPair():
    private_key = ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return private_key,public_key

def buildPeerPublicKey(peer_public_bytes: bytes):
    return serialization.load_der_public_key(
        data=peer_public_bytes,
        backend=default_backend()
    )

def derivateSharedKey(private_key: ec.EllipticCurvePrivateKey,peer_public_key: ec.EllipticCurvePublicKey, digest_algorithm_name = "sha512"):
    if not digest_algorithm_name in SUPPORTED_HASHES:
        raise ValueError(f"{digest_algorithm_name} is not supported")

    digest_algorithm_class = SUPPORTED_HASHES[digest_algorithm_name]
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=digest_algorithm_class(),
        length=digest_algorithm_class.digest_size,
        salt=None,
        info=DERIVATION_INFO,
        backend=default_backend()
    ).derive(shared_key)