import os

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

SUPPORTED_ALGORITHMS = {
    algorithms.AES.name: algorithms.AES,
    algorithms.ChaCha20.name: algorithms.ChaCha20
}

SUPPORTED_MODES = {
    modes.CBC.name: modes.CBC,
    modes.GCM.name: modes.GCM
}

ASSOCIATED_DATA = b"My awesome tag <3"

def buildSymmetricCypher(key: bytes, algorithm_name: str="AES", mode_name: str="CBC", iv: bytes=None, nonce: bytes=None, tag=None, backend=default_backend()):
    if not algorithm_name in SUPPORTED_ALGORITHMS:
        raise ValueError(f"{algorithm_name} is not supported")

    algorithm_class = SUPPORTED_ALGORITHMS[algorithm_name]

    if issubclass(algorithm_class, algorithms.BlockCipherAlgorithm):
        algorithm = algorithm_class(key)

        if not mode_name in SUPPORTED_MODES:
            raise ValueError(f"{mode_name} is not supported")

        mode_class = SUPPORTED_MODES[mode_name]

        if issubclass(mode_class, modes.ModeWithAuthenticationTag):
            mode = mode_class(iv,tag)
        else:
            mode = mode_class(iv)
        
        cipher = Cipher(algorithm=algorithm,mode=mode,backend=backend)

    else:
        algorithm = algorithm_class(key,nonce)
        cipher = Cipher(algorithm=algorithm, mode=None, backend=backend)
    
    return cipher

def cipherRequirements(algorithm_name: str, mode_name: str) -> set:
    algorithm_class = SUPPORTED_ALGORITHMS[algorithm_name]
    mode_class = SUPPORTED_MODES[mode_name] if mode_name in SUPPORTED_MODES else None
    requirements = []
    if issubclass(algorithm_class, algorithms.BlockCipherAlgorithm):
        requirements.append("iv")
        if issubclass(mode_class, modes.ModeWithAuthenticationTag):
            requirements.append("tag")
    else:
        requirements.append("nonce")

    return set(requirements)

def encrypt(cipher: Cipher, data: bytes, associated_data=None) -> bytes:
    encryptor = cipher.encryptor()
    if isinstance(cipher.algorithm, algorithms.BlockCipherAlgorithm):
        if isinstance(cipher.mode, modes.ModeWithAuthenticationTag):
            encryptor.authenticate_additional_data(associated_data)
            return ((encryptor.update(data) + encryptor.finalize()), encryptor.tag)
        else:
            padder = PKCS7(cipher.algorithm.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()
            return encryptor.update(padded_data) + encryptor.finalize()
    else:
        return encryptor.update(data) + encryptor.finalize()

def decrypt(cipher: Cipher, data: bytes, associated_data=None) -> bytes:
    decryptor = cipher.decryptor()
    if isinstance(cipher.algorithm, algorithms.BlockCipherAlgorithm):
        if isinstance(cipher.mode, modes.ModeWithAuthenticationTag):
            decryptor.authenticate_additional_data(associated_data)
            return decryptor.update(data) + decryptor.finalize()
        else:
            data = decryptor.update(data) + decryptor.finalize()
            unpadder = PKCS7(cipher.algorithm.block_size).unpadder()
            return unpadder.update(data) + unpadder.finalize()
    else:
        return decryptor.update(data) + decryptor.finalize()