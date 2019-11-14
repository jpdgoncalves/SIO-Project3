import os

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend

SUPPORTED_ALGORITHMS = {
    algorithms.AES.name: algorithms.AES,
    algorithms.ChaCha20.name: algorithms.ChaCha20
}

SUPPORTED_MODES = {
    modes.CBC.name: modes.CBC,
    modes.GCM.name: modes.GCM
}

def buildSymmetricCypher(key: bytes, algorithm_name: str = "AES", mode_name: str = "CBC", iv = None, nonce = None, tag = None, backend = default_backend()):
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