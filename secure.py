# MESSAGE NEGOTIATE
# {
#    type : NEGOTIATE
#    proposal : DH_AES_GCM_SHA512
# }

# MESSAGE EXCHANGE
# {
#    type : EXCHANGE
#    peer_key : b64encode(dh_public_bytes).decode() 
# }

# MESSAGE SECURE
# {
#    type : SECURE
#    payload : b64encode(json.dumps(message)).decode()
#    cyphered_key : b64encode(generated_key_bytes).decode()
#    iv : b64encode(bytes).decode() [It is optional]
#    nonce : b64encode(bytes).decode() [It is optional]
#    tag : b64encode(bytes).decode() [It is optional]
#    verification : b64encode(signature_bytes).decode()
# }

# MESSAGE ROTATE
# {
#    type : ROTATE
#    peer_key : b64encode(dh_public_bytes).decode()
# }

import os
import json
import base64
import symmetric_encryption
import assymetric_encryption
import handshake_ec
import hmac_generator
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

USED_IDS = set()

def secure(message: dict, shared_key:bytes, peer_public_key: RSAPublicKey, algorithm_name: str="AES", mode_name="CBC", hash_name:str="sha512") -> dict:

    message_s = {
        'id' : int.from_bytes(os.urandom(16), byteorder="big"),
        'type' : 'SECURE',
        'payload' : '',
        'cyphered_key' : '',
        'iv' : '',
        'nonce' : '',
        'tag' : '',
        'verification' : ''
    }

    key = os.urandom(32)
    hmac = hmac_generator.buildHMAC(shared_key,hash_name)

    message_s = encrypt(key, json.dumps(message).encode(), message_s, algorithm_name, mode_name)

    cyphered_key = assymetric_encryption.encrypt(peer_public_key,key)
    cyphered_key = base64.b64encode(cyphered_key).decode()
    message_s["cyphered_key"] = cyphered_key

    hmac.update( json.dumps(message_s).encode() )

    verification = hmac.finalize()

    message_s["verification"] = base64.b64encode(verification).decode()

    return message_s

def unsecure(secure_message: dict, shared_key:bytes, own_private_key: RSAPrivateKey, algorith_name: str="AES", mode_name="CBC", hash_name:str="sha512") -> dict:

    verification = base64.b64decode(secure_message["verification"].encode())
    signed_message = {
        'id' : secure_message["id"],
        'type' : secure_message['type'],
        'payload' : secure_message['payload'],
        'cyphered_key' : secure_message['cyphered_key'],
        'iv' : secure_message['iv'],
        'nonce': secure_message['nonce'],
        'tag' : secure_message['tag'],
        'verification' : ''
    }

    if secure_message["id"] in USED_IDS:
        raise ValueError("This id has already been used")
    else:
        USED_IDS.add(secure_message["id"])

    hmac = hmac_generator.buildHMAC(shared_key, hash_name)

    hmac.update( json.dumps(signed_message).encode() )
    hmac.verify( verification )

    cyphered_key = base64.b64decode(secure_message["cyphered_key"].encode())
    key = assymetric_encryption.decrypt(own_private_key, cyphered_key)

    unsecure_message = decrypt(key, secure_message, algorith_name, mode_name)
    unsecure_message = json.loads( unsecure_message.decode() )

    return unsecure_message

def encrypt(key: bytes, data: bytes ,message: dict, algorithm_name: str="AES", mode_name="CBC") -> dict:
    requirements = symmetric_encryption.cipherRequirements(algorithm_name,mode_name)
    if "iv" in requirements:
        if "tag" in requirements:
            iv = os.urandom(16)
            associated_data = symmetric_encryption.ASSOCIATED_DATA
            cipher = symmetric_encryption.buildSymmetricCypher(key, algorithm_name, mode_name,iv=iv,tag=None)
            payload,tag = symmetric_encryption.encrypt(cipher, data, associated_data)
            message["payload"] = base64.b64encode(payload).decode()
            message["iv"] = base64.b64encode(iv).decode()
            message["tag"] = base64.b64encode(tag).decode()
            return message
        else:
            iv = os.urandom(16)
            cipher = symmetric_encryption.buildSymmetricCypher(key, algorithm_name, mode_name, iv=iv)
            payload = symmetric_encryption.encrypt(cipher, data)
            message["payload"] = base64.b64encode(payload).decode()
            message["iv"] = base64.b64encode(iv).decode()
            return message
    else:
        nonce = os.urandom(16)
        cipher = symmetric_encryption.buildSymmetricCypher(key,algorithm_name,mode_name,nonce=nonce)
        payload = symmetric_encryption.encrypt(cipher, data)
        message["payload"] = base64.b64encode(payload).decode()
        message["nonce"] = base64.b64encode(nonce).decode()
        return message
    

def decrypt(key: bytes, message: dict, algorithm_name: str="AES", mode_name="CBC") -> bytes:
    requirements = symmetric_encryption.cipherRequirements(algorithm_name,mode_name)
    data = base64.b64decode( message["payload"].encode() )
    if "iv" in requirements:
        if "tag" in requirements:
            iv = base64.b64decode( message["iv"].encode() )
            tag = base64.b64decode( message["tag"].encode() )
            associated_data = symmetric_encryption.ASSOCIATED_DATA
            cipher = symmetric_encryption.buildSymmetricCypher(key, algorithm_name, mode_name, iv=iv, tag=tag)
            original_message = symmetric_encryption.decrypt(cipher,data,associated_data)
            return original_message
        else:
            iv = base64.b64decode( message["iv"].encode() )
            cipher = symmetric_encryption.buildSymmetricCypher(key, algorithm_name, mode_name,iv=iv)
            original_message = symmetric_encryption.decrypt(cipher, data)
            return original_message
    else:
        nonce = base64.b64decode( message["nonce"].encode() )
        cipher = symmetric_encryption.buildSymmetricCypher(key, algorithm_name, mode_name,nonce=nonce)
        original_message = symmetric_encryption.decrypt(cipher,data)
        return original_message

if __name__ == "__main__":

    print("Debugging secure.py")

    ALGORITHM_NAME = 'ChaCha20'
    MODE_NAME = ''
    HASH_NAME = 'sha512'
    
    c_private_bytes, c_public_bytes = assymetric_encryption.generateAssymetricKey()
    c_private_key = assymetric_encryption.getPrivateKeyFromBytes(c_private_bytes)
    c_public_key = assymetric_encryption.getPublicKeyFromBytes(c_public_bytes)
    
    s_private_bytes, s_public_bytes = assymetric_encryption.generateAssymetricKey()
    s_private_key = assymetric_encryption.getPrivateKeyFromBytes(s_private_bytes)
    s_public_key = assymetric_encryption.getPublicKeyFromBytes(s_public_bytes)
    
    dh_priv_key, dh_pub_key = handshake_ec.generateKeyPair()
    peer_priv_key, peer_pub_key = handshake_ec.generateKeyPair()
    
    shared_key = handshake_ec.deriveSharedKey(dh_priv_key, peer_pub_key)
    server_shared_key = handshake_ec.deriveSharedKey(peer_priv_key, dh_pub_key)

    msg = {
    'type' : 'OPEN',
    'file_name' : 'test.txt'
    }
    msg_secure = secure(msg, shared_key, s_public_key, ALGORITHM_NAME, MODE_NAME, HASH_NAME)
    msg_unsecure = unsecure(msg_secure, server_shared_key, s_private_key, ALGORITHM_NAME, MODE_NAME, HASH_NAME)
    
    print(msg_secure)
    print(msg_unsecure)