import os
import sys
import base64
import json

from cryptography.x509 import Certificate
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.hazmat.backends import default_backend

import cartao_cidadao
import assymetric_encryption
import certificates
import handshake_ec

USED_AUTH_IDS = set()
USER_DIRECTORY = "users/"
USERS = {}
NUMBER_OTPS = 100

def getID():
    return int.from_bytes(os.urandom(16), byteorder="big")


def getChallenge(method: str, cert: Certificate, user_name: str=None) -> dict:
    message = {
        "type" : "CHALLENGE",
        "challenge" : None,
        "certificate" : base64.b64encode(cert.public_bytes(Encoding.DER)).decode()
    }
    
    if method == "OTP":
        challenge = getChallengeOTP(user_name)
    elif method == "CERTIFICATE":
        challenge = getChallengeNonce()
    else:
        challenge = None
    
    message["challenge"] = challenge
    return message


def getChallengeOTP(user_name: str) -> dict:
    challenge = {
        "root" : "",
        "indice" : -1
    }
    
    if not user_name in USERS:
        raise Exception(f"User({user_name}) does exist.")

    user = USERS[user_name]
    root = user["root"]
    indice = user["indice"]

    challenge["root"] = base64.b64encode(root).decode()
    challenge["indice"] = indice

    return challenge


def getChallengeNonce():
    challenge = {
        "nonce" : base64.b64encode(os.urandom(32)).decode()
    }

    return challenge


def checkChallenge(message: dict):
    certificate_bytes = base64.b64decode( message["certificate"].encode())
    certificate = load_der_x509_certificate(certificate_bytes, default_backend())
    if not certificate.subject in certificates.Certificates:
        raise Exception("This is not the server certificate")

    loaded_certificate = certificates.Certificates[certificate.subject]
    c_fingerprint = certificates.fingerprint(certificate)
    lc_fingerprint = certificates.fingerprint(loaded_certificate)
    if c_fingerprint != lc_fingerprint:
        raise Exception("This is not not equal to the loaded server certificate")
 

def getChallengeResponse(method: str, message: dict, dh_public_key: ec.EllipticCurvePublicKey=None, rsa_public_key: rsa.RSAPublicKey=None) -> dict:
    r_message = {
        "type" : "CHALLENGE_RESPONSE",
        "response" : {},
        "challenge" : getChallengeNonce()
    }

    challenge = message["challenge"]
    server_certificate_bytes = base64.b64decode( message["certificate"].encode() )
    server_certificate = load_der_x509_certificate(server_certificate_bytes, default_backend())
    server_public_key = server_certificate.public_key()

    if method == "OTP":
        response = getResponseOTP(challenge,dh_public_key,rsa_public_key)
    elif method == "CERTIFICATE":
        response = getResponseCC(challenge)
        dh_public_bytes = handshake_ec.getPeerPublicBytesFromKey(dh_public_key)
        rsa_public_bytes = assymetric_encryption.getPublicBytesFromKey(rsa_public_key)
        response["dh_public_bytes"] = base64.b64encode(dh_public_bytes).decode()
        response["rsa_public_bytes"] = base64.b64encode(rsa_public_bytes).decode()
    else:
        response = {}
    
    
    r_message["response"] = response

    return r_message


def getResponseOTP(challenge: dict, dh_public_key: ec.EllipticCurvePublicKey=None, rsa_public_key: rsa.RSAPublicKey=None) -> dict:
    response = {
        "otp" : '',
        "dh_public_bytes" : '',
        "rsa_public_bytes" : ''
    }
    password = input(" - Password: ").encode()

    indice = challenge["indice"]
    root = base64.b64decode( challenge["root"].encode())
    otp = produce_otp(password, root, indice-1)

    dh_public_bytes = handshake_ec.getPeerPublicBytesFromKey(dh_public_key)
    rsa_public_bytes = assymetric_encryption.getPublicBytesFromKey(rsa_public_key)

    response["otp"] = base64.b64encode(otp).decode()
    response["dh_public_bytes"] = base64.b64encode(dh_public_bytes).decode()
    response["rsa_public_bytes"] = base64.b64encode(rsa_public_bytes).decode()

    return response


def getResponseCC(challenge: dict) -> dict:
    response = {
        "signature" : ''
    }

    nonce = base64.b64decode(challenge["nonce"].encode())
    signature = cartao_cidadao.sign_with_cc(nonce)

    response["signature"] = base64.b64encode(signature).decode()
    return response


def getResponseNonce(challenge: dict, rsa_private_key: rsa.RSAPrivateKey) -> dict:
    response = {
        "signature" : ''
    }

    nonce = base64.b64decode(challenge["nonce"].encode())
    signature = assymetric_encryption.getSignature(rsa_private_key, nonce)
    
    response["signature"] = base64.b64encode(signature).decode()
    return response


def getSucessFailure(method: str, user_name: dict, message: dict, rsa_private_key: rsa.RSAPrivateKey, dh_public_key: ec.EllipticCurvePublicKey, nonce: bytes=None) -> dict:
    r_message = {
        "type" : "SUCESS",
        "response" : {}
    }

    challenge_response = message["response"]
    challenge = message["challenge"]

    if method == "OTP" and checkResponseOTP(challenge_response, user_name):
        r_type = "SUCCESS"
        response = getResponseNonce(challenge, rsa_private_key)
    elif method == "CERTIFICATE" and checkResponseCertificate(challenge_response, user_name, nonce):
        r_type = "SUCCESS"
        response = getResponseNonce(challenge, rsa_private_key)
    else:
        r_type = "ERROR"
        response = {}
    
    dh_public_bytes = handshake_ec.getPeerPublicBytesFromKey(dh_public_key)
    response["dh_public_bytes"] = base64.b64encode(dh_public_bytes).decode()

    r_message["type"] = r_type
    r_message["response"] = response
    return r_message


def checkResponseOTP(response: dict, user_name: str) -> bool:
    
    otp_to_check = base64.b64decode(response["otp"].encode())

    return otp_check(user_name, otp_to_check)


def checkResponseCertificate(response: dict, user_name: str, nonce: bytes) -> bool:
    user = USERS[user_name]
    certificate = user["certificate"]
    signature = base64.b64decode(response["signature"].encode())

    return cartao_cidadao.verify_signature_cc(nonce, signature, certificate)


def checkResponseNonce(response: dict, nonce: bytes, rsa_public_key: rsa.RSAPublicKey) -> bool:
    signature = base64.b64decode(response["signature"].encode())
    return assymetric_encryption.verifySignature(rsa_public_key, signature, nonce)


############################################################################################
#                                                                                          #
# OTP CODE                                                                                 #
#                                                                                          #
############################################################################################


def otp_matches(current_otp: bytes, otp_to_check: bytes) -> bool:
    digest_func = assymetric_encryption.buildDigestFunction()
    digest_func.update(otp_to_check)
    otp_to_check = digest_func.finalize()
    return current_otp == otp_to_check


def otp_status(user: dict) -> bool:
    return user["indice"] >= 0


def otp_check(user_name: str, otp_to_check: bytes) -> bool:
    user = USERS[user_name]

    if not otp_status(user):
        print(f" - User{user_name} has no more OTPS left.")
        return False
    
    current_otp = user["current_otp"]
    indice = user["indice"]

    if not otp_matches(current_otp, otp_to_check):
        return False
    
    indice -= 1
    current_otp = otp_to_check
    
    user["indice"] = indice
    user["current_otp"] = current_otp
    user_json = user_dict_to_json(user)
    write_user_file(user_name, user_json)

    return True
    

def produce_otp(password: bytes, root: bytes, indice: int):
    digest_func = assymetric_encryption.buildDigestFunction()
    digest_func.update(root)
    digest_func.update(password)
    current_otp = digest_func.finalize()

    for i in range(1,indice):
        digest_func = assymetric_encryption.buildDigestFunction()
        digest_func.update(current_otp)
        current_otp = digest_func.finalize()
    return current_otp

############################################################################################
#                                                                                          #
# USERS CODE                                                                               #
#                                                                                          #
############################################################################################

def load_users():
    dir_iter = os.scandir(USER_DIRECTORY)
    for entry in dir_iter:
        user = load_user(entry.path)
        user_key = entry.name.replace(".user","")
        USERS[user_key] = user


def load_user(file_name: str) -> dict:
    user = {
        "certificate" : b'',
        "current_otp" : b'',
        "indice" : 0,
        "root" : b'',
        "write_permission" : False
    }

    with open(file_name, "r") as user_file:
        user_json = json.loads(user_file.read())

        certificate_bytes = base64.b64decode(user_json["certificate"].encode())
        certificate = load_der_x509_certificate(certificate_bytes, default_backend())
        current_otp = base64.b64decode(user_json["current_otp"].encode())
        indice = user_json["indice"]
        root = base64.b64decode(user_json["root"].encode())
        write_permission = user_json["write_permission"]
    
    user["certificate"] = certificate
    user["current_otp"] = current_otp
    user["indice"] = indice
    user["root"] = root
    user["write_permission"] = write_permission
    return user


def user_dict_to_json(user: dict) -> dict:
    user_json = {
        "certificate" : "",
        "current_otp" : "",
        "indice" : user["indice"],
        "root" : "",
        "write_permission" : user["write_permission"]

    }
    
    certificate = user["certificate"]
    certificate_bytes = certificate.public_bytes(Encoding.DER)
    current_otp = user["current_otp"]
    root = user["root"]

    user_json["certificate"] = base64.b64encode(certificate_bytes).decode()
    user_json["current_otp"] = base64.b64encode(current_otp).decode()
    user_json["root"] = base64.b64encode(root).decode()

    return user_json


def write_user_file(user_name: str, user_json: dict):
    with open(f"{USER_DIRECTORY}{user_name}.user","w") as user_file:
        contents = json.dumps(user_json)
        user_file.write(contents)


def make_user(user_name: str, password: str, write_permission: bool=False):
    print(" - Making user...")
    user_json = {
        "certificate" : '',
        "current_otp" : '',
        "indice" : NUMBER_OTPS,
        "root" : '',
        "write_permission" : write_permission
    }

    root = os.urandom(16)
    print(f" - root: {root}")
    password = password.encode()
    
    current_otp = produce_otp(password, root, NUMBER_OTPS)
    
    _,certificate_bytes = cartao_cidadao.load_cert_auth_cc()
    certicate = base64.b64encode(certificate_bytes).decode()
    current_otp = base64.b64encode(current_otp).decode()

    user_json["certificate"] = certicate
    user_json["current_otp"] = current_otp
    user_json["root"] = base64.b64encode(root).decode()
    write_user_file(user_name,user_json)
    

############################################################################################
#                                                                                          #
# MAIN CODE                                                                                #
#                                                                                          #
############################################################################################

def get_args():
    return sys.argv[1:]

def register_user():
    username = input("Username to register: ")
    password = input("Password to register: ")
    write_permission = input("Has write permission: ") == "yes"
    make_user(username, password, write_permission)

############################################################################################
#                                                                                          #
# TEST CODE                                                                                #
#                                                                                          #
############################################################################################

def test():
    load_users()
    print(f" - Users: {USERS}")
    username = input(" - Username: ")
    password = input(f" - Password to check against user({username}): ")
    auth_method = input(" - Authentication method: ").upper()

    user = USERS[username]
    current_otp = user["current_otp"]
    root = user["root"]
    indice = user["indice"]
    otp_to_check = produce_otp(password.encode(), root, indice-1)
    is_equal = otp_matches(current_otp, otp_to_check)

    print(f" - root: {root}")
    print(f" - Are otps equal: {is_equal}")

    checks = otp_check(username, otp_to_check)

    print(f" - Do otps check: {checks}")
    print(f" - User after check: {user}")
    user = load_user(f"{USER_DIRECTORY}{username}.user")
    print(f" - File after check: {user}")

    server_cert = certificates.load_cert("server.cert.pem")
    with open("server.key.pem","rb") as server_key_file:
        server_private_key = assymetric_encryption.getPrivateKeyFromBytes(server_key_file.read())
    chall_message = getChallenge(auth_method, server_cert, username)

    client_priv_bytes,client_pub_bytes = assymetric_encryption.generateAssymetricKey()
    client_priv_key = assymetric_encryption.getPrivateKeyFromBytes(client_priv_bytes)
    client_pub_key = assymetric_encryption.getPublicKeyFromBytes(client_pub_bytes)
    dh_priv_key, dh_pub_key = handshake_ec.generateKeyPair()
    dh_server_priv_key, dh_server_pub_key = handshake_ec.generateKeyPair()

    print(f" - Challenge Message: {chall_message}")
    checkChallenge(chall_message)
    chall_response = getChallengeResponse(auth_method, chall_message, dh_public_key=dh_pub_key, rsa_public_key=client_pub_key)
    
    print(f" - Challenge Response: {chall_response}")

    nonce = base64.b64decode(chall_message["challenge"]["nonce"].encode()) if auth_method == "CERTIFICATE" else None
    success_response = getSucessFailure(auth_method, username, chall_response, server_private_key, dh_server_pub_key, nonce)

    print(f" - Challenge Response: {success_response}")

    challenge = chall_response["challenge"]
    response = success_response["response"]
    nonce = base64.b64decode(challenge["nonce"].encode())
    is_success_valid = checkResponseNonce(response, nonce ,server_cert.public_key())

    print(f" - Is success valid: {is_success_valid}")

    

############################################################################################
#                                                                                          #
# MAIN CODE                                                                                #
#                                                                                          #
############################################################################################

if __name__ == "__main__":
    args = get_args()
    if len(args) != 1:
        print("Usage: python authentication.py <test|register>")
    elif args[0] == "test":
        test()
    elif args[0] == "register":
        register_user()
    else:
        print("Usage: python authentication.py <test|register>")
else:
    load_users()