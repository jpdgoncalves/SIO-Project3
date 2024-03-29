from PyKCS11 import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import binascii

lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

def get_cc_slot():
    slots = pkcs11.getSlotList()
    for slot in slots:
        if b'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            return slot
    return None

def sign_with_cc(text_bytes) -> bytes:
    slot = get_cc_slot()
    session = pkcs11.openSession(slot)
    mechanism = PyKCS11.Mechanism(CKM_SHA1_RSA_PKCS, None)
    priv_key_obj = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),(CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
    signature = bytes(session.sign(priv_key_obj, text_bytes, mechanism))
    session.closeSession()
    return signature

def load_cert_auth_cc():
    slot = get_cc_slot()
    session = pkcs11.openSession(slot)
    certificate_obj = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE),(CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]
    certificate_bytes = bytes( list( session.getAttributeValue(certificate_obj,[CKA_VALUE])[0] ) )
    certificate = x509.load_der_x509_certificate(certificate_bytes,default_backend())
    session.closeSession()
    return (certificate,certificate_bytes)

def verify_signature_cc(text_bytes,signature,cert = None):
    slot = get_cc_slot()
    session = pkcs11.openSession(slot)
    cert = load_cert_auth_cc()[0] if cert == None else cert
    public_key = cert.public_key()
    result = False
    try:
        public_key.verify(
            signature,
            text_bytes,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        result = True
    except:
        result = False
    finally:
        session.closeSession()
        return result

if __name__ == "__main__":
    text_bytes = input("Um texto para ser assinado: ").encode()
    signature = sign_with_cc(text_bytes)
    print(f"Signature: {signature}")
    is_valid = verify_signature_cc(text_bytes,signature)
    print("is valid: ", is_valid)
    _,certificate_bytes = load_cert_auth_cc()
    print(f"Certificate: {certificate_bytes}")