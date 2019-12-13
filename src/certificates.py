import os
from urllib import request

from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives.hashes import SHA256

TRUST_ANCHOR_DIRECTORY = "/etc/ssl/certs"
LOCAL_CERT_DIRECTORY = "local_certs"
DEBUG = False

Certificates = {}
Cert_Rev_List = []

def fingerprint(cert):
    return cert.fingerprint(SHA256())

def download_file(url):
    if DEBUG: print(f" - Dowloading: {url}")
    response = request.urlopen(url)
    return response.read()

def load_cert(filepath):
    cert = None

    with open(filepath, "rb")as cert_file:
        cert_data = cert_file.read()

        if b"-----BEGIN CERTIFICATE-----" in cert_data:
            if DEBUG: print(" - This is a PEM Certificate. Attempting to load.")
            cert = x509.load_pem_x509_certificate(
                cert_data,
                default_backend()
            )
        else:
            if DEBUG: print(" - Likely a DER certificate. Attempting to load.")
            cert = x509.load_der_x509_certificate(
                cert_data,
                default_backend()
            )
    if DEBUG: print(" - Certificate loaded.")
    return cert

def is_cert_date_valid(cert):
    now = datetime.now()
    return cert.not_valid_before < now and now < cert.not_valid_after

def load_trust_anchors():
    dir_iter = os.scandir(TRUST_ANCHOR_DIRECTORY)
    for entry in dir_iter:

        if DEBUG: print(f" - Verifying {entry.path}")

        if entry.is_file():

            if DEBUG: print(f" - {entry.path} is a file")

            try:
                cert = load_cert(entry.path)
                if is_cert_date_valid(cert):
                    Certificates[cert.subject] = cert
                    if DEBUG: print(f" - {entry.path} has a valid date. Registering")
                else:
                    print(f" - {entry.path} does not have a valid date. Discarding")
            except:
                print(f" - {entry.path} is not a certicate.")
        else:
            print(f" - {entry.path} is not a file")
        if DEBUG: print("---")

def load_local_certs(directory_path):
    dir_iter = os.scandir(LOCAL_CERT_DIRECTORY)
    for entry in dir_iter:

        if DEBUG: print(f"- Verifying {entry.path}")

        if entry.is_file():

            if DEBUG: print(f" - {entry.path} is a file")

            try:
                cert = load_cert(entry.path)

                if DEBUG: print(f" - {entry.path} is a certificate")

                if is_cert_date_valid(cert):
                    Certificates[cert.subject] = cert
                    if DEBUG: print(f" - {entry.path} has a valid date. Registering.")
                else:
                    print(f" - {entry.path} does not have a valid date. Discrading.")
            except:
                print(f" - {entry.path} is not a certificate.")
        else:
            print(f" - {entry.path} is not a file.")
        if DEBUG: print("---")

def build_cert_trust_chain(cert):
    trust_chain = [cert]
    
    if cert.subject == cert.issuer:
        return trust_chain
    elif cert.issuer in Certificates:
        return trust_chain + build_cert_trust_chain(Certificates[cert.issuer])
    else:
        raise Exception("The certificate provided has not been loaded! Unable to build trust chain!")

def is_cert_revoked(cert):
    if cert.subject == cert.issuer:
        return not cert.subject in Certificates
    extension_crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    for crl_obj in extension_crl:
        for uri in crl_obj.full_name:
            url = uri.value
            #print(url)
            pem_crl_data = download_file(url)
            crl = x509.load_der_x509_crl(pem_crl_data,default_backend())
            for r in crl:
                #print(f" - Serial number in crl: {r.serial_number}")
                if cert.serial_number == r.serial_number:
                    return True
    return False

def check_trust_chain(trust_chain):
    if trust_chain == []:
        return
    cert = trust_chain[0]
    if is_cert_revoked(cert):
        raise Exception("This certificate has been revoked!")
    if cert.subject == cert.issuer:
        public_key = cert.public_key()
        signature = cert.signature
        tbs_certificate_bytes = cert.tbs_certificate_bytes
        public_key.verify(
            signature,
            tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return

    cert_issuer = trust_chain[1]
    public_key = cert_issuer.public_key()
    signature = cert.signature
    tbs_certificate_bytes = cert.tbs_certificate_bytes
    public_key.verify(
        signature,
        tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )
    check_trust_chain(trust_chain[1:])



if __name__ == "__main__":
    DEBUG = True
    filepath = input("path to the certificate you wish to load: ")
    cert = load_cert(filepath)
    is_valid = is_cert_date_valid(cert)
    Certificates[cert.subject] = cert
    load_trust_anchors()
    load_local_certs(LOCAL_CERT_DIRECTORY)
    print("serial number:",cert.serial_number)
    print("version:",cert.version)
    print("issuer: ", cert.issuer)
    print("subject: ", cert.subject)
    print("datetime now:", datetime.now())
    print("not valid before:", cert.not_valid_before)
    print("not valid after:", cert.not_valid_after)
    print("is date valid:", is_valid)
    print("is in Certificates Dictionary:", cert.subject in Certificates)
    print("building trust path for {}".format(filepath))
    trust_chain = build_cert_trust_chain(cert)
    print("trust chain: ", trust_chain)
    for entry in trust_chain:
        print("====")
        print(f" - Verifying {entry.subject}")
        print(is_cert_revoked(entry))
    check_trust_chain(trust_chain)
    print("this certificate is trust worthy")

else :
    load_trust_anchors()
    load_local_certs(LOCAL_CERT_DIRECTORY)