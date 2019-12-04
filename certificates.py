import os
from urllib import request

from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID

TRUST_ANCHOR_DIRECTORY = "/etc/ssl/certs"
LOCAL_CERT_DIRECTORY = "./local_certs"

Certificates = {}
Cert_Rev_List = []

def load_pem_cert(filepath):
    cert_file = open(filepath,"rb")
    cert = x509.load_pem_x509_certificate(
        cert_file.read(),
        default_backend()
    )
    cert_file.close()
    if not cert.subject in Certificates:
        Certificates[cert.subject] = cert
    return cert

def load_trust_anchors():
    dir_iter = os.scandir(TRUST_ANCHOR_DIRECTORY)
    for entry in dir_iter:
        print("verifying ",entry.path)
        if entry.is_file():
            print(" - its a certificate file")
            try:
                cert = load_pem_cert(entry.path)
                print(" - its a PEM certificate")
                if check_cert_validity(cert):
                    Certificates[cert.subject] = cert
                    print(" - it has a valid date")
                else:
                    print(" - does not have a valid date")
            except:
                print(" - {} is not a PEM cert".format(entry.path))
        else:
            print(" - {} is not a certificate file".format(entry.path))

def load_cert_rev_list():
    dir_iter = os.scandir(LOCAL_CERT_DIRECTORY)
    for entry in dir_iter:
        print("verifying ",entry.path)
        if entry.is_file():
            print(" - its a certificate file")
            try:
                cert = load_pem_cert(entry.path)
                print(" - its a PEM certificate")
                if check_cert_validity(cert):
                    Certificates[cert.subject] = cert
                    print(" - it has a valid date")
                else:
                    print(" - does not have a valid date")
            except:
                print(" - {} is not a PEM cert".format(entry.path))
        else:
            print(" - {} is not a certificate file".format(entry.path))

def download_file(url):
    response = request.urlopen(url)
    return response.read()

def check_cert_validity(cert):
    now = datetime.now()
    return cert.not_valid_before < now and now < cert.not_valid_after

def is_cert_revoked(cert):
    if cert.subject == cert.issuer:
        return False
    extension_crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    for crl_obj in extension_crl:
        for uri in crl_obj.full_name:
            url = uri.value
            print(url)
            pem_crl_data = download_file(url)
            crl = x509.load_der_x509_crl(pem_crl_data,default_backend())
            print(crl)
            for r in crl:
                if cert.serial_number == r.serial_number:
                    return True
    return False

def build_cert_trust_chain(cert):
    trust_chain = [cert]
    
    if cert.subject == cert.issuer:
        return trust_chain
    elif cert.issuer in Certificates:
        return trust_chain + build_cert_trust_chain(Certificates[cert.issuer])
    else:
        raise Exception("The certificate provided has not been loaded! Unable to build trust chain!")

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

    filepath = input("path to the certificate you wish to load: ")
    cert = load_pem_cert(filepath)
    is_valid = check_cert_validity(cert)
    print("serial number:",cert.serial_number)
    print("version:",cert.version)
    print("datetime now:", datetime.now())
    print("not valid before:", cert.not_valid_before)
    print("not valid after:", cert.not_valid_after)
    print("is valid:", is_valid)
    print("is in Certificates Dictionary:", cert.subject in Certificates)
    load_trust_anchors()
    load_cert_rev_list()
    print("building trust path for {}".format(filepath))
    trust_chain = build_cert_trust_chain(cert)
    for entry in trust_chain:
        print("====")
        print(is_cert_revoked(entry))
    
    check_trust_chain(trust_chain)
    print("this certificate is trust worthy")

else :
    load_trust_anchors()
    load_cert_rev_list()