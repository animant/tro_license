import base64
import hashlib
import sys

import datetime

from ecdsa import SigningKey,VerifyingKey
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding
from cryptography.hazmat.backends import default_backend


def n(A):
    if A == None: return 'none'
    else: return A

#csrfile = sys.argv[1]
keyfile = sys.argv[1]
csrfile = sys.argv[2]
#subjectname = sys.argv[3]
#subjectlevel = sys.argv[4]

csr = x509.load_pem_x509_csr(data=open(csrfile).read().encode(), backend=default_backend())
common_name = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
subjectname,subjectlevel = common_name.split(":")
#print(csr.public_key)
#exit(0)

key = load_pem_private_key(open(keyfile).read().encode(), None, default_backend())
pubkey = csr.public_key()#load_pem_public_key(open(pubkeyfile).read().encode(), default_backend())
#csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
new_subject = x509.Name(
    [
        #x509.NameAttribute(NameOID.COUNTRY_NAME, u"UA"),
        #x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Kyiv"),
        x509.NameAttribute(NameOID.COMMON_NAME, subjectname),
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, subjectlevel),
        #x509.NameAttribute(NameOID.LOCALITY_NAME, u"ZSU"),
        #x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TRO"),
    ]
)
issuer = x509.Name(
    [
        #x509.NameAttribute(NameOID.COUNTRY_NAME, u"UA"),
        #x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Kyiv"),
        #x509.NameAttribute(NameOID.LOCALITY_NAME, u"ZSU"),
        #x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TRO"),
    ]
)
cert = (
    x509.CertificateBuilder()
    .subject_name(new_subject)
    .issuer_name(issuer)
    .public_key(pubkey)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    #.add_extension(
        #x509.SubjectAlternativeName([x509.DNSName(u"level:0")]),
        #critical=False,
    #)
    .sign(key, hashes.SHA256(), default_backend())
    )
print(cert.public_bytes(Encoding.PEM).decode())

