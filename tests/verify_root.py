import base64
import hashlib
import sys

from ecdsa import SigningKey,VerifyingKey

text = sys.argv[1].encode()
sig = base64.b64decode(sys.argv[2].encode())

pk = VerifyingKey.from_pem(open("../keys/public-key_01.pem").read())

verify = pk.verify(sig, text)
