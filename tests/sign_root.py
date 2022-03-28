import base64
import hashlib
import sys

from ecdsa import SigningKey,VerifyingKey

text = sys.argv[1]

sk = SigningKey.from_pem(open("../keys/private-key_01.pem").read())

sig = sk.sign(text.encode())
sys.stdout.write(base64.b64encode(sig).decode())
