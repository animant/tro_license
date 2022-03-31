import base64
import code
import hashlib
import os

from  time import time
from flask import Flask, request, make_response, render_template
from random import randint

from ecdsa import SigningKey,VerifyingKey,BadSignatureError
from OpenSSL import crypto

SES_TIMEOUT = 100
CERT_DIR = "certs"
CSR_DIR = 'csrs'


ROOT_PUB_KEY = """-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEzPipSKRl2gdSHsOCt4niGjGE6xv5BJ9K
HR1RVbFuc1gXBxgarmD1PODA4WrYr89/hEv8u7kIYPzzvv9XLfnXUQ==
-----END PUBLIC KEY-----
"""

ROOT_CERT = """-----BEGIN CERTIFICATE-----
MIIB4TCCAYagAwIBAgIUC9AC9Tpu6KDc3uteX9NicuiPX1swCgYIKoZIzj0EAwIw
RzELMAkGA1UEBhMCVUExDTALBgNVBAgMBEt5aXYxDTALBgNVBAcMBEt5aXYxDDAK
BgNVBAoMA1RSTzEMMAoGA1UECwwDWlNVMB4XDTIyMDMyOTIzNDE0MVoXDTIzMDMy
NDIzNDE0MVowRzELMAkGA1UEBhMCVUExDTALBgNVBAgMBEt5aXYxDTALBgNVBAcM
BEt5aXYxDDAKBgNVBAoMA1RSTzEMMAoGA1UECwwDWlNVMFYwEAYHKoZIzj0CAQYF
K4EEAAoDQgAEzPipSKRl2gdSHsOCt4niGjGE6xv5BJ9KHR1RVbFuc1gXBxgarmD1
PODA4WrYr89/hEv8u7kIYPzzvv9XLfnXUaNTMFEwHQYDVR0OBBYEFNwyMsqc7vdi
9UaofjWRYFT25wzMMB8GA1UdIwQYMBaAFNwyMsqc7vdi9UaofjWRYFT25wzMMA8G
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAJtJEhExBOyvn+rA4187
HlJ5gBIT7DMYMs9fniB1y9OsAiEAlN+NiQlt9dVQnH+aff0M3MWU78wHlvpl1kDP
Mi8AlzQ=
-----END CERTIFICATE-----"""

sessions = {}
app = Flask(__name__)

os.system(f"mkdir -p {CERT_DIR}")
os.system(f"mkdir -p {CSR_DIR}")

###@app.route("/")
###def hello_world():
###    return "<p>Hello, World!</p>"
###
###@app.route("/<namew>")
###def hello_worldqq(namew):
###    return f"<p>Hello, World! {namew}</p>"
###
###
###@app.route("/nameww", methods=['GET'])
###def hello_worldqqw():
###    val = request.args.get('qr','')
###    return f"<p>Hello, World! {val}</p>"
###
###
###@app.route("/ppp", methods=['POST'])
###def hello_worldqqwe():
###    val = request.form['key']
###    return f"<p>Hello, World! {val}</p>"

#@app.route("/kk/ll")
#def hello_worldw():
    #return "<p>Hello, Animant!</p>"


### 1-st ca generation

##
# @brief   upload CSR to back (client feature)
@app.route("/certificateSignatureRequest", methods=['POST'])
def csr_request():
    csrfile = request.files['csrfile']
    print("ok")
    name  = ''.join([str(randint(0,10)) for i in range(10)])
    csrfile.save(f"./csrs/{name}")
    return "Success"



##
# @brief   request nonce for authentication (root CA feature)
@app.route("/requestCSRNonce", methods=['GET'])
def get_csr_nonce():
    nonce  = ''.join(["%x"%randint(0,16) for i in range(20)])
    resp = make_response()
    resp.headers['nonce'] = nonce
    sessions[nonce] = int(time()) + SES_TIMEOUT
    return resp


def root_authentication():
    nonce = request.headers.get('nonce', '')
    signature = base64.b64decode(request.headers.get('signature', '').encode())
    print(f"nonce = {nonce}")
    print(f"signature = {signature}")
    print(request.headers)
    assert(nonce in sessions)
    assert(sessions[nonce] > int(time()))
    del sessions[nonce]
# check nonce signature
    vk = VerifyingKey.from_pem(ROOT_PUB_KEY)
    try:
        vk.verify(signature, nonce.encode())
    except BadSignatureError:
        return "Auth fail", 401


##
# @brief   return CSR to root CA
@app.route("/downloadCSR", methods=['POST'])
def put_cert():
    root_authentication()

    csrs = os.listdir('csrs')
    if len(csrs) > 1:
        for f in csrs:
            os.remove(f"{CSR_DIR}/{f}")
        return "To many CSRs were uploaded", 406
    elif len(csrs) == 0:
        return "CSR wasn't uploaded", 406

    csr_content = open(f"{CSR_DIR}/{csrs[0]}").read()
    os.remove(f"{CSR_DIR}/{csrs[0]}")
    return csr_content, 200


##
# @brief   upload CA certificate
@app.route("/uploadCert", methods=['POST'])
def upload_certificate():
    root_authentication()

    certfile = request.files['cert']
    print("ok")
    name  = ''.join([str(randint(0,10)) for i in range(10)])
    certfile.save(f"./certs/{name}")
    return 'Success', 200
