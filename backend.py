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
MDYwEAYHKoZIzj0CAQYFK4EEABwDIgAELMf8ZYwrBQ6k0HcckL5meinLpujDPaYU
IKMmbfENtS0=
-----END PUBLIC KEY-----
"""

ROOT_CERT = """-----BEGIN CERTIFICATE-----
MIIBoTCCAWagAwIBAgIUK7Cm6ZXSLX8ZOWmSDCqSqFaNb8AwCgYIKoZIzj0EAwIw
RzELMAkGA1UEBhMCVUExDTALBgNVBAgMBEt5aXYxDTALBgNVBAcMBEt5aXYxDDAK
BgNVBAoMA1RSTzEMMAoGA1UECwwDWlNVMB4XDTIyMDMyMzA5NTQxNVoXDTIzMDMy
MzA5NTQxNVowRzELMAkGA1UEBhMCVUExDTALBgNVBAgMBEt5aXYxDTALBgNVBAcM
BEt5aXYxDDAKBgNVBAoMA1RSTzEMMAoGA1UECwwDWlNVMDYwEAYHKoZIzj0CAQYF
K4EEABwDIgAELMf8ZYwrBQ6k0HcckL5meinLpujDPaYUIKMmbfENtS2jUzBRMB0G
A1UdDgQWBBSbfCROvMMwJAgn+I/dIKDLtQXXAjAfBgNVHSMEGDAWgBSbfCROvMMw
JAgn+I/dIKDLtQXXAjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCAykAMCYC
EQDOEvuXuosKyPLTohAnSHo8AhEAu4hCTo/5V0V7Uxt3dyPIEw==
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


##
# @brief   return CSR to root CA
@app.route("/downloadCSR", methods=['POST'])
def put_cert():
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
