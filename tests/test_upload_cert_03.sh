#!/bin/bash

nonce=`curl  http://127.0.0.1:5000/requestCSRNonce -i 2> /dev/null|tr -d '\r'| sed -En 's/^nonce: (.*)/\1/p'`
signature=`python3 sign_root.py $nonce`
mkdir -p tmp
python3 verify_root.py $nonce $signature

python3 sign_csr.py ../keys/private-key_01.pem tmp/req.csr > tmp/cert.pem
curl -X POST -F 'cert=@./tmp/cert.pem' -H"signature: $signature"  -H"nonce: $nonce"  http://127.0.0.1:5000/uploadCert 
