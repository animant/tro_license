#!/bin/bash

nonce=`curl  http://127.0.0.1:5000/requestCSRNonce -i 2> /dev/null|tr -d '\r'| sed -En 's/^nonce: (.*)/\1/p'`
signature=`python3 sign_root.py $nonce`
mkdir -p tmp
python3 verify_root.py $nonce $signature

curl -X POST -H"signature: $signature"  -H"nonce: $nonce"  http://127.0.0.1:5000/downloadCSR > tmp/req.csr
