#!/bin/bash

curl -F 'csrfile=@./csr_sample/req_02.csr' http://127.0.0.1:5000/certificateSignatureRequest
