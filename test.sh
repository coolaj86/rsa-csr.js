#!/bin/bash

gencsr() {
  keyfile=$1
  domain=$2
  csrfile=$3
  openssl req -key $keyfile -new -nodes \
    -config <(printf "[req]
prompt = no
req_extensions = req_ext
distinguished_name = dn

[ dn ]
CN = $domain

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $domain
DNS.2 = www.$domain") \
    -out $csrfile
}

gencsr fixtures/privkey-rsa-2048.pkcs1.pem example.com fixtures/example.com-www.csr.pem
