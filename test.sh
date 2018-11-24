#!/bin/bash
set -e

gencsr2() {
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

gencsr3() {
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
DNS.2 = www.$domain
DNS.3 = api.$domain") \
    -out $csrfile
}

rndcsr() {
  keysize=$1
	openssl genrsa -out fixtures/valid.pkcs1.1.pem $keysize
  rasha fixtures/valid.pkcs1.1.pem > fixtures/test.jwk.1.json
  gencsr3 fixtures/valid.pkcs1.1.pem whatever.net fixtures/valid.csr.1.pem
  node bin/rsa-csr.js fixtures/test.jwk.1.json whatever.net,www.whatever.net,api.whatever.net \
    > fixtures/test.csr.1.pem
  diff fixtures/valid.csr.1.pem fixtures/test.csr.1.pem
}

echo ""
echo "Generating CSR for example.com,www.example.com"
gencsr2 fixtures/privkey-rsa-2048.pkcs1.pem example.com fixtures/example.com-www.csr.pem
node bin/rsa-csr.js fixtures/privkey-rsa-2048.jwk.json example.com,www.example.com \
  > fixtures/example.com-www.csr.1.pem
diff fixtures/example.com-www.csr.pem fixtures/example.com-www.csr.1.pem
echo "Pass"

echo ""
echo "Generating CSR for whatever.net,www.whatever.net,api.whatever.net"
gencsr3 fixtures/privkey-rsa-2048.pkcs1.pem whatever.net fixtures/whatever.net-www-api.csr.pem
node bin/rsa-csr.js fixtures/privkey-rsa-2048.jwk.json whatever.net,www.whatever.net,api.whatever.net \
  > fixtures/whatever.net-www-api.csr.1.pem
diff fixtures/whatever.net-www-api.csr.pem fixtures/whatever.net-www-api.csr.1.pem
echo "Pass"

echo ""
echo "Generating random keys of various lengths and re-running tests for each"
rndcsr 3072
rndcsr 1024
rndcsr 512 # minimum size that can reasonably work
echo "Pass"

rm fixtures/*.1.*

echo ""
echo "All tests passed!"
echo "  • Fixture CSRs built and do not differ from OpenSSL-generated CSRs"
echo "  • Random keys and CSRs are also correct"
