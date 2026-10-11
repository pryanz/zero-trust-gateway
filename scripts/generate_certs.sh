#!/bin/bash
set -e
DIR="certs"
mkdir -p $DIR

echo "--- Generating Root CA ---"
openssl genrsa -out $DIR/ca.key 4096
openssl req -x509 -new -nodes -key $DIR/ca.key -sha256 -days 365 -out $DIR/ca.crt -subj "/CN=ZeroTrust Root CA"

echo "--- Generating Upstream Server Cert (with SAN) ---"
openssl genrsa -out $DIR/server.key 2048
openssl req -new -key $DIR/server.key -out $DIR/server.csr -subj "/CN=localhost"


cat << 'EOF' > $DIR/server_ext.cnf
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in $DIR/server.csr -CA $DIR/ca.crt -CAkey $DIR/ca.key -CAcreateserial -out $DIR/server.crt -days 365 -sha256 -extfile $DIR/server_ext.cnf

echo "--- Generating Gateway Client Cert ---"
openssl genrsa -out $DIR/client.key 2048
openssl req -new -key $DIR/client.key -out $DIR/client.csr -subj "/CN=zero-trust-gateway"
openssl x509 -req -in $DIR/client.csr -CA $DIR/ca.crt -CAkey $DIR/ca.key -CAcreateserial -out $DIR/client.crt -days 365 -sha256

rm -f $DIR/server_ext.cnf $DIR/*.csr $DIR/*.srl
echo "--- Certificates regenerated with proper SANs ---"