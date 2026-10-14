#!/bin/sh
# Keys and certificates for the unit tests (cargo test). Per key
# type: a CA certificate (NAME.ca.pem), a leaf it issued for localhost that
# serves as both server and client certificate (NAME.pem), the leaf's key
# in PKCS#8 (NAME.key), its public key (NAME.spki.pem) and, where the type
# has them, its other encodings: SEC1 (p256/p384.sec1.key), PKCS#1
# (rsa2048.pkcs1.key) and the ML-DSA seed-only and expanded-only PKCS#8
# forms (mldsaNN.seed.key, mldsaNN.expanded.key; NAME.key is OpenSSL's
# default, both). rsa1024.key is under the 2048-bit minimum.
#
# The tests run this when the files are missing (the repository keeps no
# keys or certificates: .gitignore). Needs OpenSSL 3.5 or later for ML-DSA
# (default: openssl on the PATH; OPENSSL=/path/to/openssl for another).
set -eu
cd "$(dirname "$0")"
O=${OPENSSL:-openssl}

printf '%s\n' "subjectAltName=DNS:localhost" "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature" > leaf.ext

pair() { # NAME GENPKEY-ARGS...
  n=$1; shift
  "$O" genpkey "$@" -out "$n.ca.key"
  "$O" req -new -x509 -key "$n.ca.key" -subj "/CN=rustls provider test CA ($n)" -days 36500 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -out "$n.ca.pem"
  "$O" genpkey "$@" -out "$n.key"
  "$O" req -new -key "$n.key" -subj "/CN=localhost" -out "$n.csr"
  "$O" x509 -req -in "$n.csr" -CA "$n.ca.pem" -CAkey "$n.ca.key" -days 36500 \
    -extfile leaf.ext -out "$n.pem" 2>/dev/null
  "$O" pkey -in "$n.key" -pubout -out "$n.spki.pem"
  rm "$n.csr" "$n.ca.key"
}

pair p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
pair p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
pair ed25519 -algorithm ED25519
pair rsa2048 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
for l in 44 65 87; do
  pair "mldsa$l" -algorithm "ML-DSA-$l"
  "$O" pkey -in "mldsa$l.key" -provparam ml-dsa.output_formats=seed-only -out "mldsa$l.seed.key"
  "$O" pkey -in "mldsa$l.key" -provparam ml-dsa.output_formats=priv-only -out "mldsa$l.expanded.key"
done
"$O" ec -in p256.key -out p256.sec1.key 2>/dev/null
"$O" ec -in p384.key -out p384.sec1.key 2>/dev/null
"$O" rsa -in rsa2048.key -traditional -out rsa2048.pkcs1.key 2>/dev/null
"$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa1024.key
"$O" pkey -in rsa1024.key -pubout -out rsa1024.spki.pem
rm leaf.ext
