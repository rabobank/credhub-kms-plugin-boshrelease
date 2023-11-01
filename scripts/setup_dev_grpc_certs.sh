#!/bin/bash

function set_bash_error_handling() {
    set -euo pipefail
}

generate_grpc_kms_certs() {
  echo "Generating gPRC Certs"

  rm -rf grpc-kms-certs
  mkdir -p grpc-kms-certs
  pushd grpc-kms-certs >/dev/null
    openssl req \
        -x509 \
        -newkey rsa:2048 \
        -days 365 \
        -sha256 \
        -nodes \
        -subj "/CN=localhost" \
        -keyout grpc_kms_ca_private.pem \
        -out grpc_kms_ca_cert.pem

    openssl genrsa -out grpc_kms_server_key.pem 2048
    openssl req -new -sha256 -key grpc_kms_server_key.pem -subj "/CN=localhost" -out grpc_kms_server.csr
    openssl x509 -req -in grpc_kms_server.csr -sha384 -CA grpc_kms_ca_cert.pem -CAkey grpc_kms_ca_private.pem \
        -CAcreateserial -out grpc_kms_server_cert.pem


  popd >/dev/null
}

main() {
  set_bash_error_handling
  generate_grpc_kms_certs
}

main
