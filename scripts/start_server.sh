#!/bin/bash

main() {
    scripts/setup_dev_grpc_certs.sh
    echo -e "CA is available at $(pwd)/grpc-kms-certs/grpc_kms_ca_cert.pem"
    go run main.go -socket /tmp/socket.sock  -public-key-file grpc-kms-certs/grpc_kms_server_cert.pem  -private-key-file grpc-kms-certs/grpc_kms_server_key.pem
}

main