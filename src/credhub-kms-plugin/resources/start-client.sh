./credhub-kms-plugin \
 -mode client \
 -client-healthcheck-interval 3 \
 -socket kms-plugin.sock \
 -public-key-file grpc-kms-certs/grpc_kms_server_cert.pem \
 -private-key-file grpc-kms-certs/grpc_kms_server_key.pem
