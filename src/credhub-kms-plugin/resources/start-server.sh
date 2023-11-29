./credhub-kms-plugin \
 -mode server \
 -az-tenant-id=6e93a626-8aca-4dc1-9191-ce291b4b75a1 \
 -az-keyvault-name=d05-credhub-keyvault \
 -az-keyvault-secret-name=credhub-encryption-keys \
 -socket kms-plugin.sock \
 -public-key-file grpc-kms-certs/grpc_kms_server_cert.pem \
 -private-key-file grpc-kms-certs/grpc_kms_server_key.pem
