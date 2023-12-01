./credhub-kms-plugin \
 -mode server \
 -az-tenant-id=<subscription id> \
 -az-keyvault-name=<keyvault name> \
 -az-keyvault-secret-name=<secret name> \
 -socket kms-plugin.sock \
 -public-key-file grpc-kms-certs/grpc_kms_server_cert.pem \
 -private-key-file grpc-kms-certs/grpc_kms_server_key.pem
