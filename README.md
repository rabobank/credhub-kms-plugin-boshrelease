# credhub-kms-plugin

Encrypts/decrypts credentials using an encryption key stored in AWS KMS or Azure keyvault.

# Generate the protobuf code
```bash
protoc --go_out=v1beta1 v1beta1/service.proto
```

# Compile Golang code
```bash 
.
```

## Local testing
```bash
mkdir -p $GOPATH/src/github.com/rabobank
git clone https://github.com/rabobank/credhub-kms-plugin $GOPATH/src/github.com/rabobank/credhub-kms-plugin
cd $GOPATH/src/github.com/rabobank/credhub-kms-plugin
go build
./scripts/setup_dev_grpc_certs.sh   # generate grpc certs
./credhub-kms-plugin -logtostderr -stderrthreshold=0 -socket kms-plugin.sock -public-key-file grpc-kms-certs/grpc_kms_server_cert.pem -private-key-file grpc-kms-certs/grpc_kms_server_key.pem &
```

