# credhub-kms-plugin

Encrypts/decrypts credentials using an encryption key stored in AWS KMS or Azure keyvault.

# Generate the protobuf code
```bash
protoc --go_out=v1beta1 v1beta1/service.proto
```

# Compile Golang code
```bash 
GOOS=linux GOARCH=amd64 CGO_ENABLED=0  go build -o credhub-kms-plugin
```

# Local testing
```bash
mkdir -p $GOPATH/src/github.com/rabobank
git clone https://github.com/rabobank/credhub-kms-plugin $GOPATH/src/github.com/rabobank/credhub-kms-plugin
cd $GOPATH/src/github.com/rabobank/credhub-kms-plugin
go build
./scripts/setup_dev_grpc_certs.sh   # generate grpc certs
./credhub-kms-plugin -logtostderr -stderrthreshold=0 -socket kms-plugin.sock -public-key-file grpc-kms-certs/grpc_kms_server_cert.pem -private-key-file grpc-kms-certs/grpc_kms_server_key.pem &
```

# Deploying
If deployed on Azure, and you are using a Managed Identity (assigned to the VM):
* you have to set the environment variable `AZURE_TENANT_ID` or `AZURE_TENANT_ID_FILE` to the tenant id of the Azure subscription.
* if your VM has multiple Managed Identities assigned, you have to specify the environment variable `AZURE_CLIENT_ID` or `AZURE_CLIENT_ID_FILE` to the client id of the Managed Identity you want to use.
