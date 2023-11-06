# credhub-kms-plugin

Encrypts/decrypts credentials using an encryption key stored in Azure keyvault (and AWS Secrets Manager, TODO).

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
./credhub-kms-plugin -socket kms-plugin.sock -public-key-file grpc-kms-certs/grpc_kms_server_cert.pem -private-key-file grpc-kms-certs/grpc_kms_server_key.pem -az-tenant-id=<tenantd-id>> -az-keyvault-name=<keyvault name> -az-keyvault-secret-name=<secret name>
```

# Deploying
If deployed on Azure, and you are using a Managed Identity (assigned to the VM):
* you have to set the environment variable `AZURE_TENANT_ID` or `AZURE_TENANT_ID_FILE` to the tenant id of the Azure subscription.
* if your VM has multiple Managed Identities assigned, you have to specify the environment variable `AZURE_CLIENT_ID` or `AZURE_CLIENT_ID_FILE` to the client id of the Managed Identity you want to use.

Run `./credhub-kms-plugin -h` for more information about all the options.  
Example invocation for an Azure environment:
```bash
./credhub-kms-plugin \
 -az-tenant-id=<tenantd-id>> \
 -az-keyvault-name=<keyvault name> \
 -az-keyvault-secret-name=<secret name> \
 -socket /var/vcap/sys/run/credhub-kms-plugin/kms-plugin.sock \
 -public-key-file kms_server_cert.pem \
 -private-key-file kms_server_key.pem
```

# Switching between credhub providers
The interface between credhub and the kms-plugin does not pass the nonce that is used by the internal provider. This means that the plugin cannot decrypt values that were encrypted by the internal provider.  
Steps you can take to switch providers:
* deploy kms plugin (use [a BOSH release for that](https://github.com/vmware-archive/sample-credhub-kms-plugin-release/tree/main))
* create a credhub backup, just to be sure (you can make a mysqldump of the cf credhub database)
* run a credhub export, saving the output to a file that you can later use to import again (you do lose entry versions though)
* stop all but one credhub instance (we assume you can afford this decreased availability)
* make sure nobody else uses credhub (yes, we again assume this has impact on availability)
* delete all credhub entries: 
```bash
#! /bin/bash
#
for E in $(credhub export -p / | grep '\- name:' | awk '{print $NF}')
do
  credhub d -n $E
done
```
* also on the cf database server:  ``delete from encryption_key_canary`` (it looks this is used during startup of credhub, and it will fail when you first run with your kms-plugin)
* start credhub
* check credhub.log
* credhub import all the entries, using the yml file you created earlier
* test: ``cf cs credhub default credhub-plugin-test -c '{"testcredentialP":"testsecretP"}'``
* start the other credhub instances


## Building the BOSH release 

```
cd ~/workspace
git clone https://github.com/cloudfoundry/bosh-package-golang-release.git
git clone <this repo>
cd credhub-kms-plugin-boshrelease
bosh vendor-package golang-1.21-linux ../bosh-package-golang-release
bosh create-release --final --version=0.0.1 --force
bosh upload-release
```

## Manifest updates

To deploy the plugin, you can use the following bosh operator file:

```
- type: replace
  path: /instance_groups/name=credhub/jobs/name=credhub/properties/credhub/encryption/keys
  value:
    - provider_name: credhub-kms-plugin
      key_properties:
        encryption_key_name: SampleEncryptionKeyName
      active: true
    - provider_name: internal-provider
      key_properties:
        encryption_password: ((credhub_encryption_password))
      active: false
- type: replace
  path: /instance_groups/name=credhub/jobs/name=credhub/properties/credhub/encryption/providers
  value:
    - name: credhub-kms-plugin
      type: kms-plugin
      connection_properties:
        endpoint: /var/vcap/sys/run/credhub-kms-plugin/credhub-kms-plugin.sock
        host: localhost
        ca: ((credhub-kms-plugin.ca))
    - name: internal-provider
      type: internal
- type: replace
  path: /variables/-
  value:
   name: credhub-kms-plugin
   options:
     common_name: localhost
     is_ca: true
   type: certificate
- type: replace
  path: /releases/-
  value:
    name: credhub-kms-plugin
    version: latest
- type: replace
  path: /instance_groups/name=credhub/jobs/-
  value:
    name: credhub-kms-plugin
    release: credhub-kms-plugin
    properties:
      credhub-kms-plugin:
        socket_endpoint: /var/vcap/sys/run/credhub-kms-plugin/credhub-kms-plugin.sock
        az-tenant-id: ((azure_ad_tenant_id))
        az-keyvault-name: d05-credhub-keyvault
        az-keyvault-secret-name: credhub-encryption-key
        private_key: ((credhub-kms-plugin.private_key))
        certificate: ((credhub-kms-plugin.certificate))
```
