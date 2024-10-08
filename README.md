# credhub-kms-plugin

The security issue with the default provider of credhub is that the encryption key is stored plaintext on the credhub VMs (`/var/vcap/jobs/credhub/config/application/encryption.yml`).  
With this kms-plugin, the encryption key is retrieved from either Azure keyvault or AWS Secrets Manager.  
Communication between credhub and the kms-plugin is done using gRPC with TLS over a local unix socket, this cert and the credhub cert should share the same CA (see operator file below ``((credhub-kms-plugin.ca))`` ).  
The secrets are encrypted using AES-GCM, with a 32 byte key and each encrypted secret has it's own nonce.  
The nonce and the name of the encryption key are prepended to the encrypted secret, returned to credhub, which then stores it in the credhub database.
The credhub-kms-plugin can run in 2 modes: server and client, the server mode is the actual kms-plugin and is called by credhub, the client mode is used by the healthchecker to verify if the credhub-kms-plugin is still healthy.

See the [Cloud Foundry documentation on kms-plugin](https://docs.cloudfoundry.org/credhub/kms-plugin.html).

# Generate the gRPC code
The communication between credhub and a kms-plugin is done using gRPC. Therefore we need to generate the grpc code: 
```bash
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative v1beta1/service.proto
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
go build .
./create-grpc-certs.sh
#  fill in the parameters in resources/start-server.sh
./start-server.sh
./start-client.sh
```

# Deploying

For both AWS and Azure you have to setup the secrets there first, in Azure you use a keyvault, in AWS you use Secrets Manager.  
The value of the secret should be a json structure that specifies all encryption keys:  

````json
{
  "keys": [
    {
      "name": "key0001",
      "value": "this-is-a-32-byte-encryption-key",
      "active": true,
      "date": "2023-11-20 16:34"
    },
    {
      "name": "key0002",
      "value": "bcdefghijklmnopqrstuvwxyz1234567",
      "active": false,
      "date": "2023-11-19 15:33"
    },
    {
      "name": "key0003",
      "value": "abcdefghijklmnopqrstuvwxyz123456",
      "active": false,
      "date": "2023-11-18 14:32"
    }
  ]
}
````
* The maximum length of a key name is 16 characters.
* The length of the encryption key value must be 32 characters.
* Only one key can be "active" at any point in time, that key will be used to encrypt new secrets.
* Once an encryption key has been used to encrypt secrets, it cannot be deleted from the secret store anymore because you need it to decrypt the secrets.  
* Do not rename an encryption key, because during decryption the name is used to identify the key in the secret store.

If any of these rules are violated, the kms-plugin will not start, or when it is already started it will not reload the encryption keys, check the logs for errors.  
The credhub-kms-plugin-healthchecker will start failing (the most important reason for it's existence is to detect errors in your keyvault or Secrets Manager content, and warn you before the credhub-kms-plugin itself starts to fail).

## Azure
If deployed on Azure, and you are using a Managed Identity (assigned to the VM):
* you have to set the environment variable `AZURE_TENANT_ID` or `AZURE_TENANT_ID_FILE` to the tenant id of the Azure subscription.
* if your VM has multiple Managed Identities assigned, you have to specify the environment variable `AZURE_CLIENT_ID` or `AZURE_CLIENT_ID_FILE` to the client id of the Managed Identity you want to use.

## AWS
When creating the secret in AWS Secrets Manager, make sure to use a (JSON) key value pair with the following (sample structure):  
Also don't activate automatic rotation.

The credhub VMs need an EC2 instance profile that allows for reading the secret from AWS Secrets Manager.  
This could be an example of the (inline) policy for that:
````
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowReadingSecret",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": [
                "arn:aws:secretsmanager:eu-west-1:123456789012:secret:my-credhub-secret-123456"
            ]
        }
    ]
}
````

Run `./credhub-kms-plugin -h` for more information about all the options, and also checkout the boshrelease file ctl.erb.    
Example invocation for an Azure environment:
```bash
./credhub-kms-plugin \
 -az-tenant-id=<tenant-id> \
 -az-keyvault-name=<keyvault name> \
 -az-keyvault-secret-name=<secret name> \
 -socket /var/vcap/sys/run/credhub-kms-plugin/kms-plugin.sock \
 -public-key-file kms_server_cert.pem \
 -private-key-file kms_server_key.pem
```
Example invocation for an AWS environment:
```bash
./credhub-kms-plugin \
 -aws-region=<eu-west-1> \
 -aws-secret-id=<secret name> \
 -socket /var/vcap/sys/run/credhub-kms-plugin/kms-plugin.sock \
 -public-key-file kms_server_cert.pem \
 -private-key-file kms_server_key.pem
```

# Switching between credhub providers
The interface between credhub and the kms-plugin does not pass the nonce that is used by the internal provider.  
This means that the plugin cannot decrypt values that were encrypted by the internal provider.  
Steps you can take to switch providers:
* first deploy the kms-plugin, but don't activate it yet (do not update the credhub configuration yet), this way you can test if the credhub-kms-plugin works since the credhub-kms-plugin-healthchecker will check it.
* store an encryption key (in either Azure keyvault or AWS Secrets Manager), and make sure it is 32 characters long
* make sure nobody else uses credhub (yes, this has impact on availability)
* create a credhub backup, just to be sure (you can make a mysqldump of the cf credhub database)
* run a credhub export, saving the output to a file that you can later use to import again (you do lose older entry **versions** though)
* stop all but one credhub instance
* delete all credhub entries: 
```bash
#! /bin/bash
#
for E in $(credhub export -p / | grep '\- name:' | awk '{print $NF}')
do
  credhub d -n $E
done
```
* stop the last credhub server
* bosh update-resurrection off
* bosh -d cf stop database/0 --no-converge
* bosh -d cf stop database/1 --no-converge
* on the cf database server:  ``delete from credential;delete from credential_version;delete from encrypted_value;delete from encryption_key_canary;`` (it looks like the encryption_key_canary is used during the startup of credhub, and it will fail when you first run with your credhub-kms-plugin while the table still contains that one row)
* update the credhub deployment so it starts using the kms plugin
* check credhub.log's for errors
* credhub import all the entries, using the yml file you created earlier
* bosh -d cf restart database/0 -n
* bosh -d cf restart database/1 -n
* bosh update-resurrection on
* test: ``cf cs credhub default credhub-plugin-test -c '{"testcredentialP":"testsecretP"}' && cf ds -f credhub-plugin-test``

## Building the BOSH release 

```
cd ~/workspace
git clone https://github.com/cloudfoundry/bosh-package-golang-release.git
git clone <this repo>
cd credhub-kms-plugin-boshrelease
bosh vendor-package golang-1.23-linux ../bosh-package-golang-release
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
        encryption_key_name: RequiredButNoClueWhy
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
     alternative_names:
       - localhost
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
# values for Azure:
        az-tenant-id: ((azure_tenant_id))
        az-keyvault-name: my-credhub-keyvault
        az-keyvault-secret-name: credhub-encryption-key
# values for AWS:
        aws-region: ((aws_region))
        aws_secret_id: my-credhub-secret
        private_key: ((credhub-kms-plugin.private_key))
        certificate: ((credhub-kms-plugin.certificate))
        mode: server

- type: replace
  path: /instance_groups/name=credhub/jobs/-
  value:
    name: credhub-kms-plugin-healthchecker
    release: credhub-kms-plugin
    properties:
      credhub-kms-plugin:
        socket_endpoint: /var/vcap/sys/run/credhub-kms-plugin/credhub-kms-plugin.sock
        private_key: ((credhub-kms-plugin.private_key))
        certificate: ((credhub-kms-plugin.certificate))
        client-healthcheck-interval : 60
        mode: client
```
