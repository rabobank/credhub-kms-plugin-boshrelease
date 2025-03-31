module github.com/rabobank/credhub-kms-plugin

go 1.23.0

toolchain go1.23.6

replace (
	github.com/golang-jwt/jwt/v5 => github.com/golang-jwt/jwt/v5 v5.2.2
	golang.org/x/net => golang.org/x/net v0.38.0
	google.golang.org/protobuf => google.golang.org/protobuf v1.36.6
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.8.2
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets v0.12.0
	github.com/aws/aws-sdk-go v1.55.6
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/net v0.38.0
	golang.org/x/sys v0.31.0
	google.golang.org/grpc v1.71.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.17.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.10.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/internal v0.7.1 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.4.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250324211829-b45e905df463 // indirect
)
