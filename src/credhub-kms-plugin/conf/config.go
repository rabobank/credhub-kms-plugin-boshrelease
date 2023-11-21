package conf

var (
	PathToUnixSocket     string
	PathToPublicKeyFile  string
	PathToPrivateKeyFile string
	AzTenantId           string
	AzClientId           string
	AzKeyvaultName       string
	AzKeyvaultSecretName string
	AwsRegion            string
	AwsSecretId          string
	CurrentCloudProvider = "MISSING"
)

const (
	CurrentCloudProviderAzure = "AZURE"
	CurrentCloudProviderAWS   = "AWS"
)
