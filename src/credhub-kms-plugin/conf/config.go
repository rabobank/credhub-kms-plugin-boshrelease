package conf

var (
	Mode                 string
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
	PluginIsHealthy      = false
)

const (
	CurrentCloudProviderAzure = "AZURE"
	CurrentCloudProviderAWS   = "AWS"
)
