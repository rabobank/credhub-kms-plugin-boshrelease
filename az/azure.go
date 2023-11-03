package pluginazure

import (
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

func GetSecret(keyVaultName, secretName string) (string, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to obtain a default Azure credential: %v", err))
	}

	client, err := azsecrets.NewClient(fmt.Sprintf("https://%s.vault.azure.net/", keyVaultName), cred, nil)
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to create an azsecrets client: %v", err))
	}

	resp, err := client.GetSecret(context.Background(), secretName, "", nil)
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to get secret %s: %v", secretName, err))
	}

	return *resp.Value, nil
}
