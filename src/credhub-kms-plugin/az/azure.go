package pluginazure

import (
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

func GetSecret(keyVaultName, secretName string) (string, error) {
	if cred, err := azidentity.NewDefaultAzureCredential(nil); err != nil {
		return "", errors.New(fmt.Sprintf("failed to obtain a default Azure credential: %v", err))
	} else {
		if client, err := azsecrets.NewClient(fmt.Sprintf("https://%s.vault.azure.net/", keyVaultName), cred, nil); err != nil {
			return "", errors.New(fmt.Sprintf("failed to create an azsecrets client: %v", err))
		} else {
			if resp, err := client.GetSecret(context.Background(), secretName, "", nil); err != nil {
				return "", errors.New(fmt.Sprintf("failed to get secret %s: %v", secretName, err))
			} else {
				return *resp.Value, nil
			}
		}
	}
}
