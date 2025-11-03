package pluginaws

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func GetSecrets(awsRegion, secretId string) (secretString *string, err error) {
	var awsConfig aws.Config
	ctx := context.TODO()
	if awsConfig, err = config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion)); err != nil {
		return nil, errors.New(fmt.Sprintf("failed to get new AWS session: %s", err))
	} else {
		svc := secretsmanager.NewFromConfig(awsConfig)
		input := &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretId)}
		var output *secretsmanager.GetSecretValueOutput
		if output, err = svc.GetSecretValue(ctx, input); err != nil {
			return nil, errors.New(fmt.Sprintf("failed to get secret from AWS %s: %v", secretId, err))
		} else {
			return output.SecretString, nil
		}
	}
}
