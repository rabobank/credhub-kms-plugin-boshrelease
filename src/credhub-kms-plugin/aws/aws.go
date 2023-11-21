package pluginaws

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

func GetSecrets(awsRegion, secretId string) (secretString *string, err error) {
	var awsSession *session.Session
	if awsSession, err = session.NewSession(&aws.Config{Region: aws.String(awsRegion)}); err != nil {
		return nil, errors.New(fmt.Sprintf("failed to get new AWS session: %s", err))
	} else {
		svc := secretsmanager.New(awsSession)
		input := &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretId)}
		var output *secretsmanager.GetSecretValueOutput
		if output, err = svc.GetSecretValue(input); err != nil {
			return nil, errors.New(fmt.Sprintf("failed to get secret from AWS %s: %v", secretId, err))
		} else {
			return output.SecretString, nil
		}
	}
}
