package pluginaws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

func GetSecret(awsRegion, secretId string) (string, error) {
	if awsSession, err := session.NewSession(&aws.Config{Region: aws.String(awsRegion)}); err != nil {
		return "", err
	} else {
		svc := secretsmanager.New(awsSession)
		input := &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretId)}
		if output, err := svc.GetSecretValue(input); err != nil {
			return "", err
		} else {
			return *output.SecretString, nil
		}
	}
}
