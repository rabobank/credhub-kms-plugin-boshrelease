package main

import (
	"flag"
	"github.com/rabobank/credhub-kms-plugin/az"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rabobank/credhub-kms-plugin/plugin"
)

var (
	pathToUnixSocket     string
	pathToPublicKeyFile  string
	pathToPrivateKeyFile string
	azTenantId           string
	azKeyvaultName       string
	azKeyvaultSecretName string
	awsSecretArn         string
	credhubEncryptionKey string
)

func main() {
	flag.StringVar(&pathToUnixSocket, "socket", "/tmp/credhub-kms.sock", "Path to the unix socket")
	flag.StringVar(&pathToPrivateKeyFile, "private-key-file", "private-key.pem", "Path to the private keyfile")
	flag.StringVar(&pathToPublicKeyFile, "public-key-file", "public-key.pem", "Path to the public keyfile")
	flag.StringVar(&azTenantId, "az-tenant-id", "", "Azure Tenant ID where the keyvault is located")
	flag.StringVar(&azKeyvaultName, "az-keyvault-name", "", "Name of the Azure keyvault that contains the credhub encryption key")
	flag.StringVar(&azKeyvaultSecretName, "az-keyvault-secret-name", "", "Name of the secret in the Azure keyvault that contains the credhub encryption key")
	flag.StringVar(&awsSecretArn, "aws-secret-arn", "", "ARN of the secret in AWS Secrets Manager that contains the credhub encryption key")
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: time.RFC3339, PadLevelText: true})
	log.SetOutput(os.Stdout)

	if azKeyvaultName == "" && awsSecretArn == "" {
		log.Fatal("az-keyvault-name or aws-secret-arn must be specified")
	}

	var initFailed = false
	if azKeyvaultName != "" {
		if azTenantId == "" {
			log.Error("az-tenant-id must be specified when using az-keyvault-name")
			initFailed = true
		}
		if azKeyvaultSecretName == "" {
			log.Error("az-keyvault-secret-name must be specified when using az-keyvault-name")
			initFailed = true
		}
		if initFailed {
			os.Exit(1)
		}
		var err error
		if credhubEncryptionKey, err = az.GetSecret(azTenantId, azKeyvaultName, azKeyvaultSecretName); err != nil {
			log.Fatalf("failed to get credhub encryption key from Azure keyvault %s: %v", azKeyvaultName, err)
		} else {
			log.Infof("got credhub encryption key from Azure keyvault %s", azKeyvaultName)
		}
		if err := os.Setenv("AZURE_TENANT_ID", azTenantId); err != nil {
			log.Fatalf("failed to set AZURE_TENANT_ID environment variable: %v", err)
		}
	}

	p, err := plugin.New(pathToUnixSocket, pathToPublicKeyFile, pathToPrivateKeyFile, credhubEncryptionKey)
	if err != nil {
		log.Fatal(err)
	}

	p.Start()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals

	p.Stop()
}
