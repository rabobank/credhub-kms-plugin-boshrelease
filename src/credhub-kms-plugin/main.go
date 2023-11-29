package main

import (
	"flag"
	"github.com/rabobank/credhub-kms-plugin/client"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rabobank/credhub-kms-plugin/conf"
	"github.com/rabobank/credhub-kms-plugin/plugin"
)

func main() {
	flag.StringVar(&conf.Mode, "mode", "server", "The mode in which to run, either 'server' or 'client'")
	flag.StringVar(&conf.PathToUnixSocket, "socket", "/tmp/credhub-kms.sock", "Path to the unix socket")
	flag.StringVar(&conf.PathToPrivateKeyFile, "private-key-file", "private-key.pem", "Path to the private keyfile")
	flag.StringVar(&conf.PathToPublicKeyFile, "public-key-file", "public-key.pem", "Path to the public keyfile")
	flag.StringVar(&conf.AzTenantId, "az-tenant-id", "", "Azure Tenant ID where the keyvault is located")
	flag.StringVar(&conf.AzClientId, "az-client-id", "", "Azure Client ID, can be the ID of a Managed Identity or the ID of a Service Principal")
	flag.StringVar(&conf.AzKeyvaultName, "az-keyvault-name", "", "Name of the Azure keyvault that contains the credhub encryption key")
	flag.StringVar(&conf.AzKeyvaultSecretName, "az-keyvault-secret-name", "", "Name of the secret in the Azure keyvault that contains the credhub encryption key")
	flag.StringVar(&conf.AwsSecretId, "aws-secret-id", "", "Name or full ARN of the secret in AWS Secrets Manager that contains the credhub encryption key")
	flag.StringVar(&conf.AwsRegion, "aws-region", "eu-west-1", "AWS region where the secret is located")
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: time.RFC3339, PadLevelText: true})
	log.SetOutput(os.Stdout)

	var initFailed = false
	if conf.Mode == "server" {
		if (conf.AzKeyvaultName == "" && conf.AwsSecretId == "") || (conf.AzKeyvaultName != "" && conf.AwsSecretId != "") {
			log.Fatal("az-keyvault-name OR aws-secret-id must be specified")
		}
		if conf.AzKeyvaultName != "" {
			if conf.AzTenantId == "" {
				log.Error("az-tenant-id must be specified when using az-keyvault-name")
				initFailed = true
			}
			if conf.AzKeyvaultSecretName == "" {
				log.Error("az-keyvault-secret-name must be specified when using az-keyvault-name")
				initFailed = true
			}
			if initFailed {
				os.Exit(1)
			}
			var err error
			if err = os.Setenv("AZURE_TENANT_ID", conf.AzTenantId); err != nil {
				log.Fatalf("failed to set AZURE_TENANT_ID environment variable: %v", err)
			}
			if conf.AzClientId != "" {
				if err = os.Setenv("AZURE_CLIENT_ID", conf.AzClientId); err != nil {
					log.Fatalf("failed to set AZURE_CLIENT_ID environment variable: %v", err)
				}
			}
			conf.CurrentCloudProvider = conf.CurrentCloudProviderAzure
		}

		if conf.AwsSecretId != "" {
			if conf.AwsRegion == "" {
				log.Fatal("aws-region must be specified when using aws-secret-id")
			}
			conf.CurrentCloudProvider = conf.CurrentCloudProviderAWS
		}

		if plgin, err := plugin.NewPlugin(conf.PathToUnixSocket, conf.PathToPublicKeyFile, conf.PathToPrivateKeyFile); err != nil {
			log.Fatal(err)
		} else {
			plugin.CurrentKeySet = new(plugin.EncryptionKeySet)
			if err = plugin.LoadFromProvider(); err != nil {
				log.Fatalf("failed to load the encryption key set from provider: %v", err)
			} else {
				conf.PluginIsHealthy = true
			}

			go func() {
				plgin.Start()
			}()

			go func() {
				for {
					time.Sleep(30 * time.Minute)
					if err = plugin.LoadFromProvider(); err != nil {
						log.Errorf("failed to reload the encryption key set from provider: %v", err)
						conf.PluginIsHealthy = false
					} else {
						conf.PluginIsHealthy = true
					}
				}
			}()

			signals := make(chan os.Signal, 1)
			signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
			log.Info("waiting for OS signals...")
			<-signals
			log.Info("signal received, stopping plugin...")

			plgin.Stop()
		}
	} else if conf.Mode == "client" {
		if err := client.RunClient(); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatalf("invalid mode '%s', must be either 'server' or 'client'", conf.Mode)
	}
}
