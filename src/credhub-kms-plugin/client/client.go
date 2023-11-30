package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/rabobank/credhub-kms-plugin/conf"
	"github.com/rabobank/credhub-kms-plugin/v1beta1"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"os"
	"time"
)

func RunClient() (err error) {
	socket := fmt.Sprintf("unix:%s", conf.PathToUnixSocket)
	log.Infof("starting client using %s and pub/priv cert %s/%s...", socket, conf.PathToPublicKeyFile, conf.PathToPrivateKeyFile)
	var tlsCredentials credentials.TransportCredentials
	for {
		time.Sleep(time.Duration(conf.ClientHealthCheckInterval) * time.Second)
		if tlsCredentials, err = loadTLSCredentials(); err != nil {
			return errors.New(fmt.Sprintf("failed to load TLS credentials: %v", err))
		} else {
			var conn *grpc.ClientConn
			if conn, err = grpc.Dial(socket, grpc.WithTransportCredentials(tlsCredentials)); err != nil {
				return errors.New(fmt.Sprintf("failed to dial server: %v", err))
			} else {
				defer func() { _ = conn.Close() }()
				grpcClient := v1beta1.NewKeyManagementServiceClient(conn)
				message := v1beta1.EncryptRequest{Version: "1", Plain: []byte(" Encryption Test Message From Client! ")}
				var encryptResponse *v1beta1.EncryptResponse
				if encryptResponse, err = grpcClient.Encrypt(context.Background(), &message); err != nil {
					return errors.New(fmt.Sprintf("failed to encrypt: %v", err))
				} else {
					var decryptResponse *v1beta1.DecryptResponse
					decryptRequest := v1beta1.DecryptRequest{Version: "1", Cipher: encryptResponse.Cipher}
					if decryptResponse, err = grpcClient.Decrypt(context.Background(), &decryptRequest); err != nil {
						return errors.New(fmt.Sprintf("failed to decrypt: %v", err))
					} else {
						if string(decryptResponse.Plain) != string(message.Plain) {
							return errors.New(fmt.Sprintf("failed to decrypt: %v", err))
						} else {
							if healthResponse, err := grpcClient.Health(context.Background(), &v1beta1.HealthRequest{}); err != nil || !healthResponse.Healthy {
								return errors.New(fmt.Sprintf("credhub-kms-plugin is not healthy, check the logs, restarting the plugin now might render it unavailable!"))
							} else {
								log.Info("healthcheck client successfully encrypted and decrypted a test message, encryptionKeySet also still valid")
							}
						}
					}
				}
			}
		}
	}
}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	if pemServerCA, err := os.ReadFile(conf.PathToPublicKeyFile); err != nil {
		return nil, err
	} else {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(pemServerCA) {
			return nil, fmt.Errorf("failed to add server certificate")
		}
		config := &tls.Config{RootCAs: certPool}
		return credentials.NewTLS(config), nil
	}
}
