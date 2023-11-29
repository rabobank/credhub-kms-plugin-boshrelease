package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/rabobank/credhub-kms-plugin/conf"
	"github.com/rabobank/credhub-kms-plugin/plugin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"os"
)

func RunClient() (err error) {
	socket := fmt.Sprintf("unix:%s", conf.PathToUnixSocket)
	log.Infof("starting client using %s and pub/priv cert %s/%s...", socket, conf.PathToPublicKeyFile, conf.PathToPrivateKeyFile)
	var tlsCredentials credentials.TransportCredentials
	if tlsCredentials, err = loadTLSCredentials(); err != nil {
		return errors.New(fmt.Sprintf("failed to load TLS credentials: %v", err))
	} else {
		var conn *grpc.ClientConn
		if conn, err = grpc.Dial(socket, grpc.WithTransportCredentials(tlsCredentials)); err != nil {
			return errors.New(fmt.Sprintf("failed to dial server: %v", err))
		} else {
			defer func() { _ = conn.Close() }()
			grpcClient := plugin.NewKeyManagementServiceClient(conn)
			message := plugin.EncryptRequest{Version: "1", Plain: []byte("Hello From the Client!")}
			var encryptResponse *plugin.EncryptResponse
			if encryptResponse, err = grpcClient.Encrypt(context.Background(), &message); err != nil {
				return errors.New(fmt.Sprintf("failed to encrypt: %v", err))
			} else {
				var decryptResponse *plugin.DecryptResponse
				decryptRequest := plugin.DecryptRequest{Version: "1", Cipher: encryptResponse.Cipher}
				if decryptResponse, err = grpcClient.Decrypt(context.Background(), &decryptRequest); err != nil {
					return errors.New(fmt.Sprintf("failed to decrypt: %v", err))
				} else {
					if string(decryptResponse.Plain) != string(message.Plain) {
						return errors.New(fmt.Sprintf("failed to decrypt: %v", err))
					} else {
						log.Infof("client successfully encrypted and decrypted message: %s", string(decryptResponse.Plain))
						if healthResponse, err := grpcClient.Health(context.Background(), &plugin.HealthRequest{}); err != nil || !healthResponse.Healthy {
							return errors.New(fmt.Sprintf("credhub-kms-plugin is not healthy, check the logs, restarting the plugin now might render it unavailable!"))
						}
					}
				}
			}
		}
		return err
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
