package plugin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	pluginaws "github.com/rabobank/credhub-kms-plugin/aws"
	pluginazure "github.com/rabobank/credhub-kms-plugin/az"
	"github.com/rabobank/credhub-kms-plugin/conf"
	pb "github.com/rabobank/credhub-kms-plugin/v1beta1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/sys/unix"

	"google.golang.org/grpc"
)

const (
	netProtocol    = "unix"
	apiVersion     = "v1beta1"
	runtime        = "CredHub KMS Plugin"
	runtimeVersion = "0.0.1"
	DateFormat     = "2006-01-02 15:04"
)

var CurrentKeySet *EncryptionKeySet

type PluginTime time.Time

func (c *PluginTime) Format() string {
	return time.Time(*c).Format(DateFormat)
}

func (c *PluginTime) UnmarshalJSON(b []byte) error {
	if t, err := time.Parse(DateFormat, strings.Trim(string(b), `"`)); err != nil {
		return err
	} else {
		*c = PluginTime(t)
		return nil
	}
}

type EncryptionKeySet struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	Name   string     `json:"name"`
	Value  string     `json:"value"`
	Active bool       `json:"active"`
	Date   PluginTime `json:"date"`
}

func (ks *EncryptionKeySet) String() string {
	var returnString string
	for _, key := range ks.Keys {
		returnString = fmt.Sprintf("%s {name:%s, active=%t, date=%s}", returnString, key.Name, key.Active, key.Date.Format())
	}
	return returnString
}

func (ks *EncryptionKeySet) GetCurrentKeyValue() string {
	//log.Infof("get current key value, number of keys: %d", len(ks.Keys))
	for ix, key := range ks.Keys {
		if key.Active {
			log.Infof("returning key(%d) %s", ix, key.Name)
			return key.Value
		}
	}
	return ""
}

func LoadFromProvider() (err error) {
	var secretString *string
	if conf.CurrentCloudProvider == conf.CurrentCloudProviderAzure {
		secretString, err = pluginazure.GetSecrets(conf.AzKeyvaultName, conf.AzKeyvaultSecretName)
		//log.Warningf("loaded encryption keyset from provider: %s", *secretString)
	} else if conf.CurrentCloudProvider == conf.CurrentCloudProviderAWS {
		secretString, err = pluginaws.GetSecrets(conf.AwsRegion, conf.AwsSecretId)
	}
	if err = json.Unmarshal([]byte(*secretString), &CurrentKeySet); err == nil {
		log.Infof("load encryption keyset from provider: %s", CurrentKeySet.String())
	}
	return err
}

type Plugin struct {
	pathToUnixSocket     string
	pathToPublicKeyFile  string
	pathToPrivateKeyFile string
	net.Listener
	*grpc.Server
}

func NewPlugin(pathToUnixSocketFile string, publicKeyFile string, privateKeyFile string) (*Plugin, error) {
	plgin := new(Plugin)
	plgin.pathToUnixSocket = pathToUnixSocketFile
	plgin.pathToPublicKeyFile = publicKeyFile
	plgin.pathToPrivateKeyFile = privateKeyFile
	return plgin, nil
}

func (plgin *Plugin) Start() {
	if err := plgin.cleanSockFile(); err != nil {
		log.Fatalf("failed to cleanSockFile %s, error: %v", plgin.pathToUnixSocket, err)
	}

	listener, err := net.Listen(netProtocol, plgin.pathToUnixSocket)
	if err != nil {
		log.Fatalf("failed to start listener on %s: %v", plgin.pathToUnixSocket, err)
	}
	plgin.Listener = listener
	log.Warningf("listening on unix domain socket: %s, using publicKeyFile %s and privateKeyfile %s", plgin.pathToUnixSocket, plgin.pathToPublicKeyFile, plgin.pathToPrivateKeyFile)

	creds, err := credentials.NewServerTLSFromFile(plgin.pathToPublicKeyFile, plgin.pathToPrivateKeyFile)
	if err != nil {
		log.Fatalf("failed to NewServerTLSFromFile, pubKeyFile: %s, privKeyFile: %s, error: %v", plgin.pathToPublicKeyFile, plgin.pathToPrivateKeyFile, err)
	}
	plgin.Server = grpc.NewServer(grpc.Creds(creds))
	pb.RegisterKeyManagementServiceServer(plgin.Server, plgin)
	if err = plgin.Serve(plgin.Listener); err != nil {
		log.Fatalf("failed to serve gRPC, %v", err)
	}
	log.Warnf("serving gRPC on %s", plgin.pathToUnixSocket)
}

func (plgin *Plugin) Stop() {
	if plgin.Server != nil {
		plgin.Server.Stop()
	}

	if plgin.Listener != nil {
		_ = plgin.Listener.Close()
	}
	log.Infof("stopped gRPC server")
}

func (plgin *Plugin) Version(ctx context.Context, request *pb.VersionRequest) (*pb.VersionResponse, error) {
	log.Infof("version rpc was called with version %s and context: %v", request.Version, ctx)
	return &pb.VersionResponse{Version: apiVersion, RuntimeName: runtime, RuntimeVersion: runtimeVersion}, nil
}

func (plgin *Plugin) Encrypt(ctx context.Context, request *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	_ = ctx // get rid of compile warnings
	log.Infof("encrypting, plaintext length: %d", len(request.Plain))

	//Create a new Cipher Block from the key
	if block, err := aes.NewCipher([]byte(CurrentKeySet.GetCurrentKeyValue())); err != nil {
		log.Errorf("failed to create new cipher block: %v", err)
		return nil, err
	} else {
		//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode  https://golang.org/pkg/crypto/cipher/#NewGCM
		var aesGCM cipher.AEAD
		if aesGCM, err = cipher.NewGCM(block); err != nil {
			return nil, err
		} else {
			nonce := make([]byte, aesGCM.NonceSize())
			if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
				return nil, err
			} else {
				//Encrypt the data using aesGCM.Seal
				//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
				ciphertext := aesGCM.Seal(nonce, nonce, request.Plain, nil)
				return &pb.EncryptResponse{Cipher: ciphertext}, nil
			}
		}
	}
}

func (plgin *Plugin) Decrypt(ctx context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	_ = ctx // get rid of compile warnings
	var decryptedBytes []byte
	log.Infof("decrypting, cipher length: %d", len(request.Cipher))

	if len(request.Cipher) == 0 {
		return &pb.DecryptResponse{Plain: decryptedBytes}, nil
	}

	//Create a new Cipher Block from the key
	if block, err := aes.NewCipher([]byte(CurrentKeySet.GetCurrentKeyValue())); err != nil {
		log.Errorf("failed to create new cipher block: %v", err)
		return nil, err
	} else {
		//Create a new GCM
		var aesGCM cipher.AEAD
		if aesGCM, err = cipher.NewGCM(block); err != nil {
			return nil, err
		} else {
			nonceSize := aesGCM.NonceSize()
			//Extract the nonce from the encrypted data
			if nonceSize > len(request.Cipher) {
				return nil, errors.New(fmt.Sprintf("invalid encrypted string, size (%d) is smaller than the nonce size (%d)", nonceSize, len(request.Cipher)))
			}
			nonce, ciphertext := request.Cipher[:nonceSize], request.Cipher[nonceSize:]
			//Decrypt the data
			if decryptedBytes, err = aesGCM.Open(nil, nonce, ciphertext, nil); err != nil {
				return nil, errors.New(fmt.Sprintf("failed to decrypt: %s", err))
			} else {
				return &pb.DecryptResponse{Plain: decryptedBytes}, nil
			}
		}
	}
}

func (plgin *Plugin) cleanSockFile() error {
	if strings.HasPrefix(plgin.pathToUnixSocket, "@") {
		return nil
	}
	if err := unix.Unlink(plgin.pathToUnixSocket); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete the socket file, error: %v", err)
	}
	return nil
}
