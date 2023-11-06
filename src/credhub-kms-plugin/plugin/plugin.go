package plugin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"google.golang.org/grpc/credentials"
	"io"
	"net"
	"os"
	"strings"

	pb "github.com/rabobank/credhub-kms-plugin/v1beta1"
	log "github.com/sirupsen/logrus"

	"golang.org/x/net/context"
	"golang.org/x/sys/unix"

	"google.golang.org/grpc"
)

const (
	netProtocol    = "unix"
	apiVersion     = "v1beta1"
	runtime        = "CredHub KMS Plugin"
	runtimeVersion = "0.0.1"
)

type Plugin struct {
	pathToUnixSocket     string
	pathToPublicKeyFile  string
	pathToPrivateKeyFile string
	credhubEncryptionKey string
	net.Listener
	*grpc.Server
}

func New(pathToUnixSocketFile string, publicKeyFile string, privateKeyFile string, credhubEncryptionKey string) (*Plugin, error) {
	plgin := new(Plugin)
	plgin.pathToUnixSocket = pathToUnixSocketFile
	plgin.pathToPublicKeyFile = publicKeyFile
	plgin.pathToPrivateKeyFile = privateKeyFile
	plgin.credhubEncryptionKey = credhubEncryptionKey
	return plgin, nil
}

func (g *Plugin) Start() {
	if err := g.cleanSockFile(); err != nil {
		log.Fatalf("failed to cleanSockFile %s, error: %v", g.pathToUnixSocket, err)
	}

	listener, err := net.Listen(netProtocol, g.pathToUnixSocket)
	if err != nil {
		log.Fatalf("failed to start listener on %s: %v", g.pathToUnixSocket, err)
	}
	g.Listener = listener
	log.Warningf("listening on unix domain socket: %s, using publicKeyFile %s and privateKeyfile %s", g.pathToUnixSocket, g.pathToPublicKeyFile, g.pathToPrivateKeyFile)

	creds, err := credentials.NewServerTLSFromFile(g.pathToPublicKeyFile, g.pathToPrivateKeyFile)
	if err != nil {
		log.Fatalf("failed to NewServerTLSFromFile, pubKeyFile: %s, privKeyFile: %s, error: %v", g.pathToPublicKeyFile, g.pathToPrivateKeyFile, err)
	}
	g.Server = grpc.NewServer(grpc.Creds(creds))
	pb.RegisterKeyManagementServiceServer(g.Server, g)
	if err = g.Serve(g.Listener); err != nil {
		log.Fatalf("failed to serve gRPC, %v", err)
	}
	log.Warnf("serving gRPC on %s", g.pathToUnixSocket)
}

func (g *Plugin) Stop() {
	if g.Server != nil {
		g.Server.Stop()
	}

	if g.Listener != nil {
		_ = g.Listener.Close()
	}
	log.Infof("stopped gRPC server")
}

func (g *Plugin) Version(ctx context.Context, request *pb.VersionRequest) (*pb.VersionResponse, error) {
	log.Infof("version rpc was called with version %s and context: %v", request.Version, ctx)
	return &pb.VersionResponse{Version: apiVersion, RuntimeName: runtime, RuntimeVersion: runtimeVersion}, nil
}

func (g *Plugin) Encrypt(ctx context.Context, request *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	_ = ctx // get rid of compile warnings
	log.Infof("encrypting, plaintext length: %d", len(request.Plain))
	response, err := encryptBytes(request.Plain, g.credhubEncryptionKey)
	if err != nil {
		log.Errorf("failed to encrypt, plaint text length %d, error: %v", len(request.Plain), err)
		return nil, err
	}
	return &pb.EncryptResponse{Cipher: []byte(response)}, nil
}

func (g *Plugin) Decrypt(ctx context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	_ = ctx // get rid of compile warnings
	log.Infof("decrypting, cipher length: %d", len(request.Cipher))
	plainText, err := decryptBytes(request.Cipher, g.credhubEncryptionKey)
	if err != nil {
		log.Errorf("failed to decrypt, plaint text length %d, error: %v", len(request.Cipher), err)
		return nil, err
	}
	return &pb.DecryptResponse{Plain: []byte(plainText)}, nil
}

func (g *Plugin) cleanSockFile() error {
	if strings.HasPrefix(g.pathToUnixSocket, "@") {
		return nil
	}
	err := unix.Unlink(g.pathToUnixSocket)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete the socket file, error: %v", err)
	}
	return nil
}

func encryptBytes(bytesToEncrypt []byte, encryptKey string) (string, error) {
	var encryptedString string
	if len(bytesToEncrypt) == 0 {
		return "", nil
	}
	key, _ := hex.DecodeString(hex.EncodeToString([]byte(encryptKey)))

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return encryptedString, err
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode  https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return encryptedString, err
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return encryptedString, err
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, bytesToEncrypt, nil)
	encryptedString = fmt.Sprintf("%x", ciphertext)
	return encryptedString, nil
}

func decryptBytes(encryptedBytes []byte, encryptKey string) (string, error) {
	var decryptedString string
	if len(encryptedBytes) == 0 {
		return "", nil
	}
	key, _ := hex.DecodeString(hex.EncodeToString([]byte(encryptKey)))
	enc, _ := hex.DecodeString(string(encryptedBytes))

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return decryptedString, err
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return decryptedString, err
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	if nonceSize > len(enc) {
		return "", errors.New(fmt.Sprintf("invalid encrypted string, size (%d) is smaller than the nonce size (%d)", nonceSize, len(enc)))
	}
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return decryptedString, err
	}

	decryptedString = fmt.Sprintf("%s", plaintext)
	return decryptedString, nil
}