package main

import (
	"flag"
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
)

func main() {
	flag.StringVar(&pathToUnixSocket, "socket", "/tmp/credhub-kms.sock", "Path to the unix socket")
	flag.StringVar(&pathToPrivateKeyFile, "private-key-file", "private-key.pem", "Path to the private keyfile")
	flag.StringVar(&pathToPublicKeyFile, "public-key-file", "public-key.pem", "Path to the public keyfile")
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: time.RFC3339, PadLevelText: true})
	log.SetOutput(os.Stdout)

	p, err := plugin.New(pathToUnixSocket, pathToPublicKeyFile, pathToPrivateKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	p.Start()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals

	p.Stop()
}
