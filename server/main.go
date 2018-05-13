package main

import (
	"log"

	// Other packages
	"github.com/jrolli/ca-proxy/ca/local"
)

func fatalError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type authorization struct {
	commonName     string
	alternateNames []string
	signature      []byte
}

type registration struct {
	authKey   string
	pubKey    []byte
	signature []byte
}

type renewal struct {
	oldCert   []byte
	pubKey    []byte
	signature []byte
}

type revokation struct {
	commonName string
	signature  []byte
}

func main() {
	log.Print("Initializing CA...")
	c, err := local.Initialize("ca.key", "ca.crt", "")

	cert, err := c.RootCert()
	fatalError(err)

	log.Print(cert)
}
