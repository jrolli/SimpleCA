// Package local provides a basic implementation for a minimal certificate
// authority implemented in Go.
package local

import (
	"errors"

	"math/big"

	// Other packages
	"github.com/jrolli/ca-proxy/ca"
)

// TODO: Allow the control key to be distinct from the root key.

// Initialize takes the path to the data store for the CA and initializes
// all of the necessary structure.  It always returns a CertAuthorizer so
// it is important to check if there is an error during initializations.
func Initialize(dataStore string) (ca.CertAuthorizer, error) {
	c := localCa{nil, nil, ""}
	return &c, c.initializeLocalCa(dataStore)
}

func (c *localCa) Authorize(names []string, sig []byte) ([]byte, error) {
	return nil, errors.New("Not implemented")
}

func (c *localCa) Register(auth, pub, sig []byte) ([]byte, error) {
	return nil, errors.New("Not implemented")
}

func (c *localCa) Renew(oldCert, pub, sig []byte) ([]byte, error) {
	return nil, errors.New("Not implemented")
}

func (c *localCa) Revoke(serial, sig []byte) error {
	return c.revokeSerial(serial, sig)
}

// Getters
func (c *localCa) CertBySerial(bi big.Int) ([]byte, error) {
	return c.getCertBySerial(bi)
}

func (c *localCa) CertByName(name string) ([]byte, error) {
	return c.getCertByName(name)
}

func (c *localCa) RootCert() ([]byte, error) {
	if c.caCert == nil {
		return nil, errors.New("ca/local: unintialized ca")
	}
	return c.caCert.Raw, nil
}

func (c *localCa) CRL() ([]byte, error) {
	return c.getCRL()
}
