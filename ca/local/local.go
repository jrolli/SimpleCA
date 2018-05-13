// Package local provides a basic implementation for a minimal certificate
// authority implemented in Go.
package local

import (
	// "errors"

	// Other packages
	"github.com/jrolli/ca-proxy/ca"
)

// Initialize takes the paths for the DER-encoded private key and
// certificate files for the CA and sets the package-level variables
// for all future calls to the CA package.  Any IO or parsing errors
// are passed through back to the caller.
func Initialize(rootKeyFile, rootKeyCert, dataStore string) (ca.CertAuthorizer, error) {
	c := localCa{nil, nil, ""}
	err := c.initializeCaKey(rootKeyFile)
	if err != nil {
		return nil, err
	}

	err = c.initializeCaCert(rootKeyCert)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// func Load

// Authorize takes the names authorized for the cert and a signature by
// the control key over those names.  The registration key (long string)
// is returned
func (c *localCa) Authorize(names []string, sig []byte) ([]byte, error) {
	return nil, nil
}

func (c *localCa) Register(auth, pub, sig []byte) ([]byte, error) {
	return nil, nil
}

func (c *localCa) Renew(oldCert, pub, sig []byte) ([]byte, error) {
	return nil, nil
}

//
func (c *localCa) Revoke(serial, sig []byte) error {
	return nil
}

// CaCert returns a slice representation of the root CA certificate
// or an error if the CA has not been initialized.
func (c *localCa) RootCert() ([]byte, error) {
	return c.caCert, nil
}
