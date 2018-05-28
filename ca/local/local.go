// Package local provides a basic implementation for a minimal certificate
// authority implemented in Go.
package local

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	// Other packages
	"github.com/jrolli/SimpleCA/ca"
)

// TODO: Allow the control key to be distinct from the root key.

// Initialize takes the path to the data store for the CA and initializes
// all of the necessary structure.  It always returns a CertAuthorizer so
// it is important to check if there is an error during initializations.
func Initialize(dataStore, namespace string) (ca.CertAuthorizer, error) {
	c := localCa{nil, nil, dataStore, namespace}

	err := os.MkdirAll(dataStore, 0755)
	if err != nil {
		return nil, err
	}

	err = c.initializeCaKey(filepath.Join(dataStore, "ca.key"))
	if err != nil {
		return nil, err
	}

	err = c.initializeCaCert(filepath.Join(dataStore, "ca.crt"), namespace)
	if err != nil {
		return nil, err
	}

	// Make the directory for referencing certs by serial number (primary)
	err = os.MkdirAll(filepath.Join(dataStore, "serial"), 0755)
	if err != nil {
		return nil, err
	}

	// Symlink the CA's cert into the serial directory
	filename := c.caCert.SerialNumber.Text(16) + ".crt"
	filename = filepath.Join(dataStore, "serial", filename)
	err = os.Symlink("../ca.crt", filename)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}

	// Make the directory for referencing certs by common name (symlinks)
	err = os.MkdirAll(filepath.Join(dataStore, "common"), 0755)
	if err != nil {
		return nil, err
	}

	// Symlink the CA's cert into the common name directory
	filename = c.caCert.Subject.CommonName + ".crt"
	filename = filepath.Join(dataStore, "common", filename)
	err = os.Symlink("../ca.crt", filename)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}

	err = os.MkdirAll(filepath.Join(dataStore, "auths"), 0700)
	if err != nil {
		return nil, err
	}

	filename = filepath.Join(dataStore, "revocations.txt")
	err = ioutil.WriteFile(filename, []byte("\n"), 0644)
	if err != nil {
		return nil, err
	}

	return &c, c.updateCRL(true)
}

func (c *localCa) Authorize(names []string, sig []byte) ([]byte, error) {
	msg := []byte(strings.Join(names, "\n"))
	hasher := sha256.New()
	_, err := hasher.Write(msg)
	if err != nil {
		return nil, err
	}

	var digest []byte
	digest = hasher.Sum(digest)

	_, err = checkSignature(c.caKey.PublicKey, digest, sig)
	if err != nil {
		return nil, err
	}

	random := rand.Reader
	auth_max := big.NewInt((1 << 62) - 1)
	auth, err := rand.Int(random, auth_max)
	if err != nil {
		return nil, err
	}

	token := []byte(auth.Text(16))
	tokenPath := filepath.Join(c.dataStore, "auths", string(token)+".txt")
	err = ioutil.WriteFile(tokenPath, msg, 0644)

	return token, nil
}

func (c *localCa) Register(auth, pub, sig []byte) ([]byte, error) {
	hasher := sha256.New()
	msg := append(auth, []byte("\x00")...)
	msg = append(msg, pub...)
	_, err := hasher.Write(msg)
	if err != nil {
		return nil, err
	}

	var digest []byte
	digest = hasher.Sum(digest)

	pubKey := ecdsa.PublicKey{elliptic.P521(), nil, nil}
	x, y := elliptic.Unmarshal(pubKey.Curve, pub)
	if x == nil {
		return nil, err
	}
	pubKey.X = x
	pubKey.Y = y

	_, err = checkSignature(pubKey, digest, sig)
	if err != nil {
		return nil, err
	}

	return c.createCertificate(string(auth), pubKey)
}

func (c *localCa) Renew(oldCert, pub, sig []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (c *localCa) Revoke(s, sig []byte) error {
	hasher := sha256.New()
	_, err := hasher.Write(s)
	if err != nil {
		return err
	}

	var digest []byte
	digest = hasher.Sum(digest)

	_, err = checkSignature(c.caKey.PublicKey, digest, sig)
	if err != nil {
		return err
	}

	serial := new(big.Int)
	_, success := serial.SetString(string(s), 16)
	if !success {
		return errors.New("invalid serial (not hexadecimal)")
	}

	_, err = c.CertBySerial(*serial)
	if err != nil {
		return err
	}

	revocationsFile := filepath.Join(c.dataStore, "revocations.txt")
	f, err := os.OpenFile(revocationsFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644)
	defer f.Close()
	if err != nil {
		return err
	}
	_, err = f.WriteString(serial.Text(16) + "\n")
	if err != nil {
		return err
	}

	c.updateCRL(true)

	return nil
}

// Getters
func (c *localCa) CertBySerial(bi big.Int) ([]byte, error) {
	f := filepath.Join(c.dataStore, "serial", bi.Text(16)+".crt")
	return ioutil.ReadFile(f)
}

func (c *localCa) CertByName(name string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(c.dataStore, "common", name+".crt"))
}

func (c *localCa) RootCert() ([]byte, error) {
	if c.caCert == nil {
		return nil, errors.New("ca/local: unintialized ca")
	}
	return c.caCert.Raw, nil
}

func (c *localCa) CRL() ([]byte, error) {
	err := c.updateCRL(false)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadFile(filepath.Join(c.dataStore, "ca.crl"))
}
