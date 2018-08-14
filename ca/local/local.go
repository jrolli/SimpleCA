// Copyright (C) 2018  John E. Rollinson <j.e.rollinson@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package local provides a basic implementation for a minimal certificate
// authority implemented in Go.
package local

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
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
// all of the necessary structure.
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

// Authorize takes the names authorized for the cert and a signature by
// the control key over those names.  The function returns a byte-string
// that is signed by the new public key as proof of authorization in the
// 'Register' function.
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

	for _, name := range names {
		nsLen := len(c.namespace) + 1
		if len(name) <= nsLen || name[len(name)-nsLen:] != "."+c.namespace {
			return nil, errors.New(fmt.Sprintf("'%s' not in namespace of '%s'", name, c.namespace))
		}
		if strings.IndexFunc(name, unsafeChar) != -1 {
			return nil, errors.New("Unsafe character in names")
		}
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

// Register takes the authorization byte-string, the public key for the
// new certificate, and the signature of the authorization string using
// the new private-key and returns the new certificate.  The server must
// validate both the authorization token (valid and not used) and the
// signature (corresponds to the presented public key).
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

// Renew uses an existing certificate to get a new certificate for the
// same domain names.  The private key of the old certificate is used to
// sign the new public key.  The server is able to validate the signature
// and authorized domain names by using the serial to look it up in its
// local database.  Upon granting the new certificate, the server must
// revoke the old certificate. [NOT IMPLEMENTED]
func (c *localCa) Renew(oldCert, pub, sig []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// Revoke uses the control key to revoke an existing certificate by its
// serial in hex format.  The server must validate the signature of the
// control key before revoking the certificate.
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

// CertBySerial returns the DER encoded certificate with the matching
// serial number.  Returns an appropriate error if it is invalid,
// expired, or non-existent.
CertBySerial(big.Int) ([]byte, e
func (c *localCa) CertBySerial(bi big.Int) ([]byte, error) {
	f := filepath.Join(c.dataStore, "serial", bi.Text(16)+".crt")
	return ioutil.ReadFile(f)
}

// CertByName returns the DER encoded certificate with the matching
// common name.  Returns an appropriate error if it is invalid, expired,
// or non-existent.
func (c *localCa) CertByName(name string) ([]byte, error) {
	if strings.Index(name, string(filepath.Separator)) >= 0 {
		return nil, errors.New("ca/local: forbidden character")
	}
	return ioutil.ReadFile(filepath.Join(c.dataStore, "common", name+".crt"))
}

// RootCert returns the root certificate in DER encoding.
func (c *localCa) RootCert() ([]byte, error) {
	if c.caCert == nil {
		return nil, errors.New("ca/local: unintialized ca")
	}
	return c.caCert.Raw, nil
}

// CRL returns a CRL that is currently valid.
func (c *localCa) CRL() ([]byte, error) {
	err := c.updateCRL(false)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadFile(filepath.Join(c.dataStore, "ca.crl"))
}
