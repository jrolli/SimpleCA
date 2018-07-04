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

package local

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// marshalPublicKey is a helper function for passing the ECDSA public key
// parameters to the existing marshal function for elliptic curves.
func marshalPublicKey(pub ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func unsafeChar(r rune) bool {
	return !((r >= '0' && r <= '9') ||
		(r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		r == '.' || r == '@')
}

// There is some kind of bug in the Go's x509 code that causes this to fail
type ecdsaSignature struct {
	R, S *big.Int
}

func checkSignature(pub ecdsa.PublicKey, msg, sig []byte) (bool, error) {
	ecdsaSig := new(ecdsaSignature)
	_, err := asn1.Unmarshal(sig, ecdsaSig)
	if err != nil {
		return false, err
	}

	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
		return false, errors.New("invalid signature paramaters")
	}

	if !ecdsa.Verify(&pub, msg, ecdsaSig.R, ecdsaSig.S) {
		return false, errors.New("invalid signature")
	}

	return true, nil
}

// localCa holds the data required for keeping state on a CA that is directly
// controlled by the server.  The struct is for internal use but implements
// the CertAuthorizer interface via the public functions in 'local.go'
type localCa struct {
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	dataStore string
	namespace string
}

// initializeCaKey attempts to load the CA's key from the filesystem and
// generates a new one if the file does not exist.
func (c *localCa) initializeCaKey(key string) error {
	privKey, err := ioutil.ReadFile(key)
	switch err.(type) {
	case (*os.PathError):
		// passthrough
	case nil:
		c.caKey, err = x509.ParseECPrivateKey(privKey)
		return err
	default:
		return err
	}

	random := rand.Reader
	curv := elliptic.P521()
	priv, err := ecdsa.GenerateKey(curv, random)
	if err != nil {
		return err
	}
	c.caKey = priv
	privKey, err = x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(key, privKey, 0400)
}

// initializeCaCert attempts to load the CA's certificate from the filesystem
// and generates a new one if the file does not exist.  This must be called
// after 'initializeCaKey'.
func (c *localCa) initializeCaCert(cert, namespace string) error {
	der, err := ioutil.ReadFile(cert)
	switch err.(type) {
	case (*os.PathError):
		// passthrough
	case nil:
		caCert, err := x509.ParseCertificate(der)
		c.caCert = caCert
		return err
	default:
		return err
	}

	random := rand.Reader

	subject := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"RolliNix"},
		OrganizationalUnit: []string{"VPN Certificates"},
		// Locality:,
		// Province:,
		// StreetAddress:,
		// PostalCode:,
		// SerialNumber:,
		CommonName: "ca." + namespace,
		// Names:,
		// ExtraNames:,
	}

	keyId := sha256.Sum256(marshalPublicKey(c.caKey.PublicKey))
	sn_max := big.NewInt((1 << 30) - 1)

	serial, err := rand.Int(random, sn_max)
	if err != nil {
		return err
	}

	metaCert := &x509.Certificate{
		// AuthorityKeyId:,
		BasicConstraintsValid: true,
		// DNSNames:,
		// ExcludedDNSDomains:,
		// ExtKeyUsage:,
		IsCA:                        true,
		KeyUsage:                    x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		MaxPathLen:                  2,
		MaxPathLenZero:              false,
		NotAfter:                    time.Now().AddDate(10, 0, 7),
		NotBefore:                   time.Now(),
		PermittedDNSDomains:         []string{namespace},
		PermittedDNSDomainsCritical: true,
		SerialNumber:                serial,
		// SignatureAlgorithm:,
		Subject:      subject,
		SubjectKeyId: keyId[:],
		// UnknownExtKeyUsage:,
	}

	der, err = x509.CreateCertificate(random, metaCert, metaCert, c.caKey.Public(), c.caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(der)
	c.caCert = caCert
	if err != nil {
		return err
	}
	return ioutil.WriteFile(cert, der, 0644)
}

func (c localCa) updateCRL(forced bool) error {
	crlData, err := ioutil.ReadFile(filepath.Join(c.dataStore, "ca.crl"))
	if err == nil || forced {
		crl, err := x509.ParseCRL(crlData)
		if err == nil {
			if c.caCert.CheckCRLSignature(crl) == nil {
				if !crl.HasExpired(time.Now().Add(time.Hour)) {
					return nil
				} // HasExpired
			} // CheckCRLSignature
		} // ParseCRL
	} // ReadFile

	revokedFile := filepath.Join(c.dataStore, "revocations.txt")
	revokedRaw, err := ioutil.ReadFile(revokedFile)
	if err != nil {
		if os.IsNotExist(err) {
			revokedRaw = []byte("")
		} else {
			return err
		}
	}

	start := time.Now()
	revokedStr := strings.Split(string(revokedRaw), "\n")
	revSer := make([]pkix.RevokedCertificate, 0, len(revokedStr))
	for _, s := range revokedStr {
		if s == "" {
			continue
		}
		bi := new(big.Int)
		var rc pkix.RevokedCertificate
		var success bool
		rc.SerialNumber, success = bi.SetString(s, 16)
		if !success {
			return errors.New("invalid serial (not hexadecimal)")
		}
		rc.RevocationTime = start.Add(-time.Minute)
		rc.Extensions = nil
		revSer = append(revSer, rc)
	}

	expiry := start.Add(time.Minute)
	crlData, err = c.caCert.CreateCRL(
		rand.Reader,
		c.caKey,
		revSer,
		start,
		expiry)
	if err != nil {
		return err
	}

	filename := filepath.Join(c.dataStore, "ca.crl")
	return ioutil.WriteFile(filename, crlData, 0644)
}

func (c localCa) createCertificate(auth string, pub ecdsa.PublicKey) ([]byte, error) {
	authFile := filepath.Join(c.dataStore, "auths", auth+".txt")
	rawNames, err := ioutil.ReadFile(authFile)
	if err != nil {
		return nil, err
	}
	// Authorization has been used, fail closed
	os.Remove(authFile)

	names := strings.Split(string(rawNames), "\n")

	random := rand.Reader
	subject := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"RolliNix"},
		OrganizationalUnit: []string{"VPN Certificates"},
		// Locality:,
		// Province:,
		// StreetAddress:,
		// PostalCode:,
		// SerialNumber:,
		CommonName: names[0],
		// Names:,
		// ExtraNames:,
	}

	keyId := sha256.Sum256(marshalPublicKey(pub))
	sn_max := big.NewInt((1 << 30) - 1)

	serial, err := rand.Int(random, sn_max)
	if err != nil {
		return nil, err
	}

	keyUse := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	extKeyUse := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageIPSECUser}
	metaCert := &x509.Certificate{
		BasicConstraintsValid: false,
		DNSNames:              names,
		ExtKeyUsage:           extKeyUse,
		IsCA:                  false,
		KeyUsage:              keyUse,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
		NotAfter:              time.Now().AddDate(1, 0, 7),
		NotBefore:             time.Now(),
		SerialNumber:          serial,
		Subject:               subject,
		SubjectKeyId:          keyId[:],
	}

	cert, err := x509.CreateCertificate(rand.Reader, metaCert, c.caCert, &pub, c.caKey)
	if err != nil {
		return nil, err
	}

	serialFile := filepath.Join(c.dataStore, "serial", serial.Text(16)+".crt")
	serialLink := filepath.Join("..", "serial", serial.Text(16)+".crt")
	commonFile := filepath.Join(c.dataStore, "common", names[0]+".crt")

	err = ioutil.WriteFile(serialFile, cert, 0644)
	if err != nil {
		return nil, err
	}

	err = os.Symlink(serialLink, commonFile)
	if err != nil {
		os.Remove(serialFile) // Undo saved certificate
		return nil, err
	}

	return cert, nil
}
