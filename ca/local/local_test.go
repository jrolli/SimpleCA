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
	"testing"

	// Main packages
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Helper packages
	"github.com/jrolli/SimpleCA/ca"
)

func fatal(t *testing.T, e interface{}) {
	if e != nil {
		t.Fatal(e)
	}
}

func fail(t *testing.T, e interface{}) {
	if e != nil {
		t.Error(e)
	}
}

func TestLocalCA(t *testing.T) {
	r, err := rand.Int(rand.Reader, big.NewInt((1<<32)-1))
	fatal(t, err)

	datastore := filepath.Join(os.TempDir(), r.Text(16))
	defer os.RemoveAll(datastore)

	var c ca.CertAuthorizer

	t.Run("initialize", func(t *testing.T) {
		c, err = Initialize(datastore, "local.test")
		fatal(t, err)
	})

	t.Run("reinitialize", func(t *testing.T) {
		c, err = Initialize(datastore, "local.test")
		fail(t, err)
	})

	var rootCertData []byte
	t.Run("get-root-cert", func(t *testing.T) {
		rootCertData, err = c.RootCert()
		fail(t, err)
	})

	rootCert, err := x509.ParseCertificate(rootCertData)
	fatal(t, err)

	t.Run("check-cert-by-name", func(t *testing.T) {
		res, err := c.CertByName(rootCert.Subject.CommonName)
		fatal(t, err)

		if bytes.Compare(res, rootCertData) != 0 {
			t.Error("certificates do not match")
		}
	})

	t.Run("check-cert-by-serial", func(t *testing.T) {
		res, err := c.CertBySerial(*rootCert.SerialNumber)
		fatal(t, err)

		if bytes.Compare(res, rootCertData) != 0 {
			t.Error("certificates do not match")
		}
	})

	t.Run("check-empty-crl", func(t *testing.T) {
		crlData, err := c.CRL()
		fatal(t, err)

		crl, err := x509.ParseCRL(crlData)
		fatal(t, err)

		if crl.HasExpired(time.Now()) {
			t.Error("expired CRL")
		}
		if len(crl.TBSCertList.RevokedCertificates) > 0 {
			t.Error("revoked certificates exist")
		}
	})

	authKeyDER, err := ioutil.ReadFile(filepath.Join(datastore, "ca.key"))
	fatal(t, err)

	authKey, err := x509.ParseECPrivateKey(authKeyDER)
	fatal(t, err)

	h := crypto.SHA256
	var auth []byte
	names := []string{"a.local.test", "b.local.test", "c.local.test"}
	hasher := sha256.New()
	t.Run("authorize", func(t *testing.T) {
		msg := []byte(strings.Join(names, "\n"))
		_, err := hasher.Write(msg)
		fatal(t, err)

		var digest []byte
		digest = hasher.Sum(digest)

		r, s, err := ecdsa.Sign(rand.Reader, authKey, digest)
		if !ecdsa.Verify(&(authKey.PublicKey), digest, r, s) {
			t.Fatal("cannot verify signature")
		}

		asnSig, err := asn1.Marshal(ecdsaSignature{r, s})
		fatal(t, err)

		_, err = checkSignature(authKey.PublicKey, digest, asnSig)
		fail(t, err)

		sig, err := authKey.Sign(rand.Reader, digest, h)

		_, err = checkSignature(authKey.PublicKey, digest, asnSig)
		fail(t, err)

		auth, err = c.Authorize(names, sig)
		fail(t, err)
		if auth == nil {
			t.Error("no auth token returned")
		}
		authFile := filepath.Join(datastore, "auths", string(auth)+".txt")
		dat, err := ioutil.ReadFile(authFile)
		fail(t, err)
		if bytes.Compare(dat, msg) != 0 {
			t.Error("auth file does not match authorization")
		}
	})

	var cert *x509.Certificate
	var certData []byte
	var certKey *ecdsa.PrivateKey
	t.Run("register", func(t *testing.T) {
		random := rand.Reader
		curv := elliptic.P521()
		certKey, err = ecdsa.GenerateKey(curv, random)
		fatal(t, err)

		hasher.Reset()
		msg := append(auth, []byte("\x00")...)
		msg = append(msg, marshalPublicKey(certKey.PublicKey)...)
		_, err := hasher.Write(msg)
		fatal(t, err)

		var digest []byte
		digest = hasher.Sum(digest)

		sig, err := certKey.Sign(rand.Reader, digest, h)
		fatal(t, err)
		certData, err = c.Register(auth, marshalPublicKey(certKey.PublicKey), sig)
		fail(t, err)

		if certData == nil {
			t.Fatal("no certificate returned")
		}

		cert, err = x509.ParseCertificate(certData)
		fatal(t, err)

		err = cert.CheckSignatureFrom(rootCert)
		fail(t, err)

		for _, val := range names {
			err = cert.VerifyHostname(val)
			fail(t, err)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		if cert == nil {
			fatal(t, "no certificate from authorize")
		}

		hasher.Reset()
		serial := []byte(cert.SerialNumber.Text(16))
		_, err := hasher.Write(serial)
		fatal(t, err)

		var digest []byte
		digest = hasher.Sum(digest)
		sig, err := authKey.Sign(rand.Reader, digest, h)
		fatal(t, err)

		err = c.Revoke(serial, sig)
		fail(t, err)

		crlData, err := c.CRL()
		fatal(t, err)

		crl, err := x509.ParseCRL(crlData)
		fatal(t, err)

		if crl.HasExpired(time.Now()) {
			t.Error("expired CRL")
		}
		if len(crl.TBSCertList.RevokedCertificates) == 0 {
			t.Error("empty CRL")
		}
		revoked := false
		for _, val := range crl.TBSCertList.RevokedCertificates {
			if val.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				revoked = true
				break
			}
		}
		if !revoked {
			t.Error("certificate not revoked")
		}
	})
}
