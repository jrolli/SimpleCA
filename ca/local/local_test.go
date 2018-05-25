package local

import (
	"testing"

	// Main packages
	"bytes"

	"crypto/rand"
	"crypto/x509"

	"math/big"

	"os"

	"path/filepath"

	"time"

	// Helper packages
	"github.com/jrolli/ca-proxy/ca"
)

func TestLocalCA(t *testing.T) {
	r, err := rand.Int(rand.Reader, big.NewInt((1<<32)-1))
	if err != nil {
		t.Fatal(err)
	}

	datastore := filepath.Join(os.TempDir(), r.Text(16))
	defer os.RemoveAll(datastore)

	var c ca.CertAuthorizer

	t.Run("initialize", func(t *testing.T) {
		c, err = Initialize(datastore)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("reinitialize", func(t *testing.T) {
		c, err = Initialize(datastore)
		if err != nil {
			t.Fatal(err)
		}
	})

	var rootCertData []byte
	t.Run("get-root-cert", func(t *testing.T) {
		rootCertData, err = c.RootCert()
		if err != nil {
			t.Error(err)
		}
	})

	rootCert, err := x509.ParseCertificate(rootCertData)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("check-cert-by-name", func(t *testing.T) {
		res, err := c.CertByName(rootCert.Subject.CommonName)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(res, rootCertData) != 0 {
			t.Error("Certificates do not match")
		}
	})

	t.Run("check-cert-by-serial", func(t *testing.T) {
		res, err := c.CertBySerial(*rootCert.SerialNumber)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(res, rootCertData) != 0 {
			t.Error("Certificates do not match")
		}
	})

	t.Run("check-empty-crl", func(t *testing.T) {
		crlData, err := c.CRL()
		if err != nil {
			t.Fatal(err)
		}

		crl, err := x509.ParseCRL(crlData)
		if err != nil {
			t.Fatal(err)
		}

		if crl.HasExpired(time.Now()) {
			t.Error("Expired CRL")
		}
		if len(crl.TBSCertList.RevokedCertificates) > 0 {
			t.Error("Revoked certificates exist")
		}
	})
}
