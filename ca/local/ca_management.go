package local

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"

	"io/ioutil"

	"math/big"

	"os"

	"time"
)

func marshalPublicKey(pub ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

type localCa struct {
	caKey    *ecdsa.PrivateKey
	caCert   []byte
	keyStore string
}

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

func (c *localCa) initializeCaCert(cert string) error {
	der, err := ioutil.ReadFile(cert)
	switch err.(type) {
	case (*os.PathError):
		// passthrough
	case nil:
		c.caCert = der
		return nil
	default:
		return err
	}

	random := rand.Reader

	subject := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"RolliNix"},
		OrganizationalUnit: []string{"Certificates"},
		// Locality:,
		// Province:,
		// StreetAddress:,
		// PostalCode:,
		// SerialNumber:,
		CommonName: "RolliNix CA",
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
		PermittedDNSDomains:         []string{"vpn.rollinix.net"},
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
	c.caCert = der
	return ioutil.WriteFile(cert, der, 0644)
}
