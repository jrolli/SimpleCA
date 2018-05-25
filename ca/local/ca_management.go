package local

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"

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

// localCa holds the data required for keeping state on a CA that is directly
// controlled by the server.  The struct is for internal use but implements
// the CertAuthorizer interface via the public functions in 'local.go'
type localCa struct {
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	dataStore string
}

// initializeLocalCa does calls each of the functions necessary to initialize
// the CA and passes any error back up the stack.
func (c *localCa) initializeLocalCa(dataStore string) error {
	c.dataStore = dataStore

	err := os.MkdirAll(dataStore, 0755)
	if err != nil {
		return err
	}

	err = c.initializeCaKey(filepath.Join(dataStore, "ca.key"))
	if err != nil {
		return err
	}

	err = c.initializeCaCert(filepath.Join(dataStore, "ca.crt"))
	if err != nil {
		return err
	}

	// Make the directory for referencing certs by serial number (primary)
	err = os.MkdirAll(filepath.Join(dataStore, "serial"), 0755)
	if err != nil {
		return err
	}

	// Symlink the CA's cert into the serial directory
	filename := c.caCert.SerialNumber.Text(16) + ".crt"
	filename = filepath.Join(dataStore, "serial", filename)
	err = os.Symlink("../ca.crt", filename)
	if err != nil && !os.IsExist(err) {
		return err
	}

	// Make the directory for referencing certs by common name (symlinks)
	err = os.MkdirAll(filepath.Join(dataStore, "common"), 0755)
	if err != nil {
		return err
	}

	// Symlink the CA's cert into the common name directory
	filename = c.caCert.Subject.CommonName + ".crt"
	filename = filepath.Join(dataStore, "common", filename)
	err = os.Symlink("../ca.crt", filename)
	if err != nil && !os.IsExist(err) {
		return err
	}

	err = os.MkdirAll(filepath.Join(dataStore, "auths"), 0700)
	if err != nil {
		return err
	}

	filename = filepath.Join(dataStore, "revocations.txt")
	err = ioutil.WriteFile(filename, []byte("\n"), 0644)
	if err != nil {
		return err
	}

	return c.updateCRL()
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
func (c *localCa) initializeCaCert(cert string) error {
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
		CommonName: "ca.vpn.rollinix.net",
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
	caCert, err := x509.ParseCertificate(der)
	c.caCert = caCert
	if err != nil {
		return err
	}
	return ioutil.WriteFile(cert, der, 0644)
}

func (c localCa) getCRL() ([]byte, error) {
	err := c.updateCRL()
	if err != nil {
		return nil, err
	}

	return ioutil.ReadFile(filepath.Join(c.dataStore, "ca.crl"))
}

func (c localCa) updateCRL() error {
	crlData, err := ioutil.ReadFile(filepath.Join(c.dataStore, "ca.crl"))
	if err == nil {
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
			revokedRaw = nil
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

func (c *localCa) getCertByName(name string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(c.dataStore, "common", name+".crt"))
}

func (c *localCa) getCertBySerial(bi big.Int) ([]byte, error) {
	f := filepath.Join(c.dataStore, "serial", bi.Text(16)+".crt")
	return ioutil.ReadFile(f)
}

func (c *localCa) revokeSerial(s, sig []byte) error {
	err := c.caCert.CheckSignature(x509.ECDSAWithSHA256, s, sig)
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

	return errors.New("not implemented")
}
