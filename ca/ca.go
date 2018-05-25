// Package ca provides a common interface for upstream providers
// of certificate authority services that can be used to get new
// end use certificates.
package ca

import "math/big"

type CertAuthorizer interface {
	// Authorize takes the names authorized for the cert and a signature by
	// the control key over those names.  The function returns a byte-string
	// that is signed by the new public key as proof of authorization in the
	// 'Register' function.
	Authorize(names []string, sig []byte) ([]byte, error)

	// Register takes the authorization byte-string, the public key for the
	// new certificate, and the signature of the authorization string using
	// the new private-key and returns the new certificate.  The server must
	// validate both the authorization token (valid and not used) and the
	// signature (corresponds to the presented public key).
	Register(auth, pub, sig []byte) ([]byte, error)

	// Renew uses an existing certificate to get a new certificate for the
	// same domain names.  The private key of the old certificate is used to
	// sign the new public key.  The server is able to validate the signature
	// and authorized domain names by using the serial to look it up in its
	// local database.  Upon granting the new certificate, the server must
	// revoke the old certificate.
	Renew(oldCertSerial, pub, sig []byte) ([]byte, error)

	// Revoke uses the control key to revoke an existing certificate by its
	// serial.  The server must validate the signature of the control key
	// before revoking the certificate.
	Revoke(serial, sig []byte) error

	// Getter Methods

	// CertBySerial returns the DER encoded certificate with the matching
	// serial number.  Returns an appropriate error if it is invalid,
	// expired, or non-existent.
	CertBySerial(big.Int) ([]byte, error)

	// CertByName returns the DER encoded certificate with the matching
	// common name.  Returns an appropriate error if it is invalid, expired,
	// or non-existent.
	CertByName(string) ([]byte, error)

	// RootCert returns the root certificate in DER encoding.
	RootCert() ([]byte, error)

	// CRL returns a CRL that is currently valid.
	CRL() ([]byte, error)
}
