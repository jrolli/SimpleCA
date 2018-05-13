// Package ca provides a common interface for upstream providers
// of certificate authority services that can be used to get new
// end use certificates.
package ca

type CertAuthorizer interface {
	Authorize(names []string, sig []byte) ([]byte, error)
	Register(auth, pub, sig []byte) ([]byte, error)
	Renew(oldCert, pub, sig []byte) ([]byte, error)
	Revoke(serial, sig []byte) error
	RootCert() ([]byte, error)
}
