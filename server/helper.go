package main

import (
	// "crypto"
	// "crypto/rand"
	// "crypto/sha256"
	// "crypto/x509"
	"crypto/ecdsa"
	"crypto/elliptic"
	// "flag"
	// "io/ioutil"
	"fmt"
	"log"
	"net/http"
	"os"
	// "path/filepath"
	// "strings"
	// Other packages
	// "github.com/jrolli/SimpleCA/ca/local"
)

// marshalPublicKey is a helper function for passing the ECDSA public key
// parameters to the existing marshal function for elliptic curves.
func marshalPublicKey(pub ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func safeChar(r rune) bool {
	return !((r >= '0' && r <= '9') ||
		(r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		r == '.')
}

func fatalError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func hPanic(w http.ResponseWriter, r *http.Request, status int, e error) {
	err := handlerError{status, w, r, e}
	panic(err)
}

func checkMethod(w http.ResponseWriter, r *http.Request, method string) {
	if r.Method != method {
		hPanic(w, r, http.StatusMethodNotAllowed, nil)
	}
}

func checkError(w http.ResponseWriter, r *http.Request, e error) {
	if e != nil {
		hPanic(w, r, http.StatusInternalServerError, e)
	}
}

type handlerError struct {
	status int
	w      http.ResponseWriter
	r      *http.Request
	e      error
}

func (h *handlerError) Error() string {
	if h.status == http.StatusMethodNotAllowed {
		return fmt.Sprintf("%s method not supported", h.r.Method)
	}
	return h.e.Error()
}

func handlePanic() {
	p := recover()
	if p == nil {
		return
	}

	switch v := p.(type) {
	case handlerError:
		if os.IsNotExist(v.e) {
			http.NotFound(v.w, v.r)
		} else {
			http.Error(v.w, v.Error(), v.status)
		}
		return
	default:
		panic(p)
	}
	// http.Error(w, fmt.Sprintf("%s method not supported", e.method), r.Method)
}

func handlerWrapper(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer handlePanic()
		h(w, r)
	}
}

// type authorization struct {
//  names     []string
//  signature []byte
// }

// type registration struct {
//  authKey   []byte
//  pubKey    []byte
//  signature []byte
// }

// type renewal struct {
//  oldCert   []byte
//  pubKey    []byte
//  signature []byte
// }

// type revocation struct {
//  serial    []byte
//  signature []byte
// }
// names := []string{"test.vpn.rollinix.net"}
