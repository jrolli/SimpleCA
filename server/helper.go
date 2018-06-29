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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"log"
	"net/http"
	"os"
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
