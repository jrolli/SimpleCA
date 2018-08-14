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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/jrolli/go-pkcs12"
)

type authMsg struct {
	Names     []string
	Signature []byte
}

func authHandler() http.HandlerFunc {
	return handlerWrapper(func(w http.ResponseWriter, r *http.Request) {

		checkMethod(w, r, http.MethodPost)

		rawMsg, err := ioutil.ReadAll(r.Body)
		checkError(w, r, err)

		var msg authMsg
		json.Unmarshal(rawMsg, &msg)

		if len(msg.Signature) == 0 || len(msg.Names) == 0 {
			hPanic(w, r, http.StatusBadRequest, errors.New("Invalid JSON"))
		}

		authCode, err := certAuthority.Authorize(msg.Names, msg.Signature)
		checkError(w, r, err)

		_, err = w.Write(authCode)
		checkError(w, r, err)

	})
}

type registerMsg struct {
	AuthKey   []byte
	PublicKey []byte
	Signature []byte
}

func registerHandler() http.HandlerFunc {
	return handlerWrapper(func(w http.ResponseWriter, r *http.Request) {
		checkMethod(w, r, http.MethodPost)

		rawMsg, err := ioutil.ReadAll(r.Body)
		checkError(w, r, err)

		var msg registerMsg
		json.Unmarshal(rawMsg, &msg)

		if len(msg.Signature) == 0 || len(msg.AuthKey) == 0 || len(msg.PublicKey) == 0 {
			hPanic(w, r, http.StatusBadRequest, errors.New("invalid JSON"))
		}

		cert, err := certAuthority.Register(msg.AuthKey, msg.PublicKey, msg.Signature)
		if os.IsNotExist(err) {
			hPanic(w, r, http.StatusForbidden, errors.New("invalid token"))
		}
		checkError(w, r, err)

		w.Header().Set("Content-Type", "application/pkix-cert; charset=utf-8")

		_, err = w.Write(cert)
		checkError(w, r, err)
	})
}

func registerGetHandler() http.HandlerFunc {
	return handlerWrapper(func(w http.ResponseWriter, r *http.Request) {
		checkMethod(w, r, http.MethodGet)

		if r.URL.Path[len(r.URL.Path)-4:] != ".p12" {
			hPanic(w, r, http.StatusNotFound, errors.New("unknown extension"))
		}

		authCode := r.URL.Path[len("/register/") : len(r.URL.Path)-4]

		if strings.IndexFunc(authCode, unsafeChar) != -1 {
			hPanic(w, r, http.StatusBadRequest, errors.New("unsafe character"))
		}

		auth := []byte(authCode)

		// /register
		random := rand.Reader
		curv := elliptic.P521()
		certKey, err := ecdsa.GenerateKey(curv, random)
		checkError(w, r, err)

		pk := marshalPublicKey(certKey.PublicKey)

		hash := crypto.SHA256
		hasher := sha256.New()
		msg := append(auth)
		_, err = hasher.Write(msg)
		checkError(w, r, err)

		var digest []byte
		digest = hasher.Sum(digest)

		sig, err := certKey.Sign(rand.Reader, digest, hash)

		cert, err := certAuthority.Register(auth, pk, sig)
		checkError(w, r, err)

		newCert, err := x509.ParseCertificate(cert)
		checkError(w, r, err)

		root, err := certAuthority.RootCert()
		checkError(w, r, err)

		rootCert, err := x509.ParseCertificate(root)
		checkError(w, r, err)

		caCerts := []*x509.Certificate{rootCert}

		p12, err := pkcs12.Encode(certKey, newCert, caCerts, authCode)
		checkError(w, r, err)

		w.Header().Set("Content-Type", "application/x-pkcs12; charset=utf-8")

		_, err = w.Write(p12)
		checkError(w, r, err)
	})
}

func rootCertHandler() http.HandlerFunc {
	return handlerWrapper(func(w http.ResponseWriter, r *http.Request) {

		checkMethod(w, r, http.MethodGet)

		cert, err := certAuthority.RootCert()
		checkError(w, r, err)

		w.Header().Set("Content-Type", "application/pkix-cert; charset=utf-8")

		_, err = w.Write(cert)
		checkError(w, r, err)

	})
}

func crlHandler() http.HandlerFunc {
	return handlerWrapper(func(w http.ResponseWriter, r *http.Request) {

		checkMethod(w, r, http.MethodGet)

		cert, err := certAuthority.CRL()
		checkError(w, r, err)

		_, err = w.Write(cert)
		checkError(w, r, err)

	})
}

func certByNameHandler() http.HandlerFunc {
	return handlerWrapper(func(w http.ResponseWriter, r *http.Request) {
		checkMethod(w, r, http.MethodGet)

		if r.URL.Path[len(r.URL.Path)-4:] != ".crt" {
			hPanic(w, r, http.StatusNotFound, errors.New("Unknown extension"))
		}

		certName := r.URL.Path[len("/name/") : len(r.URL.Path)-4]

		if strings.IndexFunc(certName, unsafeChar) != -1 {
			hPanic(w, r, http.StatusBadRequest, errors.New("Unsafe character"))
		}

		cert, err := certAuthority.CertByName(certName)
		checkError(w, r, err)

		w.Header().Set("Content-Type", "application/pkix-cert; charset=utf-8")

		_, err = w.Write(cert)
		checkError(w, r, err)
	})
}

func certBySerialHandler() http.HandlerFunc {
	return handlerWrapper(func(w http.ResponseWriter, r *http.Request) {
		checkMethod(w, r, http.MethodGet)

		if r.URL.Path[len(r.URL.Path)-4:] != ".crt" {
			hPanic(w, r, http.StatusNotFound, errors.New("unknown extension"))
		}

		serial := r.URL.Path[len("/serial/") : len(r.URL.Path)-4]

		if strings.IndexFunc(serial, unsafeChar) != -1 {
			hPanic(w, r, http.StatusBadRequest, errors.New("unsafe character"))
		}

		var s big.Int
		if _, success := s.SetString(serial, 16); !success {
			hPanic(w, r, http.StatusBadRequest, errors.New("Could not parse serial"))
		}

		cert, err := certAuthority.CertBySerial(s)
		checkError(w, r, err)

		w.Header().Set("Content-Type", "application/pkix-cert; charset=utf-8")

		_, err = w.Write(cert)
		checkError(w, r, err)
	})
}
