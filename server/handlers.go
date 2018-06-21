package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
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
			hPanic(w, r, http.StatusBadRequest, errors.New("Invalid JSON"))
		}

		cert, err := certAuthority.Register(msg.AuthKey, msg.PublicKey, msg.Signature)
		checkError(w, r, err)

		_, err = w.Write(cert)
		checkError(w, r, err)
	})
}

func rootCertHandler() http.HandlerFunc {
	return handlerWrapper(func(w http.ResponseWriter, r *http.Request) {

		checkMethod(w, r, http.MethodGet)

		cert, err := certAuthority.RootCert()
		checkError(w, r, err)

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

func safeChar(r rune) bool {
	return !((r >= '0' && r <= '9') ||
		(r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		r == '.')
}

func certByNameHandler() http.HandlerFunc {
	return handlerWrapper(func(w http.ResponseWriter, r *http.Request) {
		checkMethod(w, r, http.MethodGet)

		certName := r.URL.Path[len("/name/"):]

		if strings.IndexFunc(certName, safeChar) != -1 {
			checkError(w, r, errors.New("Unsafe character"))
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

		serial := r.URL.Path[len("/serial/"):]

		if strings.IndexFunc(serial, safeChar) != -1 {
			checkError(w, r, errors.New("Unsafe character"))
		}

		var s big.Int
		if _, success := s.SetString(serial, 16); !success {
			checkError(w, r, errors.New("Could not parse serial"))
		}

		cert, err := certAuthority.CertBySerial(s)
		checkError(w, r, err)

		w.Header().Set("Content-Type", "application/pkix-cert; charset=utf-8")

		_, err = w.Write(cert)
		checkError(w, r, err)
	})
}
