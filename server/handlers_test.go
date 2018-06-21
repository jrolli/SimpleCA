package main

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
	"encoding/json"
	// "fmt"
	// "errors"
	"io/ioutil"
	// "log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	// "time"

	// Other packages
	"github.com/jrolli/SimpleCA/ca/local"
)

// marshalPublicKey is a helper function for passing the ECDSA public key
// parameters to the existing marshal function for elliptic curves.
func marshalPublicKey(pub ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

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

func TestHandlerInterface(t *testing.T) {
	r, err := rand.Int(rand.Reader, big.NewInt((1<<32)-1))
	fatal(t, err)

	datastore := filepath.Join(os.TempDir(), r.Text(16))
	defer os.RemoveAll(datastore)

	certAuthority, err = local.Initialize(datastore, "test")
	hash := crypto.SHA256
	hasher := sha256.New()
	var auth []byte
	names := []string{"a.local.test", "b.local.test", "c.local.test"}

	authKeyDER, err := ioutil.ReadFile(filepath.Join(datastore, "ca.key"))
	fatal(t, err)

	authKey, err := x509.ParseECPrivateKey(authKeyDER)
	fatal(t, err)

	var rootCertData []byte
	rootCertData, err = certAuthority.RootCert()
	fatal(t, err)

	rootCert, err := x509.ParseCertificate(rootCertData)
	fatal(t, err)

	t.Run("root-cert", func(t *testing.T) {
		h := rootCertHandler()

		input := bytes.NewReader([]byte(""))
		respRec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ca.crt", input)

		h(respRec, req)
		resp := respRec.Result()

		if resp.StatusCode != http.StatusOK {
			t.Fail()
		}

		body, err := ioutil.ReadAll(resp.Body)
		fatal(t, err)

		if bytes.Compare(body, rootCertData) != 0 {
			t.Fail()
		}
	})

	t.Run("authorize", func(t *testing.T) {
		h := authHandler()

		t.Run("get", func(t *testing.T) {
			msg := authMsg{[]string{}, []byte("")}
			jsonMsg, err := json.Marshal(msg)
			fatal(t, err)

			input := bytes.NewReader(jsonMsg)
			respRec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/authorize", input)

			h(respRec, req)
			resp := respRec.Result()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fail()
			}

			body, err := ioutil.ReadAll(resp.Body)
			fatal(t, err)

			if bytes.Compare(body, []byte("GET method not supported\n")) != 0 {
				t.Fail()
			}
		})

		t.Run("post-nodata", func(t *testing.T) {
			msg := authMsg{[]string{}, []byte("")}
			jsonMsg, err := json.Marshal(msg)
			fatal(t, err)

			input := bytes.NewReader(jsonMsg)
			respRec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/authorize", input)

			h(respRec, req)
			resp := respRec.Result()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fail()
			}

			body, err := ioutil.ReadAll(resp.Body)
			fatal(t, err)

			if bytes.Compare(body, []byte("Invalid JSON\n")) != 0 {
				t.Fail()
			}
		})

		t.Run("post-empty-names", func(t *testing.T) {
			msg := authMsg{[]string{}, []byte("a")}
			jsonMsg, err := json.Marshal(msg)
			fatal(t, err)

			input := bytes.NewReader(jsonMsg)
			respRec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/authorize", input)

			h(respRec, req)
			resp := respRec.Result()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fail()
			}

			body, err := ioutil.ReadAll(resp.Body)
			fatal(t, err)

			if bytes.Compare(body, []byte("Invalid JSON\n")) != 0 {
				t.Fail()
			}
		})

		t.Run("post-empty-sig", func(t *testing.T) {
			msg := authMsg{[]string{"a"}, []byte("")}
			jsonMsg, err := json.Marshal(msg)
			fatal(t, err)

			input := bytes.NewReader(jsonMsg)
			respRec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/authorize", input)

			h(respRec, req)
			resp := respRec.Result()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fail()
			}

			body, err := ioutil.ReadAll(resp.Body)
			fatal(t, err)

			if bytes.Compare(body, []byte("Invalid JSON\n")) != 0 {
				t.Fail()
			}
		})

		t.Run("post-invalid-sig", func(t *testing.T) {
			msg := authMsg{[]string{"a"}, []byte("a")}
			jsonMsg, err := json.Marshal(msg)
			fatal(t, err)

			input := bytes.NewReader(jsonMsg)
			respRec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/authorize", input)

			h(respRec, req)
			resp := respRec.Result()

			if resp.StatusCode != http.StatusInternalServerError {
				t.Fail()
			}
		})

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

			sig, err := authKey.Sign(rand.Reader, digest, hash)
			fatal(t, err)

			msgStruct := authMsg{names, sig}
			jsonMsg, err := json.Marshal(msgStruct)
			fatal(t, err)

			input := bytes.NewReader(jsonMsg)
			respRec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/authorize", input)

			h(respRec, req)
			resp := respRec.Result()

			if resp.StatusCode != http.StatusOK {
				t.Fail()
			}

			auth, err = ioutil.ReadAll(resp.Body)
			fail(t, err)
			if auth == nil {
				t.Error("no auth token returned")
			}
		})
	})

	var cert *x509.Certificate
	var certKey *ecdsa.PrivateKey

	t.Run("register", func(t *testing.T) {
		h := registerHandler()

		// /register
		random := rand.Reader
		curv := elliptic.P521()
		certKey, err = ecdsa.GenerateKey(curv, random)
		fatal(t, err)

		pk := marshalPublicKey(certKey.PublicKey)

		hasher.Reset()
		msg := append(auth, []byte("\x00")...)
		msg = append(msg, pk...)
		_, err := hasher.Write(msg)
		fatal(t, err)

		var digest []byte
		digest = hasher.Sum(digest)

		sig, err := certKey.Sign(rand.Reader, digest, hash)
		fatal(t, err)

		msgStruct := registerMsg{auth, pk, sig}
		jsonMsg, err := json.Marshal(msgStruct)
		fatal(t, err)

		input := bytes.NewReader(jsonMsg)
		respRec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", input)

		h(respRec, req)
		resp := respRec.Result()

		if resp.StatusCode != http.StatusOK {
			t.Fail()
		}

		certData, err := ioutil.ReadAll(resp.Body)
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

	t.Run("cert-lookup", func(t *testing.T) {
		t.Run("by-serial", func(t *testing.T) {
			// /serial/[serial]
		})

		t.Run("by-name", func(t *testing.T) {
			// /name/[cn]
		})
	})

	t.Run("revoke", func(t *testing.T) {
		// /revoke
	})

	t.Run("crl", func(t *testing.T) {
		// /ca.crl
	})
}
