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

// client is a minimal implementation for interfacing with the CA server
// from the command line.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func main() {
	// always needed
	server := flag.String("server", "", "address of CA server")
	key := flag.String("key", "", "file for ECDSA private key")

	// authorize flags
	authorize := flag.Bool("authorize", false, "create a new authorization")
	names := flag.String("names", "", "comma separated list of names for cert (CN is first)")

	// register flags
	register := flag.Bool("register", false, "register a new certificate")
	token := flag.String("token", "", "authorization token for registration")
	p12 := flag.Bool("p12", false, "register using the PKCS12 end-point") // negates 'key'
	out := flag.String("out", "", "path for output")

	// parse and check for consistency in flags
	flag.Parse()
	if !(*authorize || *register) {
		invokeError("Error: must use 'authorize' or 'register'")
	} else if *authorize && *register {
		invokeError("Error: 'authorize' and 'register' are incompatible")
	} else if *server == "" {
		invokeError("Error: 'server' is required")
	} else if *authorize && *key == "" {
		invokeError("Error: 'key' required with 'authorize'")
	} else if *authorize && *names == "" {
		invokeError("Error: 'names' required with 'authorize'")
	} else if *names != "" && !*authorize {
		invokeError("Error: 'names' only valid with 'authorize'")
	} else if *register && *token == "" {
		invokeError("Error: 'token' required with 'register'")
	} else if *register && *out == "" {
		invokeError("Error: 'out' required with 'register'")
	} else if *p12 && !*register {
		invokeError("Error: 'p12' only valid with 'register'")
	} else if *out != "" && !*register {
		invokeError("Error: 'out' only valid with 'register'")
	} else if *token != "" && !*register {
		invokeError("Error: 'token' only valid with 'register'")
	} else if *register && *p12 && *key != "" {
		invokeError("Error: cannot use 'key' when registering with 'p12'")
	}

	// execute based off input
	if *authorize {
		sendAuth(*server, *key, *names)
	}
}

type authMsg struct {
	Names     []string
	Signature []byte
}

func sendAuth(server, derFile, nameList string) {
	url := server + "/authorize"

	names := strings.Split(nameList, ",")
	hash := crypto.SHA256
	hasher := sha256.New()

	keyDer, err := ioutil.ReadFile(derFile)
	checkError(err)

	key, err := x509.ParseECPrivateKey(keyDer)
	checkError(err)

	msg := []byte(strings.Join(names, "\n"))
	_, err = hasher.Write(msg)
	checkError(err)

	var digest []byte
	digest = hasher.Sum(digest)

	sig, err := key.Sign(rand.Reader, digest, hash)
	checkError(err)

	msgStruct := authMsg{names, sig}
	jsonMsg, err := json.Marshal(msgStruct)
	checkError(err)
	jsonReader := bytes.NewReader(jsonMsg)

	client := http.DefaultClient
	resp, err := client.Post(url, "application/json", jsonReader)
	checkError(err)

	respBody, err := ioutil.ReadAll(resp.Body)
	checkError(err)

	fmt.Println(string(respBody))
}

type registerMsg struct {
	AuthKey   []byte
	PublicKey []byte
	Signature []byte
}

func sendReg(server, derFile, tokenStr string) {
	url := server + "/register"
	token := []byte(tokenStr)

	hash := crypto.SHA256
	hasher := sha256.New()

	keyDer, err := ioutil.ReadFile(derFile)
	checkError(err)

	key, err := x509.ParseECPrivateKey(keyDer)
	checkError(err)

	msg := []byte(strings.Join(names, "\n"))
	_, err = hasher.Write(msg)
	checkError(err)

	var digest []byte
	digest = hasher.Sum(digest)

	sig, err := key.Sign(rand.Reader, digest, hash)
	checkError(err)

	msgStruct := authMsg{names, sig}
	jsonMsg, err := json.Marshal(msgStruct)
	checkError(err)
	jsonReader := bytes.NewReader(jsonMsg)

	client := http.DefaultClient
	resp, err := client.Post(url, "application/json", jsonReader)
	checkError(err)

	respBody, err := ioutil.ReadAll(resp.Body)
	checkError(err)

	fmt.Println(string(respBody))
}

func invokeError(msg string) {
	fmt.Fprintln(os.Stderr, msg+"\n\nUsage:")
	flag.PrintDefaults()
	os.Exit(1)
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
