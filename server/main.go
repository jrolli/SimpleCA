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

// server is a basic web application that interfaces with a local CA
package main

import (
	"flag"
	"log"
	"net/http"

	// Other packages
	"github.com/jrolli/SimpleCA/ca"
	"github.com/jrolli/SimpleCA/ca/local"
)

var certAuthority ca.CertAuthorizer

func main() {
	baseDir := flag.String("dir", "ca", "path to directory for the CA files")
	domain := flag.String("domain", "test", "DNS domain for CA certificates")
	listen := flag.String("listen", ":80", "listen address for server")
	cert := flag.String("cert", "", "path to web server certificate")
	key := flag.String("certkey", "", "path to key for web certificate")
	flag.Parse()

	var err error

	log.Print("Initializing CA...")
	certAuthority, err = local.Initialize(*baseDir, *domain)
	fatalError(err)

	http.HandleFunc("/authorize", authHandler())
	http.HandleFunc("/register", registerHandler())
	http.HandleFunc("/register/", registerGetHandler())
	http.HandleFunc("/serial/", certBySerialHandler())
	http.HandleFunc("/name/", certByNameHandler())
	http.HandleFunc("/ca.crt", rootCertHandler())
	http.HandleFunc("/ca.crl", crlHandler())

	if len(*key) > 0 && len(*cert) > 0 {
		log.Fatal(http.ListenAndServeTLS(*listen, *cert, *key, nil))
	} else {
		log.Fatal(http.ListenAndServe(*listen, nil))
	}
}
