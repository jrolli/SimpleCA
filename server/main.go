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
