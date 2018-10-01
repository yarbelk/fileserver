package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/yarbelk/fileserver/fs"
	"golang.org/x/crypto/acme/autocert"
)

var (
	serveWhat = flag.String("serveDir", ".", "Which directory to serve.  defaults to '.'")
	tls       = flag.Bool("tls", true, "Serve with TLS, needs domains. Only set to false \nfor testing.  It will serve on port 443 when enabled")
	domains   = flag.String("domains", "", "a comma separated list of domains to serve against")
)

func main() {
	flag.Parse()
	if *tls && len(*domains) == 0 {
		fmt.Fprintf(os.Stderr, "Need a list of domains to listen too")
		flag.PrintDefaults()
	}
	domainsArgs := strings.Split(*domains, ",")
	fileHandler := fs.FileServer(fs.GoodDir(*serveWhat))
	if !*tls {
		log.Fatal(http.ListenAndServe(":8080", fileHandler))
	} else {
		log.Fatal(http.Serve(autocert.NewListener(domainsArgs...), fileHandler))
	}
}
