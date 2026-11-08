// Command serve serves the documents interop/eudi/scripts/setup wrote
// to DIR, over TLS with its serve-cert.pem, for the EUDI verifier to
// fetch during interop/eudi/run-verifier.sh:
//
//	/statuslists/jwt    statuslist.jwt      application/statuslist+jwt
//	/statuslists/cwt    statuslist.cwt      application/statuslist+cwt
//	/type-metadata/pid  type-metadata.json  application/json
//
// Usage: go run ./interop/eudi/scripts/serve -dir DIR -addr ADDR
//
// Each document served is logged, so a run shows what the verifier
// fetched.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

func main() {
	dir := flag.String("dir", "", "the directory setup wrote")
	addr := flag.String("addr", "", "the address to listen on")
	flag.Parse()
	if *dir == "" || *addr == "" {
		log.Fatal("-dir and -addr are required")
	}

	mux := http.NewServeMux()
	for path, doc := range map[string]struct{ file, contentType string }{
		"GET /statuslists/jwt":   {"statuslist.jwt", statuslist.TokenMediaType},
		"GET /statuslists/cwt":   {"statuslist.cwt", statuslist.CWTTokenMediaType},
		"GET /type-metadata/pid": {"type-metadata.json", "application/json"},
	} {
		body, err := os.ReadFile(filepath.Join(*dir, doc.file)) // #nosec G304 -- the operator's own -dir
		if err != nil {
			log.Fatal(err)
		}
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			log.Printf("served %s", path)
			w.Header().Set("Content-Type", doc.contentType)
			_, _ = w.Write(body)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Only the fact: request data stays out of the log.
		log.Print("not found: a request for another path")
		http.NotFound(w, r)
	})

	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("listening on %s", *addr)
	log.Fatal(server.ListenAndServeTLS(filepath.Join(*dir, "serve-cert.pem"), filepath.Join(*dir, "serve-key.pem")))
}
