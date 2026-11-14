// Command serve serves the documents interop/eudi/scripts/setup (or
// pidsetup) wrote to DIR, over TLS with its serve-cert.pem, for the
// EUDI verifier (interop/eudi/run-verifier.sh), or the EUDI PID Issuer
// and its Keycloak (run-pid-issuer.sh), to fetch:
//
//	/statuslists/jwt    statuslist.jwt      application/statuslist+jwt
//	/statuslists/cwt    statuslist.cwt      application/statuslist+cwt
//	/type-metadata/pid  type-metadata.json  application/json
//
// A document DIR doesn't hold isn't served: pidsetup writes only the
// first.
//
// With -publish, the status lists aren't setup's fixed tokens but lists
// published as an issuer publishes them (publish.go): a
// statuslist.Allocator hands out each credential's index and keeps its
// status, and a statuslist.Publisher serves each list, signed by its
// credential's issuer (the keys in setup's wallet-sdjwt.json and
// wallet-mdoc.json). -admin, a loopback address, then serves the
// issuer's side: POST /allocate?list=jwt|cwt hands out an index, and
// POST /status sets one's status (publish.go).
//
// Usage: go run ./interop/eudi/scripts/serve -dir DIR -addr ADDR [-publish -admin ADDR]
//
// Each document served is logged, so a run shows what the verifier
// fetched.
package main

import (
	"errors"
	"flag"
	"io/fs"
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
	publish := flag.Bool("publish", false, "publish the status lists from a statuslist.Allocator, signing them per request, rather than serve setup's tokens")
	admin := flag.String("admin", "", "with -publish, the loopback address to serve POST /allocate and POST /status on")
	flag.Parse()
	if *dir == "" || *addr == "" || *publish != (*admin != "") {
		log.Fatal("-dir and -addr are required, and -publish needs -admin")
	}

	mux := http.NewServeMux()
	docs := map[string]struct{ file, contentType string }{
		"GET /type-metadata/pid": {"type-metadata.json", "application/json"},
	}
	if *publish {
		lists, err := newPublishedLists(*dir)
		if err != nil {
			log.Fatal(err)
		}
		lists.route(mux)
		go func() { log.Fatal(adminServer(*admin, lists).ListenAndServe()) }()
		log.Printf("status lists published; admin on http://%s", *admin)
	} else {
		docs["GET /statuslists/jwt"] = struct{ file, contentType string }{"statuslist.jwt", statuslist.TokenMediaType}
		docs["GET /statuslists/cwt"] = struct{ file, contentType string }{"statuslist.cwt", statuslist.CWTTokenMediaType}
	}
	for path, doc := range docs {
		body, err := os.ReadFile(filepath.Join(*dir, doc.file)) // #nosec G304 -- the operator's own -dir
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("not serving %s: no %s", path, doc.file)
			continue
		}
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
