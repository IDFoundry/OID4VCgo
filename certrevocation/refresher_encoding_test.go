package certrevocation_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// A fetch asks for no content coding, and a gzip answer sent anyway is
// never inflated: MaxBytes bounds the bytes sent, and the compressed
// bytes are refused as they are, though they'd inflate to a CRL the
// issuer signed. A small gzip stream can't make the process inflate,
// and parse, a CRL many times its size before its signature is checked.
func TestRefresher_GzipAnswerNotInflated(t *testing.T) {
	p := newPKI(t)
	list := numbered(t, p.inter, p.interKey, 1, -time.Hour)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(list.Raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		asked = append(asked, req.Header.Get("Accept-Encoding"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz.Bytes())
	}))
	t.Cleanup(srv.Close)

	for name, client := range map[string]*http.Client{"default client": nil, "given client": {}} {
		r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter}, HTTPClient: client})
		if err := r.Refresh(context.Background()); err == nil {
			t.Errorf("%s: Refresh of a gzip answer = nil error, want it refused uninflated", name)
		}
		if lists, _ := r.Lists(context.Background()); len(lists) != 0 {
			t.Errorf("%s: %d lists held, want none", name, len(lists))
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, enc := range asked {
		if enc != "identity" {
			t.Errorf("a fetch asked for Accept-Encoding %q, want identity", enc)
		}
	}
}
