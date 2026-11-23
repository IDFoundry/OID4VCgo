package certrevocation_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
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

// A Refresher reads at most 1 MiB of a CRL unless MaxBytes says more:
// tens of thousands of revocations, far beyond an IACA's or an issuer
// CA's list, while whoever answers a plain http distribution point
// makes the process parse what it sends before its signature is
// checked. A genuine list beyond it is refused, the held one kept,
// until MaxBytes is raised.
func TestRefresher_DefaultMaxBytes(t *testing.T) {
	const mib = 1 << 20
	p := newPKI(t)
	// 20-byte serial numbers, the longest RFC 5280 §4.1.2.2 allows:
	// about 40 bytes an entry.
	serials := make([]*big.Int, mib/36)
	for i := range serials {
		serials[i] = new(big.Int).Lsh(big.NewInt(int64(i)+1), 140)
	}
	large := numbered(t, p.inter, p.interKey, 1, -time.Hour, serials...)
	if len(large.Raw) <= mib || len(large.Raw) > 2*mib {
		t.Fatalf("the list is %d bytes, want between 1 and 2 MiB", len(large.Raw))
	}
	srv := newCRLServer(t)
	srv.serveCRL("/ca.crl", large)
	cfg := certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter}}
	if err := newRefresher(t, cfg).Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds 1048576 bytes") {
		t.Errorf("Refresh of a %d-byte list by default = %v, want it refused for its size", len(large.Raw), err)
	}
	cfg.MaxBytes = 2 * mib
	r := newRefresher(t, cfg)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh with MaxBytes raised: %v", err)
	}
	if got := heldList(t, r); !bytes.Equal(got.Raw, large.Raw) {
		t.Error("the list isn't held")
	}
}
