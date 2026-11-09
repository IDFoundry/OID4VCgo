package identifierlist

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Every listed identifier is found revoked when they differ in length.
// The token's deterministic CBOR orders map keys shortest first (RFC
// 8949 §4.2.1), not as bytes.Compare does, so the parsed identifiers
// must be sorted again before they're binary searched: identifiers of
// one length sort the same both ways, and wouldn't show it.
func TestChecker_MixedLengthIdentifiers(t *testing.T) {
	pki := newPKI(t)
	listed := [][]byte{
		{0xff}, {0x00, 0x01}, {0x80}, {0x01, 0x02, 0x03}, {0x7f, 0xff},
		{0x00}, {0xfe, 0x00, 0x00, 0x00}, {0x10, 0x20}, {0x02}, {0xaa, 0xbb, 0xcc},
	}
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(&Publisher{
			URI: uri, Signer: pki.key, Chain: []*x509.Certificate{pki.leaf},
			Identifiers: func(context.Context) ([][]byte, error) { return listed, nil },
		}).ServeHTTP(w, r)
	}))
	defer srv.Close()
	uri = srv.URL + "/identifierlists/1"
	c := Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: pki.roots}
	ctx := context.Background()
	for _, id := range listed {
		if revoked, _, err := c.Check(ctx, Ref{ID: id, URI: uri}, pki.dsPath); err != nil || !revoked {
			t.Errorf("listed %x: revoked %v, %v; want revoked", id, revoked, err)
		}
		if err := c.RequireNotRevoked(ctx, Ref{ID: id, URI: uri}, pki.dsPath); err == nil {
			t.Errorf("listed %x: RequireNotRevoked = nil", id)
		}
	}
	for _, id := range [][]byte{{0x01}, {0x00, 0x02}, {0xff, 0xff}, {0x01, 0x02}} {
		if revoked, _, err := c.Check(ctx, Ref{ID: id, URI: uri}, pki.dsPath); err != nil || revoked {
			t.Errorf("unlisted %x: revoked %v, %v; want not revoked", id, revoked, err)
		}
	}
}
