package identifierlist

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// A Publisher whose signer is on P-384 or P-521 signs with ES384 or
// ES512, and a Checker reads what it serves.
func TestPublisher_NISTCurves(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			pki := newPKI(t)
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := testcert.LeafFor(t, "identifier list signer", &key.PublicKey, pki.ca, pki.caKey)
			var uri string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				(&Publisher{
					URI: uri, Signer: key, Chain: []*x509.Certificate{leaf},
					Identifiers: func(context.Context) ([][]byte, error) { return [][]byte{{0xcc, 0xcc}}, nil },
				}).ServeHTTP(w, r)
			}))
			defer srv.Close()
			uri = srv.URL + "/identifierlists/1"
			c := Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: pki.roots}
			ctx := context.Background()
			if revoked, _, err := c.Check(ctx, Ref{ID: []byte{0xcc, 0xcc}, URI: uri}, pki.dsPath); err != nil || !revoked {
				t.Errorf("revoked: %v, %v", revoked, err)
			}
			if revoked, _, err := c.Check(ctx, Ref{ID: []byte{0xcc, 0xcd}, URI: uri}, pki.dsPath); err != nil || revoked {
				t.Errorf("not revoked: %v, %v", revoked, err)
			}
		})
	}
}
