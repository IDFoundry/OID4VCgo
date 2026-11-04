package statuslist

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// A Status List Token in CWT form signed on P-384 (ES384) or P-521
// (ES512) — an mdoc issuer's IACA material may be on either — is
// served by a Publisher set to the CWT form and read by a Checker. The
// JWT form, ES256 or EdDSA only, is refused: as a configuration with
// DefaultForm FormJWT, as a Token, and as a request for it alone (406).
func TestPublisher_CWTOnNISTCurves(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	statuses := func(context.Context) ([]uint8, error) { return []uint8{0, 1}, nil }
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cert := testcert.LeafFor(t, curve.Params().Name+" status signer", &key.PublicKey, ca, caKey)
			var uri string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				(&Publisher{
					URI: uri, Signer: key, Chain: []*x509.Certificate{cert}, Statuses: statuses, DefaultForm: FormCWT,
				}).ServeHTTP(w, r)
			}))
			defer srv.Close()
			uri = srv.URL + "/statuslists/1"
			c := Checker{Fetcher: Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots, Options: VerifyOptions{UnboundSigner: AnyListSigner}}
			for idx, want := range map[uint64]StatusType{0: StatusValid, 1: StatusInvalid} {
				if got, _, err := c.Check(context.Background(), StatusListRef{Idx: idx, URI: uri}, true); err != nil || got != want {
					t.Errorf("idx %d: %v, %v; want %v", idx, got, err, want)
				}
			}
			if _, _, err := c.Check(context.Background(), StatusListRef{Idx: 0, URI: uri}, false); err == nil {
				t.Error("the JWT form was read")
			}
			req, err := http.NewRequest(http.MethodGet, uri, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Accept", TokenMediaType)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotAcceptable {
				t.Errorf("Accept %s: status %d, want 406", TokenMediaType, resp.StatusCode)
			}

			p := &Publisher{URI: uri, Signer: key, Chain: []*x509.Certificate{cert}, Statuses: statuses, DefaultForm: FormCWT}
			if _, err := p.Token(context.Background(), false); err == nil || !strings.Contains(err.Error(), "CWT tokens only") {
				t.Errorf("JWT Token: %v", err)
			}
			p.DefaultForm = FormJWT
			if _, err := p.Token(context.Background(), true); err == nil || !strings.Contains(err.Error(), "set DefaultForm to FormCWT") {
				t.Errorf("DefaultForm FormJWT: %v", err)
			}
		})
	}
}

// CheckCWTX5Chain verifies a token signed with ES384 by a P-384 signer;
// the signer is refused under another curve's algorithm.
func TestCheckCWTX5Chain_P384(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := testcert.LeafFor(t, "P-384 status signer", &key.PublicKey, ca, caKey)
	sl, err := New(Bits1, []uint8{1, 0}, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := TokenClaims{Sub: "https://issuer.example/statuslists/1", Iat: now.Unix(), StatusList: sl}
	token, err := IssueTokenCWTX5Chain(key, cose.ES384, claims, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	opts := VerifyOptions{UnboundSigner: AnyListSigner}
	if got, _, err := CheckCWTX5Chain(token, roots, StatusListRef{Idx: 0, URI: claims.Sub}, opts); err != nil || got != StatusInvalid {
		t.Errorf("CheckCWTX5Chain: %v, %v", got, err)
	}
	if _, err := IssueTokenCWTX5Chain(key, cose.ES256, claims, []*x509.Certificate{cert}); err == nil {
		t.Error("a P-384 key signed under ES256")
	}
}
