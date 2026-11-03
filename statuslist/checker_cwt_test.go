package statuslist

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// Checker.Check reads the CWT form as an mdoc's revocation list
// (ISO/IEC 18013-5 §12.3.6.3), whatever Options says: a list without
// exp, or with its x5chain unprotected, is refused.
func TestChecker_CWTIsAnMdocRevocationList(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	leaf, key := testcert.Leaf(t, "status signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	cwtSL, err := toCWTStatusList(sl)
	if err != nil {
		t.Fatal(err)
	}
	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		claims := map[int]any{cwtClaimSub: base + r.URL.Path, cwtClaimIat: now.Unix(), cwtClaimExp: now.Add(time.Hour).Unix(), cwtClaimStatusList: cwtSL}
		protected, unprotected := cose.Headers{Typ: CWTTokenMediaType, X5Chain: [][]byte{leaf.Raw}}, cose.Headers{}
		switch r.URL.Path {
		case "/no-exp":
			delete(claims, cwtClaimExp)
		case "/unprotected":
			protected.X5Chain, unprotected.X5Chain = nil, protected.X5Chain
		}
		raw, err := cbor.Marshal(claims)
		if err != nil {
			t.Error(err)
			return
		}
		token, err := cose.SignTagged(cose.ES256, key, protected, unprotected, raw, nil)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", CWTTokenMediaType)
		_, _ = w.Write(token)
	}))
	defer srv.Close()
	base = srv.URL
	c := Checker{Fetcher: Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots, Options: VerifyOptions{UnboundSigner: AnyListSigner}}

	if err := c.RequireValid(context.Background(), StatusListRef{URI: base + "/ok"}, true); err != nil {
		t.Errorf("a conformant list: %v", err)
	}
	for path, want := range map[string]string{
		"/no-exp":      "missing the required exp",
		"/unprotected": "token signer",
	} {
		err := c.RequireValid(context.Background(), StatusListRef{URI: base + path}, true)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error containing %q", path, err, want)
		}
	}
}
