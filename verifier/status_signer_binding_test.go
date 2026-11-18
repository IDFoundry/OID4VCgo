package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// signerBindingUnset is how a StatusPolicy refuses a Checker that
// binds the list signer itself.
const signerBindingUnset = "Issuer, IssuerKey and UnboundSigner must be unset"

// A StatusPolicy's Checker can't name the status list signer: each
// check binds the signer to its own credential's issuer, and
// Options.Issuer or IssuerKey would replace that binding, so another
// issuer's list could decide a revoked credential VALID. The
// configuration is refused at every assurance level, and every check
// with it, before any list is fetched.
func TestStatusPolicy_RefusesACheckerNamingTheSigner(t *testing.T) {
	iaca, iacaKey := testcert.CA(t, "IACA")
	other, otherKey := testcert.CA(t, "another IACA")
	ds, _ := testcert.Leaf(t, "document signer", iaca, iacaKey)
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	roots.AddCert(other)
	// A list signer under the other IACA, VALID at index 0: it must
	// never decide the status of a document the first IACA certified.
	foreignSigner, foreignKey := testcert.Leaf(t, "status signer under another IACA", other, otherKey)
	var fetches atomic.Int32
	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		sl, err := statuslist.New(statuslist.Bits1, []uint8{0}, "")
		if err != nil {
			t.Error(err)
			return
		}
		exp := time.Now().Add(time.Hour).Unix()
		claims := statuslist.TokenClaims{Sub: base + r.URL.Path, Iat: time.Now().Unix(), Exp: &exp, StatusList: sl}
		token, err := statuslist.IssueTokenCWTX5Chain(foreignKey, cose.ES256, claims, []*x509.Certificate{foreignSigner})
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", statuslist.CWTTokenMediaType)
		_, _ = w.Write(token)
	}))
	defer srv.Close()
	base = srv.URL
	result := verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{
		MdocStatus:  &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 0, URI: base + "/list"}},
		IssuerChain: [][]byte{ds.Raw},
	}}}
	ctx := context.Background()
	checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
	if err := verifier.RequireValidStatus(checker)(ctx, "id", result); err == nil || !strings.Contains(err.Error(), "§12.3.6.2") {
		t.Fatalf("unpinned: %v, want the list refused by the §12.3.6.2 binding", err)
	}

	for name, set := range map[string]func(*statuslist.VerifyOptions){
		"Issuer":        func(o *statuslist.VerifyOptions) { o.Issuer = "https://issuer-b.example" },
		"IssuerKey":     func(o *statuslist.VerifyOptions) { o.IssuerKey = foreignSigner.PublicKey.(*ecdsa.PublicKey) },
		"UnboundSigner": func(o *statuslist.VerifyOptions) { o.UnboundSigner = statuslist.AnyListSigner },
	} {
		t.Run(name, func(t *testing.T) {
			pinned := checker
			set(&pinned.Options)
			refused := func(what string, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), signerBindingUnset) {
					t.Errorf("%s: %v, want refused (%s)", what, err, signerBindingUnset)
				}
			}
			policy := &verifier.StatusPolicy{Checker: pinned}
			refused("CheckStatusDecision, development", verifier.CheckStatusDecision(verifier.AssuranceDevelopment, policy, false))
			production := productionStatus()
			set(&production.Checker.Options)
			refused("CheckStatusDecision, production", verifier.CheckStatusDecision(verifier.AssuranceProduction, production, false))
			before := fetches.Load()
			refused("StatusPolicy.Check", policy.Check(ctx, result.Credentials...))
			refused("RequireValidStatus", verifier.RequireValidStatus(pinned)(ctx, "id", result))
			refused("RequireValidStatusFrom", verifier.RequireValidStatusFrom(pinned, verifier.AnyStatusListSigner)(ctx, "id", result))
			refused("StatusPolicy.Check, no credentials", policy.Check(ctx))
			if n := fetches.Load() - before; n != 0 {
				t.Errorf("%d status lists fetched under a refused policy, want 0", n)
			}
		})
	}
}
