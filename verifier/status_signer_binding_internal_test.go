package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Each check binds a status list's signer to its own credential's
// issuer, whatever the Checker it starts from says: a caller's
// Options.Issuer, IssuerKey or UnboundSigner (which StatusPolicy
// refuses) can't stand in for the binding, for an mdoc (ISO/IEC
// 18013-5 §12.3.6.2) nor for an SD-JWT VC under StatusIssuers.
func TestRequireValid_CallerSignerOptionsDontReplaceTheBinding(t *testing.T) {
	ctx := context.Background()
	pins := func(signer *x509.Certificate, issuer string) map[string]func(*statuslist.VerifyOptions) {
		return map[string]func(*statuslist.VerifyOptions){
			"Issuer":        func(o *statuslist.VerifyOptions) { o.Issuer = issuer },
			"IssuerKey":     func(o *statuslist.VerifyOptions) { o.IssuerKey = signer.PublicKey.(*ecdsa.PublicKey) },
			"UnboundSigner": func(o *statuslist.VerifyOptions) { o.UnboundSigner = statuslist.AnyListSigner },
			"all three": func(o *statuslist.VerifyOptions) {
				o.Issuer, o.IssuerKey, o.UnboundSigner = issuer, signer.PublicKey, statuslist.AnyListSigner
			},
		}
	}

	t.Run("mdoc", func(t *testing.T) {
		iaca, iacaKey := testcert.CA(t, "IACA")
		other, otherKey := testcert.CA(t, "another IACA")
		ds, _ := testcert.Leaf(t, "document signer", iaca, iacaKey)
		roots := x509.NewCertPool()
		roots.AddCert(iaca)
		roots.AddCert(other)
		foreignSigner, foreignKey := testcert.Leaf(t, "status signer under another IACA", other, otherKey)
		var base string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		vc := VerifiedCredential{
			MdocStatus:  &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 0, URI: base + "/list"}},
			IssuerChain: [][]byte{ds.Raw},
		}
		for name, set := range pins(foreignSigner, "https://issuer-b.example") {
			checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
			set(&checker.Options)
			if err := requireValid(ctx, checker, nil, vc); err == nil || !strings.Contains(err.Error(), "§12.3.6.2") {
				t.Errorf("%s: %v, want the list refused by the §12.3.6.2 binding", name, err)
			}
		}
	})

	t.Run("SD-JWT VC under StatusIssuers", func(t *testing.T) {
		ca, caKey := testcert.CA(t, "shared root")
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		const issuerA, issuerB = "https://issuer-a.example", "https://issuer-b.example"
		u, err := url.Parse(issuerB)
		if err != nil {
			t.Fatal(err)
		}
		signerB, keyB := testcert.Issue(t, &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u}}, ca, caKey)
		var base string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sl, err := statuslist.New(statuslist.Bits1, []uint8{0}, "")
			if err != nil {
				t.Error(err)
				return
			}
			token, err := statuslist.IssueTokenX5C(keyB, "ES256", statuslist.TokenClaims{Sub: base + r.URL.Path, Iat: time.Now().Unix(), StatusList: sl}, []*x509.Certificate{signerB})
			if err != nil {
				t.Error(err)
				return
			}
			w.Header().Set("Content-Type", statuslist.TokenMediaType)
			_, _ = w.Write([]byte(token))
		}))
		defer srv.Close()
		base = srv.URL
		// Issuer A's credential, whose list at its uri issuer B signed.
		vc := VerifiedCredential{Claims: map[string]any{
			"iss": issuerA, "status": map[string]any{"status_list": map[string]any{"idx": float64(0), "uri": base + "/a"}},
		}}
		errNotStatusIssuer := errors.New("not a Status Issuer")
		refuseAll := func(string, *x509.Certificate, [][]*x509.Certificate) error { return errNotStatusIssuer }
		for name, set := range pins(signerB, issuerB) {
			checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
			set(&checker.Options)
			if err := requireValid(ctx, checker, refuseAll, vc); !errors.Is(err, errNotStatusIssuer) {
				t.Errorf("%s: %v, want issuer B's list refused by StatusIssuers", name, err)
			}
		}
	})
}
