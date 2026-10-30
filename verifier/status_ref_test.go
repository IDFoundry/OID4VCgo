package verifier_test

import (
	"context"
	"crypto/x509"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

func TestVerifiedCredential_StatusListRef(t *testing.T) {
	const uri = "https://issuer.example/statuslists/1"
	cases := map[string]struct {
		vc              verifier.VerifiedCredential
		want            statuslist.StatusListRef
		wantCWT, wantOK bool
		wantErr         bool
	}{
		"sd-jwt with status": {
			vc:   verifier.VerifiedCredential{Claims: map[string]any{"status": map[string]any{"status_list": map[string]any{"idx": float64(7), "uri": uri}}}},
			want: statuslist.StatusListRef{Idx: 7, URI: uri}, wantOK: true,
		},
		"sd-jwt without status": {vc: verifier.VerifiedCredential{Claims: map[string]any{"vct": "x"}}},
		// A status that can't be read isn't "no status".
		"sd-jwt status not an object": {vc: verifier.VerifiedCredential{Claims: map[string]any{"status": uri + "#5"}}, wantErr: true},
		"sd-jwt null status":          {vc: verifier.VerifiedCredential{Claims: map[string]any{"status": nil}}, wantErr: true},
		"sd-jwt malformed status": {
			vc:      verifier.VerifiedCredential{Claims: map[string]any{"status": map[string]any{"status_list": "nope"}}},
			wantErr: true,
		},
		"mdoc with status": {
			vc:   verifier.VerifiedCredential{MdocStatus: &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 9, URI: uri}}},
			want: statuslist.StatusListRef{Idx: 9, URI: uri}, wantCWT: true, wantOK: true,
		},
		// An MSO status naming only a mechanism mdoc.Status doesn't
		// model decodes with neither member: unknown, not absent.
		"mdoc status naming no known mechanism": {vc: verifier.VerifiedCredential{MdocStatus: &mdoc.Status{}}, wantErr: true},
		"sd-jwt status naming no known mechanism": {
			vc:      verifier.VerifiedCredential{Claims: map[string]any{"status": map[string]any{"status_List": map[string]any{"idx": float64(7), "uri": uri}}}},
			wantErr: true,
		},
		"mdoc identifier list only": {
			vc:      verifier.VerifiedCredential{MdocStatus: &mdoc.Status{IdentifierList: &mdoc.IdentifierListRef{URI: uri}}},
			wantErr: true,
		},
		"mdoc index beyond int range": {
			vc:   verifier.VerifiedCredential{MdocStatus: &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: math.MaxUint64, URI: uri}}},
			want: statuslist.StatusListRef{Idx: math.MaxUint64, URI: uri}, wantCWT: true, wantOK: true,
		},
	}
	for name, c := range cases {
		ref, cwt, ok, err := c.vc.StatusListRef()
		if (err != nil) != c.wantErr || ok != c.wantOK || cwt != c.wantCWT || ref != c.want {
			t.Errorf("%s: StatusListRef = %+v, cwt %v, ok %v, err %v", name, ref, cwt, ok, err)
		}
	}
}

// RequireValidStatus refuses an answer holding a credential whose
// status isn't VALID or can't be read, and passes one whose credentials
// are VALID or carry no status.
func TestRequireValidStatus(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	leaf, leafKey := testcert.Leaf(t, "status signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sl, err := statuslist.New(statuslist.Bits1, []uint8{0, 1}, "")
		if err != nil {
			t.Error(err)
			return
		}
		token, err := statuslist.IssueTokenX5C(leafKey, jose.ES256, statuslist.TokenClaims{Sub: uri, Iat: time.Now().Unix(), StatusList: sl}, []*x509.Certificate{leaf})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", statuslist.TokenMediaType)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()
	uri = srv.URL + "/statuslists/1"
	accept := verifier.RequireValidStatus(statuslist.Checker{
		Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots,
	})
	// Issued with the status list signer's key, which binds the list to it.
	withStatus := func(idx float64, u string) verifier.VerifiedCredential {
		return verifier.VerifiedCredential{
			Claims:      map[string]any{"status": map[string]any{"status_list": map[string]any{"idx": idx, "uri": u}}},
			IssuerChain: [][]byte{leaf.Raw},
		}
	}
	unbound := withStatus(0, uri)
	unbound.IssuerChain = nil
	ctx := context.Background()
	cases := map[string]struct {
		creds   []verifier.VerifiedCredential
		refused bool
	}{
		"valid":                {creds: []verifier.VerifiedCredential{withStatus(0, uri)}},
		"no status":            {creds: []verifier.VerifiedCredential{{Claims: map[string]any{"vct": "x"}}}},
		"revoked":              {creds: []verifier.VerifiedCredential{withStatus(1, uri)}, refused: true},
		"one of two revoked":   {creds: []verifier.VerifiedCredential{withStatus(0, uri), withStatus(1, uri)}, refused: true},
		"unreadable":           {creds: []verifier.VerifiedCredential{withStatus(0, srv.URL+"/statuslists/2")}, refused: true},
		"malformed reference":  {creds: []verifier.VerifiedCredential{{Claims: map[string]any{"status": map[string]any{"status_list": "nope"}}}}, refused: true},
		"status not an object": {creds: []verifier.VerifiedCredential{{Claims: map[string]any{"status": uri + "#0"}}}, refused: true},
		// Nothing ties its list's signer to its issuer.
		"no issuer to bind to": {creds: []verifier.VerifiedCredential{unbound}, refused: true},
	}
	for name, tc := range cases {
		err := accept(ctx, "id", verifier.VerifyResponseResult{Credentials: tc.creds})
		if (err != nil) != tc.refused {
			t.Errorf("%s: %v, want refused=%v", name, err, tc.refused)
		}
	}
	var notValid *statuslist.NotValidError
	if err := accept(ctx, "id", verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{withStatus(1, uri)}}); !errors.As(err, &notValid) || notValid.Status != statuslist.StatusInvalid {
		t.Errorf("revoked: %v, want a NotValidError", err)
	}
	// Unless a StatusIssuerPolicy decides who may sign it.
	anySigner := verifier.RequireValidStatusFrom(statuslist.Checker{
		Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots,
	}, verifier.AnyStatusListSigner)
	if err := anySigner(ctx, "id", verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{unbound}}); err != nil {
		t.Errorf("no issuer to bind to, with AnyStatusListSigner: %v", err)
	}
}

// RequireStatusReference refuses an answer with a credential that has
// no status reference, which RequireValidStatus would let through, and
// otherwise leaves the answer to the Accept it wraps.
func TestRequireStatusReference(t *testing.T) {
	sdjwt := verifier.VerifiedCredential{CredentialQueryID: "pid", Claims: map[string]any{"status": map[string]any{"status_list": map[string]any{"idx": float64(0), "uri": "https://status.example/1"}}}}
	mdl := verifier.VerifiedCredential{CredentialQueryID: "mdl", MdocStatus: &mdoc.Status{StatusList: &mdoc.StatusListRef{URI: "https://status.example/2"}}}
	identifierList := verifier.VerifiedCredential{CredentialQueryID: "mdl", MdocStatus: &mdoc.Status{IdentifierList: &mdoc.IdentifierListRef{URI: "https://status.example/3"}}}
	noStatus := verifier.VerifiedCredential{CredentialQueryID: "unrevocable", Claims: map[string]any{"vct": "x"}}
	noMdocStatus := verifier.VerifiedCredential{CredentialQueryID: "unrevocable", Claims: map[string]any{"org.iso.18013.5.1": map[string]any{}}}
	unknownMdocStatus := verifier.VerifiedCredential{CredentialQueryID: "unknown", MdocStatus: &mdoc.Status{}}
	unknownStatus := verifier.VerifiedCredential{CredentialQueryID: "unknown", Claims: map[string]any{"status": map[string]any{"status_List": map[string]any{}}}}
	ctx := context.Background()

	wrapped := 0
	accept := verifier.RequireStatusReference(func(context.Context, string, verifier.VerifyResponseResult) error {
		wrapped++
		return nil
	})
	for name, tc := range map[string]struct {
		creds   []verifier.VerifiedCredential
		refused bool
	}{
		"SD-JWT VC and mdoc with references": {creds: []verifier.VerifiedCredential{sdjwt, mdl}},
		"an identifier list":                 {creds: []verifier.VerifiedCredential{identifierList}},
		"an SD-JWT VC without one":           {creds: []verifier.VerifiedCredential{sdjwt, noStatus}, refused: true},
		"an mdoc without one":                {creds: []verifier.VerifiedCredential{noMdocStatus}, refused: true},
		// Nothing could check a status naming no known mechanism.
		"an mdoc status naming no known mechanism":   {creds: []verifier.VerifiedCredential{unknownMdocStatus}, refused: true},
		"an SD-JWT status naming no known mechanism": {creds: []verifier.VerifiedCredential{unknownStatus}, refused: true},
	} {
		wrapped = 0
		err := accept(ctx, "id", verifier.VerifyResponseResult{Credentials: tc.creds})
		if (err != nil) != tc.refused {
			t.Errorf("%s: %v, want refused=%v", name, err, tc.refused)
		}
		if want := map[bool]int{false: 1, true: 0}[tc.refused]; wrapped != want {
			t.Errorf("%s: the wrapped Accept ran %d times, want %d", name, wrapped, want)
		}
	}
	if err := verifier.RequireStatusReference(nil)(ctx, "id", verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{sdjwt}}); err != nil {
		t.Errorf("no wrapped Accept: %v", err)
	}
	refusal := errors.New("refused")
	if err := verifier.RequireStatusReference(func(context.Context, string, verifier.VerifyResponseResult) error { return refusal })(ctx, "id", verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{sdjwt}}); !errors.Is(err, refusal) {
		t.Errorf("the wrapped Accept's refusal: %v", err)
	}
}
