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
		"sd-jwt malformed status": {
			vc:      verifier.VerifiedCredential{Claims: map[string]any{"status": map[string]any{"status_list": "nope"}}},
			wantErr: true,
		},
		"mdoc with status": {
			vc:   verifier.VerifiedCredential{MdocStatus: &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 9, URI: uri}}},
			want: statuslist.StatusListRef{Idx: 9, URI: uri}, wantCWT: true, wantOK: true,
		},
		"mdoc status without a list": {vc: verifier.VerifiedCredential{MdocStatus: &mdoc.Status{}}},
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
	withStatus := func(idx float64, u string) verifier.VerifiedCredential {
		return verifier.VerifiedCredential{Claims: map[string]any{"status": map[string]any{"status_list": map[string]any{"idx": idx, "uri": u}}}}
	}
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
		"mdoc identifier list": {creds: []verifier.VerifiedCredential{{MdocStatus: &mdoc.Status{IdentifierList: &mdoc.IdentifierListRef{URI: uri}}}}, refused: true},
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
}
