package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// crlServer serves whatever DER body holds, as a distribution point.
type crlServer struct {
	*httptest.Server
	body   atomic.Pointer[[]byte]
	status atomic.Int32
}

func newCRLServer(t *testing.T) *crlServer {
	t.Helper()
	s := &crlServer{}
	s.status.Store(http.StatusOK)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if code := int(s.status.Load()); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		if b := s.body.Load(); b != nil {
			_, _ = w.Write(*b)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *crlServer) serve(b []byte) { s.body.Store(&b) }

// crlAt is a list from ca numbered n, issued hoursAgo, current for
// validFor from then.
func crlAt(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, n int64, hoursAgo int, validFor time.Duration) *x509.RevocationList {
	t.Helper()
	this := time.Now().Add(-time.Duration(hoursAgo) * time.Hour)
	return testcert.CRLFromTemplate(t, &x509.RevocationList{Number: big.NewInt(n), ThisUpdate: this, NextUpdate: this.Add(validFor)}, ca, key)
}

// refreshResult decodes RefreshCRLs' JSON, refusing a key ABI.md
// doesn't document.
func refreshResult(t *testing.T, text string) crlRefreshJSON {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	var out crlRefreshJSON
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("RefreshCRLs JSON %s: %v", text, err)
	}
	if out.ABI != ABIVersion {
		t.Errorf("abi %d, want %d", out.ABI, ABIVersion)
	}
	return out
}

func outcomes(r crlRefreshJSON) []string {
	var out []string
	for _, res := range r.Results {
		out = append(out, res.Outcome)
	}
	return out
}

// A Wallet's RefreshCRLs keeps each list its distribution point's CA
// signed that is current and not older than the one held, reports each
// point's outcome, and never lets a failure evict a good list.
func TestRefreshCRLs_Outcomes(t *testing.T) {
	ca, caKey := testcert.CA(t, "refresh CA")
	other, otherKey := testcert.CA(t, "another CA")
	srv := newCRLServer(t)
	cfg := map[string]any{
		"development": true, "verifier_roots": pemOf("CERTIFICATE", ca.Raw), "revocation": []string{"verifier"},
		"crl_distribution_points": []map[string]string{{"url": srv.URL + "/ca.crl", "issuer": pemOf("CERTIFICATE", ca.Raw)}},
	}
	text, _ := json.Marshal(cfg)
	w, err := NewWallet(string(text), &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	refresh := func(name string, want string) crlRefreshJSON {
		t.Helper()
		out, err := w.RefreshCRLs(nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		r := refreshResult(t, out)
		if got := outcomes(r); !slices.Equal(got, []string{want}) {
			t.Errorf("%s: outcomes %v (%+v), want [%s]", name, got, r.Results, want)
		}
		return r
	}
	held := func() *big.Int {
		t.Helper()
		lists, _ := w.crls.checker().Lists(context.Background())
		if len(lists) != 1 {
			t.Fatalf("%d lists held, want 1", len(lists))
		}
		return lists[0].Number
	}

	five := crlAt(t, ca, caKey, 5, 1, 4*time.Hour)
	srv.serve(five.Raw)
	r := refresh("first", crlUpdated)
	if held().Int64() != 5 {
		t.Errorf("held %v, want 5", held())
	}
	if lists, err := parseCRLs(r.CRLs); err != nil || len(lists) != 1 || lists[0].Number.Int64() != 5 {
		t.Errorf("crls %q: %v, want list 5", r.CRLs, err)
	}
	if r.Results[0].URL != srv.URL+"/ca.crl" || r.Results[0].Error != "" {
		t.Errorf("result %+v", r.Results[0])
	}

	refresh("the same list", crlUnchanged)

	srv.serve(crlAt(t, ca, caKey, 4, 1, 4*time.Hour).Raw)
	r = refresh("an older list", crlFailed)
	if !strings.HasPrefix(r.Results[0].Error, "[protocol]") || held().Int64() != 5 {
		t.Errorf("older: error %q, held %v, want protocol and 5 kept", r.Results[0].Error, held())
	}

	srv.serve(crlAt(t, other, otherKey, 9, 1, 4*time.Hour).Raw)
	r = refresh("another CA's list", crlFailed)
	if !strings.Contains(r.Results[0].Error, "isn't signed") || held().Int64() != 5 {
		t.Errorf("another CA's: error %q, held %v", r.Results[0].Error, held())
	}

	srv.status.Store(http.StatusInternalServerError)
	r = refresh("a failed fetch", crlFailed)
	if held().Int64() != 5 || r.CRLs == "" {
		t.Errorf("after a failed fetch, held %v, crls %q, want 5 kept and returned", held(), r.CRLs)
	}
	srv.status.Store(http.StatusOK)

	srv.serve(make([]byte, 8<<20+1))
	r = refresh("an oversized response", crlFailed)
	if !strings.Contains(r.Results[0].Error, "exceeds") || held().Int64() != 5 {
		t.Errorf("oversized: error %q, held %v", r.Results[0].Error, held())
	}

	srv.serve(crlAt(t, ca, caKey, 6, 0, 4*time.Hour).Raw)
	refresh("a newer list", crlUpdated)
	if held().Int64() != 6 {
		t.Errorf("held %v, want 6", held())
	}
	// SetCRLs still refuses the older list the refresh replaced.
	if err := w.SetCRLs(pemOf("X509 CRL", five.Raw)); code(err) != CodeInvalidInput {
		t.Errorf("SetCRLs(list 5) after refreshing to 6: %v, want invalid_input", err)
	}
}

// next_refresh is halfway from now to the list's nextUpdate, at most an
// hour away; after a failure, within minutes.
func TestRefreshCRLs_NextRefresh(t *testing.T) {
	ca, caKey := testcert.CA(t, "refresh CA")
	srv := newCRLServer(t)
	now := time.Now()
	s := &crlSet{now: func() time.Time { return now }}
	if err := s.configureRefresh(crlRefreshConfig{development: true, points: []crlDistributionPoint{{URL: srv.URL, Issuer: pemOf("CERTIFICATE", ca.Raw)}}}); err != nil {
		t.Fatal(err)
	}
	next := func() time.Duration {
		t.Helper()
		out, err := s.refresh(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		at, err := time.Parse(time.RFC3339, refreshResult(t, out).NextRefresh)
		if err != nil {
			t.Fatal(err)
		}
		return at.Sub(now.Truncate(time.Second))
	}
	// Current for another 40 minutes: due in 20.
	srv.serve(testcert.CRLFromTemplate(t, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(40 * time.Minute)}, ca, caKey).Raw)
	if got := next(); got < 19*time.Minute || got > 21*time.Minute {
		t.Errorf("next_refresh in %v, want 20m", got)
	}
	// Current for a week: due in an hour, the longest wait.
	srv.serve(testcert.CRLFromTemplate(t, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(7 * 24 * time.Hour)}, ca, caKey).Raw)
	if got := next(); got < 59*time.Minute || got > 61*time.Minute {
		t.Errorf("next_refresh in %v, want 1h", got)
	}
	srv.status.Store(http.StatusNotFound)
	if got := next(); got < 4*time.Minute || got > 6*time.Minute {
		t.Errorf("after a failure, next_refresh in %v, want 5m", got)
	}
}

// Outside development, a distribution point on a loopback address isn't
// fetched; one in plain http is refused under crl_require_https; and a
// configuration with no distribution points is not_configured.
func TestRefreshCRLs_Refusals(t *testing.T) {
	ca, caKey := testcert.CA(t, "refresh CA")
	srv := newCRLServer(t)
	srv.serve(testcert.CRL(t, ca, caKey).Raw)
	issuer := pemOf("CERTIFICATE", ca.Raw)
	point := []crlDistributionPoint{{URL: srv.URL, Issuer: issuer}}

	s := &crlSet{}
	if err := s.configureRefresh(crlRefreshConfig{points: point}); err != nil {
		t.Fatal(err)
	}
	out, err := s.refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := refreshResult(t, out); r.Results[0].Outcome != crlFailed || !strings.HasPrefix(r.Results[0].Error, "[network]") || !strings.Contains(r.Results[0].Error, "not allowed") || r.CRLs != "" {
		t.Errorf("a loopback point outside development: %+v, want a network failure and no lists", r)
	}

	for name, cfg := range map[string]crlRefreshConfig{
		"http under crl_require_https": {points: point, requireHTTPS: true},
		"not a URL":                    {points: []crlDistributionPoint{{URL: "ldap://ca.example/crl", Issuer: issuer}}},
		"no issuer":                    {points: []crlDistributionPoint{{URL: srv.URL}}},
		"two issuers":                  {points: []crlDistributionPoint{{URL: srv.URL, Issuer: issuer + issuer}}},
		"repeated":                     {points: append(point, point...)},
	} {
		if err := (&crlSet{}).configureRefresh(cfg); code(err) != CodeInvalidInput {
			t.Errorf("%s: %v, want invalid_input", name, err)
		}
	}

	r, err := NewProximityReader(`{"development": true, "issuer_roots": `+jsonString(issuer)+`, "revocation": ["issuer"]}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.RefreshCRLs(nil); err == nil || !strings.HasPrefix(err.Error(), "[invalid_input:not_configured]") {
		t.Errorf("RefreshCRLs with no points: %v, want invalid_input:not_configured", err)
	}

	op := NewOperation(0)
	op.Cancel()
	if _, err := s.refresh(op.context()); code(err) != CodeCancelled {
		t.Errorf("cancelled: %v, want cancelled", err)
	}
}

// crl_distribution_points_from_roots fetches the distribution point a
// self-signed CA among the roots of a role "revocation" names gives for
// its own list, as an IACA does; a reader's RefreshCRLs uses it.
func TestRefreshCRLs_FromRoots(t *testing.T) {
	srv := newCRLServer(t)
	iaca, key := selfSignedCA(t, "IACA", []string{srv.URL + "/iaca.crl", "ldap://ignored.example/crl"})
	srv.serve(testcert.CRL(t, iaca, key).Raw)

	r, err := NewProximityReader(`{"development": true, "issuer_roots": `+jsonString(pemOf("CERTIFICATE", iaca.Raw))+
		`, "revocation": ["issuer"], "crl_distribution_points_from_roots": true}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.RefreshCRLs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := refreshResult(t, out); len(got.Results) != 1 || got.Results[0].URL != srv.URL+"/iaca.crl" || got.Results[0].Outcome != crlUpdated {
		t.Errorf("from roots: %+v, want the IACA's point updated", got.Results)
	}
	// An explicit entry for the URL wins; another root naming it is
	// refused, to be bound explicitly.
	other, _ := testcert.CA(t, "another IACA")
	explicit := []crlPoint{{url: srv.URL + "/iaca.crl", issuer: other}}
	points, err := pointsFromRoots(explicit, []string{pemOf("CERTIFICATE", iaca.Raw)}, false)
	if err != nil || len(points) != 1 || points[0].issuer != other {
		t.Errorf("explicit entry: %v, %v, want it kept alone", points, err)
	}
	if points, _ := pointsFromRoots(nil, []string{pemOf("CERTIFICATE", iaca.Raw)}, true); len(points) != 0 {
		t.Errorf("with crl_require_https, %v, want the http point left out", points)
	}
	twin, _ := selfSignedCA(t, "IACA 2", iaca.CRLDistributionPoints)
	if _, err := pointsFromRoots([]crlPoint{{url: "https://unrelated.example/crl", issuer: other}}, []string{pemOf("CERTIFICATE", iaca.Raw), pemOf("CERTIFICATE", twin.Raw)}, false); code(err) != CodeInvalidInput {
		t.Errorf("two roots naming one point: %v, want invalid_input", err)
	}

	// A role declined isn't fetched for.
	r, err = NewProximityReader(`{"development": true, "issuer_roots": `+jsonString(pemOf("CERTIFICATE", iaca.Raw))+
		`, "no_revocation_check": ["issuer"], "crl_distribution_points_from_roots": true}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.RefreshCRLs(nil); code(err) != CodeInvalidInput {
		t.Errorf("from the roots of no named role: %v, want not_configured", err)
	}
}

// selfSignedCA is a self-signed CA certificate naming the CRL
// distribution points cdps, as an IACA's does, and its key.
func selfSignedCA(t *testing.T, name string, cdps []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: cdps,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// RefreshCRLs' JSON has exactly the keys ABI.md documents for it.
func TestRefreshCRLs_JSONMatchesABI(t *testing.T) {
	doc, err := os.ReadFile("ABI.md")
	if err != nil {
		t.Fatal(err)
	}
	keys := func(v any) []string {
		var out []string
		ty := reflect.TypeOf(v)
		for i := range ty.NumField() {
			if name, _, _ := strings.Cut(ty.Field(i).Tag.Get("json"), ","); name != "" {
				out = append(out, name)
			}
		}
		return out
	}
	want := map[string][]string{
		`{"abi", "results", "crls", "next_refresh"}`: append([]string{"abi"}, keys(crlRefreshJSON{})...),
		`{"url", "outcome", "error"}`:                keys(crlRefreshResult{}),
	}
	for documented, fields := range want {
		if !strings.Contains(string(doc), documented) {
			t.Errorf("ABI.md doesn't document %s", documented)
		}
		for _, f := range fields {
			if !strings.Contains(documented, `"`+f+`"`) {
				t.Errorf("%q isn't in ABI.md's %s", f, documented)
			}
		}
	}
	for _, o := range []string{crlUpdated, crlUnchanged, crlFailed} {
		if !strings.Contains(string(doc), "`"+o+"`") {
			t.Errorf("ABI.md doesn't document the outcome %q", o)
		}
	}
}
