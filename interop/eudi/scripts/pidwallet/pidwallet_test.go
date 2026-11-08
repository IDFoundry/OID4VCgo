package main

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
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

func TestLoginFormAction(t *testing.T) {
	base, _ := url.Parse("https://localhost:19443/idp/realms/r/protocol/openid-connect/auth")
	page := `<html><form id="kc-form-login" class="x" action="https://localhost:19443/idp/realms/r/login-actions/authenticate?session_code=a&amp;execution=b" method="post"></form></html>`
	got, err := loginFormAction(page, base)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://localhost:19443/idp/realms/r/login-actions/authenticate?session_code=a&execution=b"; got != want {
		t.Fatalf("action %q, want %q", got, want)
	}
	if _, err := loginFormAction(`<form id="kc-form-login" action="https://evil.example/steal">`, base); err == nil {
		t.Fatal("a form posting to another origin was accepted")
	}
	if _, err := loginFormAction(`<p>We are sorry...</p>`, base); err == nil || !strings.Contains(err.Error(), "We are sorry") {
		t.Fatalf("no form: %v", err)
	}
	if _, err := loginFormAction(`<form id="kc-form-login">`, base); err == nil {
		t.Fatal("a form with no action was accepted")
	}
}

func TestPageText(t *testing.T) {
	page := "<html><style>p{}</style><script>x()</script><p>Invalid   &amp; expired</p></html>"
	if got := pageText(page); got != "Invalid & expired" {
		t.Fatalf("pageText %q", got)
	}
	if got := pageText(strings.Repeat("a", 500)); len(got) != 200 {
		t.Fatalf("pageText length %d", len(got))
	}
}

// keycloakStub stands in for Keycloak's authorization endpoint and
// login form.
func keycloakStub(t *testing.T, redirectURI string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "AUTH_SESSION_ID", Value: "s1", Path: "/"})
		http.Redirect(w, r, "/login?tab=1", http.StatusFound)
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form id="kc-form-login" action="/authenticate?tab=1&amp;x=2" method="post">`))
	})
	mux.HandleFunc("POST /authenticate", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("AUTH_SESSION_ID"); err != nil || c.Value != "s1" {
			http.Error(w, "<p>no session</p>", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("x") != "2" || r.FormValue("username") != "tneal" || r.FormValue("password") != "password" {
			http.Error(w, "<p>Invalid username or password.</p>", http.StatusOK)
			return
		}
		w.Header().Set("Location", redirectURI+"?code=c1&state=s&iss=i")
		w.WriteHeader(http.StatusFound)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLogin(t *testing.T) {
	const redirect = "dev.idfoundry.oid4vcgo.interop:/callback"
	srv := keycloakStub(t, redirect)
	got, err := login(context.Background(), srv.Client(), srv.URL+"/auth", redirect, "tneal", "password")
	if err != nil {
		t.Fatal(err)
	}
	if got != redirect+"?code=c1&state=s&iss=i" {
		t.Fatalf("redirect %q", got)
	}
	if _, err := login(context.Background(), srv.Client(), srv.URL+"/auth", redirect, "tneal", "wrong"); err == nil {
		t.Fatal("a refused sign-in returned a redirect")
	}
}

func TestRecorder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("DPoP-Nonce", "n")
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", algs="ES256"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	rec := &recorder{next: http.DefaultTransport}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/credential?secret=1", nil)
	req.Header.Set("DPoP", "proof")
	res, err := (&http.Client{Transport: rec}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	got := rec.recorded()
	if len(got) != 1 {
		t.Fatalf("%d exchanges", len(got))
	}
	e := got[0]
	if e.Path != "/credential" || e.Status != 401 || !e.DPoP || e.Attestation || !e.DPoPNonce || e.Error != "use_dpop_nonce" {
		t.Fatalf("exchange %+v", e)
	}
	if rec.count(func(e exchange) bool { return e.DPoPNonce }) != 1 {
		t.Fatal("count")
	}
}

// testProvider is a provider whose signers are under a throwaway CA.
func testProvider(t *testing.T) *provider {
	t.Helper()
	ca, caKey := testCA(t)
	p := &provider{statusURI: "https://host.docker.internal:19445/statuslists/jwt", walletStatusIdx: 1, keyStorageStatus: 0,
		now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	p.waKey, p.waCert = testLeaf(t, ca, caKey)
	p.kaKey, p.kaCert = testLeaf(t, ca, caKey)
	return p
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Unix(0, 0), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: time.Unix(0, 0), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

// verified checks compact's signature with cert and returns its header
// and claims.
func verified(t *testing.T, compact string, cert *x509.Certificate) (map[string]any, map[string]any) {
	t.Helper()
	header, payload, err := jose.Verify(jose.ES256, cert.PublicKey, compact)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return header, claims
}

func TestWalletAttestation(t *testing.T) {
	p := testProvider(t)
	instance, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	compact, err := p.WalletAttestation(context.Background(), "eudiw-abca", instance.Public())
	if err != nil {
		t.Fatal(err)
	}
	header, claims := verified(t, compact, p.waCert)
	if header["typ"] != "oauth-client-attestation+jwt" || len(header["x5c"].([]any)) != 1 {
		t.Fatalf("header %v", header)
	}
	for _, name := range []string{"iss", "sub", "exp", "cnf", "wallet_name", "wallet_version", "wallet_solution_certification_information", "client_status"} {
		if claims[name] == nil {
			t.Errorf("no %s", name)
		}
	}
	if claims["sub"] != "eudiw-abca" {
		t.Errorf("sub %v", claims["sub"])
	}
	ref := claims["client_status"].(map[string]any)["status"].(map[string]any)["status_list"].(map[string]any)
	if ref["idx"] != float64(1) || ref["uri"] != p.statusURI {
		t.Errorf("client_status %v", ref)
	}
}

func TestKeyAttestation(t *testing.T) {
	p := testProvider(t)
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	compact, err := p.KeyAttestation(context.Background(), nil, []*ecdsa.PublicKey{&k1.PublicKey, &k2.PublicKey}, "c-nonce")
	if err != nil {
		t.Fatal(err)
	}
	header, claims := verified(t, compact, p.kaCert)
	if header["typ"] != "key-attestation+jwt" {
		t.Fatalf("typ %v", header["typ"])
	}
	if len(claims["attested_keys"].([]any)) != 2 || claims["nonce"] != "c-nonce" || claims["exp"] == nil || claims["certification"] == nil {
		t.Fatalf("claims %v", claims)
	}
	for _, name := range []string{"key_storage", "user_authentication"} {
		if v := claims[name].([]any); len(v) != 1 || v[0] != "iso_18045_high" {
			t.Errorf("%s %v", name, v)
		}
	}
	if claims["key_storage_status"].(map[string]any)["exp"] == nil {
		t.Error("key_storage_status has no exp")
	}
	if _, err := p.KeyAttestation(context.Background(), nil, nil, "n"); err == nil {
		t.Fatal("an attestation of no keys was issued")
	}
}

func TestKeyIndexProof(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	compact, err := keyIndexProof(key, "https://issuer.example", "n1", "ka.jwt.sig", time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := jose.Verify(jose.ES256, key.Public(), compact)
	if err != nil {
		t.Fatal(err)
	}
	if header["kid"] != "0" || header["key_attestation"] != "ka.jwt.sig" || header["typ"] != "openid4vci-proof+jwt" || header["jwk"] != nil {
		t.Fatalf("header %v", header)
	}
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	if claims["aud"] != "https://issuer.example" || claims["nonce"] != "n1" || claims["iat"] != float64(1_800_000_000) {
		t.Fatalf("claims %v", claims)
	}
}

func TestClaimNames(t *testing.T) {
	got := claimNames(map[string]any{
		"given_name": "a", "address": map[string]any{"street": "s"},
		"eu.europa.ec.eudi.pid.1": map[string]any{"family_name": "b", "birth_date": "c"},
	})
	want := []string{"address", "eu.europa.ec.eudi.pid.1/birth_date", "eu.europa.ec.eudi.pid.1/family_name", "given_name"}
	if !slices.Equal(got, want) {
		t.Fatalf("claimNames %v, want %v", got, want)
	}
}

func TestSummarize(t *testing.T) {
	env := &environment{rec: &recorder{exchanges: []exchange{
		{Method: "GET", Path: "/.well-known/openid-credential-issuer/pid-issuer", Status: 200, ContentType: "application/jwt"},
		{Method: "POST", Path: "/idp/realms/r/challenge", Status: 200},
		{Method: "POST", Path: "/idp/realms/r/challenge", Status: 200},
		{Method: "POST", Path: "/pid-issuer/wallet/nonceEndpoint", Status: 200, DPoPNonce: true},
		{Method: "POST", Path: "/pid-issuer/wallet/credentialEndpoint", Status: 401, Error: "use_dpop_nonce", DPoPNonce: true},
		{Method: "POST", Path: "/pid-issuer/wallet/credentialEndpoint", Status: 200, ContentType: "application/jwt"},
	}}, encryptedRequest: true}
	var res result
	env.summarize(&res)
	if !res.SignedMetadata || res.Challenges != 2 || res.DPoPNonces != 2 || res.DPoPNonceRetries != 1 || !res.EncryptedResponse || !res.EncryptedRequest {
		t.Fatalf("summary %+v", res)
	}
}
