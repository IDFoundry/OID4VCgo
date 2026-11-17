package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const signedMetadataPath = "/.well-known/openid-credential-issuer/i"

// serveMetadata starts a server answering the metadata path with
// respond's content type and body, given the issuer URL and the
// request's Accept header.
func serveMetadata(t *testing.T, respond func(issuerURL, accept string) (string, string)) string {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != signedMetadataPath {
			http.NotFound(w, r)
			return
		}
		contentType, body := respond(srv.URL+"/i", r.Header.Get("Accept"))
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/i"
}

func signedMetadataWallet(t *testing.T, roots *x509.CertPool, require bool) *wallet.Wallet {
	t.Helper()
	cfg := validConfig()
	cfg.IssuerMetadataRoots, cfg.RequireSignedIssuerMetadata = roots, require
	deps := validDependencies()
	deps.HTTP = http.DefaultClient
	w, err := wallet.New(cfg, deps)
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}
	return w
}

// signMetadataClaims signs claims as a metadata JWT with the given
// signer and x5c, for the cases SignMetadataJWS won't produce.
func signMetadataClaims(t *testing.T, key *ecdsa.PrivateKey, cert *x509.Certificate, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jose.Sign(jose.ES256, key, map[string]any{
		"typ": issuer.MetadataJWSTyp, "x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestFetchCredentialIssuerMetadata_Signed(t *testing.T) {
	root, rootKey := testcert.CA(t, "metadata root")
	mid, midKey := testcert.Intermediate(t, "metadata intermediate", root, rootKey)
	leaf, leafKey := testcert.Leaf(t, "metadata signer", mid, midKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	otherRoot, _ := testcert.CA(t, "another root")
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(otherRoot)

	var want oid4vci.Metadata
	signed := func(issuerURL, accept string) (string, string) {
		want = testMetadata(t, issuerURL)
		if !strings.Contains(accept, "application/jwt") {
			body, _ := json.Marshal(want)
			return "application/json", string(body)
		}
		token, err := issuer.SignMetadataJWS(want, leafKey, jose.ES256, leaf, mid)
		if err != nil {
			t.Fatal(err)
		}
		return "application/jwt", token
	}
	issuerURL := serveMetadata(t, signed)

	got, err := signedMetadataWallet(t, roots, true).FetchCredentialIssuerMetadata(t.Context(), issuerURL)
	if err != nil {
		t.Fatalf("signed metadata under a trusted root: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("metadata = %+v, want %+v", got, want)
	}
	if _, err := signedMetadataWallet(t, otherRoots, false).FetchCredentialIssuerMetadata(t.Context(), issuerURL); err == nil {
		t.Error("used signed metadata whose signer chains to an untrusted root")
	}
	// Without roots, the Wallet doesn't ask for signed metadata and gets
	// plain JSON.
	if _, err := newDiscoveryTestWallet(t).FetchCredentialIssuerMetadata(t.Context(), issuerURL); err != nil {
		t.Errorf("unsigned fetch without roots: %v", err)
	}

	plain := serveMetadata(t, func(issuerURL, _ string) (string, string) {
		body, _ := json.Marshal(testMetadata(t, issuerURL))
		return "application/json", string(body)
	})
	if _, err := signedMetadataWallet(t, roots, false).FetchCredentialIssuerMetadata(t.Context(), plain); err != nil {
		t.Errorf("plain metadata, signature not required: %v", err)
	}
	if _, err := signedMetadataWallet(t, roots, true).FetchCredentialIssuerMetadata(t.Context(), plain); err == nil {
		t.Error("used plain metadata though signed metadata is required")
	}

	alwaysSigned := serveMetadata(t, func(issuerURL, _ string) (string, string) {
		token, err := issuer.SignMetadataJWS(testMetadata(t, issuerURL), leafKey, jose.ES256, leaf, mid)
		if err != nil {
			t.Fatal(err)
		}
		return "application/jwt", token
	})
	if _, err := newDiscoveryTestWallet(t).FetchCredentialIssuerMetadata(t.Context(), alwaysSigned); err == nil {
		t.Error("used signed metadata it has no roots to verify")
	}
}

// The signed metadata's own claims are checked: sub names the issuer,
// iat isn't in the future, exp isn't past, and the signer's certificate
// isn't self-signed.
func TestFetchCredentialIssuerMetadata_SignedClaims(t *testing.T) {
	root, rootKey := testcert.CA(t, "metadata root")
	leaf, leafKey := testcert.Leaf(t, "metadata signer", root, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	selfSigned, selfSignedKey := testcert.SelfSignedLeaf(t, "self-signed signer")
	selfRoots := x509.NewCertPool()
	selfRoots.AddCert(selfSigned)
	now := time.Now().Unix()
	for name, tc := range map[string]struct {
		claims func(issuerURL string) map[string]any
		key    *ecdsa.PrivateKey
		cert   *x509.Certificate
		roots  *x509.CertPool
		ok     bool
	}{
		"valid":          {claims: func(u string) map[string]any { return map[string]any{"sub": u, "iat": now, "exp": now + 3600} }, ok: true},
		"another issuer": {claims: func(string) map[string]any { return map[string]any{"sub": "https://other.example", "iat": now} }},
		"no iat":         {claims: func(u string) map[string]any { return map[string]any{"sub": u} }},
		"iat in future":  {claims: func(u string) map[string]any { return map[string]any{"sub": u, "iat": now + 3600} }},
		"expired":        {claims: func(u string) map[string]any { return map[string]any{"sub": u, "iat": now - 7200, "exp": now - 3600} }},
		"not valid yet":  {claims: func(u string) map[string]any { return map[string]any{"sub": u, "iat": now, "nbf": now + 3600} }},
		"fractional times": {claims: func(u string) map[string]any {
			return map[string]any{"sub": u, "iat": float64(now) + 0.25, "exp": float64(now) + 3600.5}
		}, ok: true},
		"self-signed cert": {claims: func(u string) map[string]any { return map[string]any{"sub": u, "iat": now} }, key: selfSignedKey, cert: selfSigned, roots: selfRoots},
		// A reader matching names exactly takes a different endpoint.
		"case-variant member": {claims: func(u string) map[string]any {
			return map[string]any{"sub": u, "iat": now, "Credential_Endpoint": "https://attacker.example/credential"}
		}},
	} {
		key, cert, pool := leafKey, leaf, roots
		if tc.key != nil {
			key, cert, pool = tc.key, tc.cert, tc.roots
		}
		issuerURL := serveMetadata(t, func(issuerURL, _ string) (string, string) {
			body, _ := json.Marshal(testMetadata(t, issuerURL))
			claims := map[string]any{}
			_ = json.Unmarshal(body, &claims)
			for k, v := range tc.claims(issuerURL) {
				claims[k] = v
			}
			return "application/jwt", signMetadataClaims(t, key, cert, claims)
		})
		_, err := signedMetadataWallet(t, pool, true).FetchCredentialIssuerMetadata(t.Context(), issuerURL)
		if tc.ok != (err == nil) {
			t.Errorf("%s: err = %v, want ok = %v", name, err, tc.ok)
		}
	}
}

func TestNewRequireSignedIssuerMetadataNeedsRoots(t *testing.T) {
	cfg := validConfig()
	cfg.RequireSignedIssuerMetadata = true
	if _, err := wallet.New(cfg, validDependencies()); err == nil {
		t.Error("New accepted require_signed_issuer_metadata without issuer_metadata_roots")
	}
}

// RequireIssuerMetadataName refuses signed metadata whose certificate
// doesn't name the issuer, and MaxIssuerMetadataAge metadata issued too
// long ago; without them, both are accepted.
func TestFetchCredentialIssuerMetadata_SignedNameAndAge(t *testing.T) {
	root, rootKey := testcert.CA(t, "metadata root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	naming := func(uri string) *x509.Certificate {
		u, _ := url.Parse(uri)
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
		}, root, &key.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	now := time.Now()
	for name, tc := range map[string]struct {
		certNames   func(issuerURL string) string
		iat         time.Time
		requireName bool
		maxAge      time.Duration
		ok          bool
	}{
		"names the issuer, required":         {func(u string) string { return u }, now, true, 0, true},
		"names another issuer, required":     {func(string) string { return "https://other.example" }, now, true, 0, false},
		"names another issuer, not required": {func(string) string { return "https://other.example" }, now, false, 0, true},
		"recent, with a max age":             {func(u string) string { return u }, now.Add(-time.Minute), false, time.Hour, true},
		"too old, with a max age":            {func(u string) string { return u }, now.Add(-2 * time.Hour), false, time.Hour, false},
		"old, without a max age":             {func(u string) string { return u }, now.Add(-2 * time.Hour), false, 0, true},
	} {
		issuerURL := serveMetadata(t, func(issuerURL, _ string) (string, string) {
			body, _ := json.Marshal(testMetadata(t, issuerURL))
			claims := map[string]any{}
			_ = json.Unmarshal(body, &claims)
			claims["sub"], claims["iat"] = issuerURL, tc.iat.Unix()
			return "application/jwt", signMetadataClaims(t, key, naming(tc.certNames(issuerURL)), claims)
		})
		cfg := validConfig()
		cfg.IssuerMetadataRoots, cfg.RequireSignedIssuerMetadata = roots, true
		cfg.RequireIssuerMetadataName, cfg.MaxIssuerMetadataAge = tc.requireName, tc.maxAge
		deps := validDependencies()
		deps.HTTP = http.DefaultClient
		w, err := wallet.New(cfg, deps)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.FetchCredentialIssuerMetadata(t.Context(), issuerURL); tc.ok != (err == nil) {
			t.Errorf("%s: err = %v, want ok = %v", name, err, tc.ok)
		}
	}
}

// Metadata refused because the configuration doesn't take its issuer —
// unsigned where it must be signed, or signed with a certificate or sub
// naming another issuer — wraps ErrUntrustedIssuer. A signer the roots
// don't anchor, or expired metadata, is refused without it.
func TestFetchCredentialIssuerMetadata_UntrustedIssuer(t *testing.T) {
	root, rootKey := testcert.CA(t, "metadata root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	otherRoot, otherRootKey := testcert.CA(t, "another root")
	signer := func(uri string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		return testcert.Issue(t, &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u}}, ca, caKey)
	}
	now := time.Now().Unix()
	for name, tc := range map[string]struct {
		respond   func(issuerURL string, claims map[string]any) string
		untrusted bool
	}{
		"unsigned": {func(_ string, claims map[string]any) string {
			body, _ := json.Marshal(claims)
			return string(body)
		}, true},
		"certificate naming another issuer": {func(issuerURL string, claims map[string]any) string {
			cert, key := signer("https://other.example", root, rootKey)
			return signMetadataClaims(t, key, cert, claims)
		}, true},
		"sub naming another issuer": {func(issuerURL string, claims map[string]any) string {
			cert, key := signer(issuerURL, root, rootKey)
			claims["sub"] = "https://other.example"
			return signMetadataClaims(t, key, cert, claims)
		}, true},
		"signer under another root": {func(issuerURL string, claims map[string]any) string {
			cert, key := signer(issuerURL, otherRoot, otherRootKey)
			return signMetadataClaims(t, key, cert, claims)
		}, false},
		"expired": {func(issuerURL string, claims map[string]any) string {
			cert, key := signer(issuerURL, root, rootKey)
			claims["iat"], claims["exp"] = now-7200, now-3600
			return signMetadataClaims(t, key, cert, claims)
		}, false},
	} {
		issuerURL := serveMetadata(t, func(issuerURL, _ string) (string, string) {
			body, _ := json.Marshal(testMetadata(t, issuerURL))
			claims := map[string]any{}
			_ = json.Unmarshal(body, &claims)
			claims["sub"], claims["iat"] = issuerURL, now
			return "application/jwt", tc.respond(issuerURL, claims)
		})
		cfg := validConfig()
		cfg.IssuerMetadataRoots, cfg.RequireSignedIssuerMetadata, cfg.RequireIssuerMetadataName = roots, true, true
		deps := validDependencies()
		deps.HTTP = http.DefaultClient
		w, err := wallet.New(cfg, deps)
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.FetchCredentialIssuerMetadata(t.Context(), issuerURL)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if errors.Is(err, wallet.ErrUntrustedIssuer) != tc.untrusted {
			t.Errorf("%s: %v, want ErrUntrustedIssuer %t", name, err, tc.untrusted)
		}
	}
}
