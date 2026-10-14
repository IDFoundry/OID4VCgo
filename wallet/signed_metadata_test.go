package wallet_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		"valid":            {claims: func(u string) map[string]any { return map[string]any{"sub": u, "iat": now, "exp": now + 3600} }, ok: true},
		"another issuer":   {claims: func(string) map[string]any { return map[string]any{"sub": "https://other.example", "iat": now} }},
		"no iat":           {claims: func(u string) map[string]any { return map[string]any{"sub": u} }},
		"iat in future":    {claims: func(u string) map[string]any { return map[string]any{"sub": u, "iat": now + 3600} }},
		"expired":          {claims: func(u string) map[string]any { return map[string]any{"sub": u, "iat": now - 7200, "exp": now - 3600} }},
		"self-signed cert": {claims: func(u string) map[string]any { return map[string]any{"sub": u, "iat": now} }, key: selfSignedKey, cert: selfSigned, roots: selfRoots},
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
