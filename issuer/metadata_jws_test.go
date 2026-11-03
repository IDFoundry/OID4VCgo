package issuer_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func testSignerAndCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	ca, caKey := testcert.CA(t, "metadata test CA")
	cert, key := testcert.Leaf(t, "issuer.example.com", ca, caKey)
	return key, cert
}

// TestSignMetadataJWS_ProducesValidJWS proves the signed JWS carries
// §12.2.3's own REQUIRED "sub"/"iat" claims (plus every metadata
// member as a top-level claim), the mandatory "typ" header, and a
// single "x5c" entry verifying against cert.
func TestSignMetadataJWS_ProducesValidJWS(t *testing.T) {
	key, cert := testSignerAndCert(t)
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	meta := iss.Metadata()

	signed, err := issuer.SignMetadataJWS(meta, key, jose.ES256, cert)
	if err != nil {
		t.Fatalf("SignMetadataJWS: %v", err)
	}

	header, payload, err := jose.Verify(jose.ES256, &key.PublicKey, signed)
	if err != nil {
		t.Fatalf("jose.Verify: %v", err)
	}
	if header["typ"] != issuer.MetadataJWSTyp {
		t.Errorf("typ = %v, want %q", header["typ"], issuer.MetadataJWSTyp)
	}
	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("x5c = %#v, want a single-entry array", header["x5c"])
	}
	if x5c[0] != base64.StdEncoding.EncodeToString(cert.Raw) {
		t.Errorf("x5c[0] does not match cert")
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if claims["sub"] != testIssuer {
		t.Errorf("sub = %v, want %q (the credential_issuer value)", claims["sub"], testIssuer)
	}
	iat, _ := claims["iat"].(float64)
	if iat == 0 {
		t.Error("iat claim missing")
	}
	// A captured copy mustn't verify forever (§12.2.3's exp).
	if exp, _ := claims["exp"].(float64); exp-iat != issuer.DefaultMetadataLifetime.Seconds() {
		t.Errorf("exp = %v, want iat + DefaultMetadataLifetime (%v)", claims["exp"], iat+issuer.DefaultMetadataLifetime.Seconds())
	}
	if claims["credential_endpoint"] != testCredentialEndpoint {
		t.Errorf("credential_endpoint = %v, want passthrough of the metadata field", claims["credential_endpoint"])
	}
}

// TestMetadataHandler_NegotiatesContentType: NewMetadataHandler serves
// plain JSON unless the Wallet's Accept prefers application/jwt (by q),
// and a signed JWS when it does, with Vary: Accept either way.
func TestMetadataHandler_NegotiatesContentType(t *testing.T) {
	key, cert := testSignerAndCert(t)
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	handler, err := issuer.NewMetadataHandler(iss, &issuer.MetadataSigner{Signer: key, Alg: jose.ES256, Certificate: cert})
	if err != nil {
		t.Fatalf("NewMetadataHandler: %v", err)
	}
	for accept, want := range map[string]string{
		"":                 "application/json",
		"application/json": "application/json",
		"application/jwt":  "application/jwt",
		"application/jwt, application/json;q=0.5": "application/jwt",
		"application/json, application/jwt;q=0.5": "application/json",
		"application/jwt;q=0":                     "application/json",
	} {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if ct := rec.Header().Get("Content-Type"); ct != want {
			t.Errorf("Accept %q: Content-Type = %q, want %q", accept, ct, want)
		}
		if rec.Header().Get("Vary") != "Accept" {
			t.Errorf("Accept %q: no Vary: Accept", accept)
		}
		if want == "application/jwt" {
			if _, _, err := jose.Verify(jose.ES256, &key.PublicKey, rec.Body.String()); err != nil {
				t.Errorf("Accept %q: response body is not a valid JWS: %v", accept, err)
			}
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/openid-credential-issuer", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", rec.Code)
	}
}

// The signed copy is reused until Refresh has passed on the Issuer's
// clock, then signed again with a new iat.
func TestMetadataHandler_CachesSignedCopy(t *testing.T) {
	key, cert := testSignerAndCert(t)
	clock := &mutableClock{now: time.Now()}
	deps := validDependencies(t)
	deps.Clock = clock
	iss := newTestIssuer(t, validConfig(t), deps)
	handler, err := issuer.NewMetadataHandler(iss, &issuer.MetadataSigner{Signer: key, Alg: jose.ES256, Certificate: cert, Refresh: time.Minute})
	if err != nil {
		t.Fatalf("NewMetadataHandler: %v", err)
	}
	get := func() string {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
		req.Header.Set("Accept", "application/jwt")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	first := get()
	if get() != first {
		t.Error("signed again within Refresh")
	}
	clock.now = clock.now.Add(2 * time.Minute)
	refreshed := get()
	if refreshed == first {
		t.Fatal("not signed again after Refresh")
	}
	_, payload, err := jose.Verify(jose.ES256, &key.PublicKey, refreshed)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Iat != clock.now.Unix() {
		t.Errorf("iat = %d, want the Issuer's clock %d", claims.Iat, clock.now.Unix())
	}
	if want := clock.now.Add(issuer.DefaultMetadataLifetime).Unix(); claims.Exp != want {
		t.Errorf("exp = %d, want iat + DefaultMetadataLifetime %d", claims.Exp, want)
	}
}

// MetadataSigner.Lifetime sets exp; left zero, it's at least twice
// Refresh, so a copy is never served expired.
func TestMetadataHandler_Lifetime(t *testing.T) {
	key, cert := testSignerAndCert(t)
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	for name, tc := range map[string]struct {
		refresh, lifetime, want time.Duration
	}{
		"set":                   {refresh: time.Minute, lifetime: 10 * time.Minute, want: 10 * time.Minute},
		"default":               {want: issuer.DefaultMetadataLifetime},
		"default, long Refresh": {refresh: 48 * time.Hour, want: 96 * time.Hour},
	} {
		handler, err := issuer.NewMetadataHandler(iss, &issuer.MetadataSigner{Signer: key, Alg: jose.ES256, Certificate: cert, Refresh: tc.refresh, Lifetime: tc.lifetime})
		if err != nil {
			t.Fatalf("%s: NewMetadataHandler: %v", name, err)
		}
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
		req.Header.Set("Accept", "application/jwt")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		_, payload, err := jose.Verify(jose.ES256, &key.PublicKey, rec.Body.String())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var claims struct {
			Iat int64 `json:"iat"`
			Exp int64 `json:"exp"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp-claims.Iat != int64(tc.want.Seconds()) {
			t.Errorf("%s: exp - iat = %d, want %d", name, claims.Exp-claims.Iat, int64(tc.want.Seconds()))
		}
	}
}

// NewMetadataHandler refuses a signer it couldn't sign verifiable
// metadata with, rather than serving unsigned metadata.
func TestNewMetadataHandler_RefusesMisconfiguredSigner(t *testing.T) {
	key, cert := testSignerAndCert(t)
	other, _ := testSignerAndCert(t)
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	for name, s := range map[string]*issuer.MetadataSigner{
		"another key's certificate": {Signer: other, Alg: jose.ES256, Certificate: cert},
		"an unsupported alg":        {Signer: key, Alg: "HS256", Certificate: cert},
		"no certificate":            {Signer: key, Alg: jose.ES256},
		"Lifetime not over Refresh": {Signer: key, Alg: jose.ES256, Certificate: cert, Refresh: time.Hour, Lifetime: time.Hour},
	} {
		if _, err := issuer.NewMetadataHandler(iss, s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := issuer.NewMetadataHandler(iss, nil); err != nil {
		t.Errorf("no signer (JSON only): %v", err)
	}
}

// The deprecated MetadataHandler serves unsigned metadata when its
// signer is refused, but not under AssuranceProduction, where it
// answers with a server error instead.
func TestMetadataHandler_MisconfiguredSignerUnderProduction(t *testing.T) {
	other, _ := testSignerAndCert(t)
	_, cert := testSignerAndCert(t)
	for name, tc := range map[string]struct {
		assurance issuer.AssuranceLevel
		want      int
	}{
		"development": {issuer.AssuranceDevelopment, http.StatusOK},
		"production":  {issuer.AssuranceProduction, http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionIssuer(t)
			cfg.Assurance = tc.assurance
			iss, err := issuer.New(cfg, deps)
			if err != nil {
				t.Fatal(err)
			}
			h := issuer.MetadataHandler(iss, other, jose.ES256, cert) //nolint:staticcheck // the deprecated handler under test
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil))
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
