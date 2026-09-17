package issuer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func testSignerAndCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := testcert.SelfSigned(t, "issuer.example.com", &key.PublicKey, key)
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
	if claims["iat"] == nil {
		t.Error("iat claim missing")
	}
	if claims["credential_endpoint"] != testCredentialEndpoint {
		t.Errorf("credential_endpoint = %v, want passthrough of the metadata field", claims["credential_endpoint"])
	}
}

// TestMetadataHandler_NegotiatesContentType proves MetadataHandler
// returns plain JSON when the Wallet doesn't ask for application/jwt,
// and a signed JWS (with matching Content-Type) when it does.
func TestMetadataHandler_NegotiatesContentType(t *testing.T) {
	key, cert := testSignerAndCert(t)
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))

	handler := issuer.MetadataHandler(iss, key, jose.ES256, cert)

	t.Run("json by default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
	})

	t.Run("jwt when requested", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
		req.Header.Set("Accept", "application/jwt")
		rec := httptest.NewRecorder()
		handler(rec, req)
		if ct := rec.Header().Get("Content-Type"); ct != "application/jwt" {
			t.Errorf("Content-Type = %q, want application/jwt", ct)
		}
		if _, _, err := jose.Verify(jose.ES256, &key.PublicKey, rec.Body.String()); err != nil {
			t.Errorf("response body is not a valid JWS: %v", err)
		}
	})
}
