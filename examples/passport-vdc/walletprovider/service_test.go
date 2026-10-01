package walletprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/attestation"
)

func newService(t *testing.T) (*Provider, Client) {
	t.Helper()
	p, err := New(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(p.Handler("wallet-1"))
	t.Cleanup(srv.Close)
	return p, Client{URL: srv.URL, HTTP: srv.Client()}
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// jwtClaims decodes a JWT's payload without verifying it.
func jwtClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// TestService_Attests: the Client gets a Wallet Attestation for the
// wallet's client_id and instance key, and a Key Attestation over its
// holder keys carrying the issuer's nonce, both from the provider.
func TestService_Attests(t *testing.T) {
	_, c := newService(t)
	ctx := context.Background()

	wa, err := c.WalletAttestation(ctx, "wallet-1", &p256(t).PublicKey)
	if err != nil {
		t.Fatalf("WalletAttestation: %v", err)
	}
	if claims := jwtClaims(t, wa); claims["iss"] != testIssuer || claims["sub"] != "wallet-1" || claims["cnf"] == nil {
		t.Errorf("Wallet Attestation claims = %v", claims)
	}

	ka, err := c.KeyAttestation(ctx, []*ecdsa.PublicKey{&p256(t).PublicKey, &p256(t).PublicKey}, "c-nonce-1")
	if err != nil {
		t.Fatalf("KeyAttestation: %v", err)
	}
	claims := jwtClaims(t, ka)
	if keys, _ := claims["attested_keys"].([]any); claims["iss"] != testIssuer || claims["nonce"] != "c-nonce-1" || claims["iat"] == nil || len(keys) != 2 {
		t.Errorf("Key Attestation claims = %v", claims)
	}
}

// TestService_Refuses: the service attests only its own wallet's
// client_id, and only public EC P-256 keys, a bounded number of them,
// with a nonce.
func TestService_Refuses(t *testing.T) {
	p, c := newService(t)
	ctx := context.Background()
	if _, err := c.WalletAttestation(ctx, "another-wallet", &p256(t).PublicKey); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("another client_id: %v, want 403", err)
	}
	if _, err := c.KeyAttestation(ctx, []*ecdsa.PublicKey{&p256(t).PublicKey}, ""); err == nil {
		t.Error("a Key Attestation was issued without a nonce")
	}
	tooMany := make([]*ecdsa.PublicKey, maxAttestedKeys+1)
	for i := range tooMany {
		tooMany[i] = &p256(t).PublicKey
	}
	if _, err := c.KeyAttestation(ctx, tooMany, "n"); err == nil {
		t.Error("a Key Attestation was issued over too many keys")
	}

	h := p.Handler("wallet-1")
	pub, err := attestation.AttestedKey(&p256(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var withD map[string]any
	_ = json.Unmarshal(pub, &withD)
	withD["d"] = "AAAA"
	private, _ := json.Marshal(withD)
	for name, tc := range map[string]struct{ path, body string }{
		"private key":    {WalletAttestationPath, `{"client_id":"wallet-1","instance_key":` + string(private) + `}`},
		"P-384 key":      {KeyAttestationPath, `{"keys":[{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}],"nonce":"n"}`},
		"not JSON":       {KeyAttestationPath, `keys`},
		"unknown member": {KeyAttestationPath, `{"keys":[` + string(pub) + `],"nonce":"n","key_storage":["iso_18045_high"]}`},
		"too large":      {KeyAttestationPath, `{"nonce":"` + strings.Repeat("a", maxRequestBytes) + `"}`},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, KeyAttestationPath, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d, want 405", w.Code)
	}
}
