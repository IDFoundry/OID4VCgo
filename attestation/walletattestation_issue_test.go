package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

func testP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

func validWalletAttestationClaims(instance *ecdsa.PublicKey) WalletAttestationClaims {
	return WalletAttestationClaims{
		Issuer: "https://wallet-provider.example.com", Subject: "demo-wallet",
		InstanceKey: instance, IssuedAt: 1790000000, ExpiresAt: 1790003600,
		Extra: WalletAttestationExtraClaims{
			WalletName: "Demo Wallet", WalletLink: "https://wallet-provider.example.com/wallet",
			Status: map[string]any{"status_list": map[string]any{"idx": 3, "uri": "https://example.com/sl"}},
		},
	}
}

func TestIssueWalletAttestation(t *testing.T) {
	provider, instance := testP256(t), testP256(t)
	compact, err := IssueWalletAttestation(provider, jose.ES256, Header{KeyID: "provider-1"}, validWalletAttestationClaims(&instance.PublicKey))
	if err != nil {
		t.Fatalf("IssueWalletAttestation: %v", err)
	}

	header, payload, err := jose.Verify(jose.ES256, &provider.PublicKey, compact)
	if err != nil {
		t.Fatalf("jose.Verify: %v", err)
	}
	if header["typ"] != WalletAttestationTypHeader || header["kid"] != "provider-1" {
		t.Errorf("header = %v", header)
	}

	var claims struct {
		Iss string                     `json:"iss"`
		Sub string                     `json:"sub"`
		Iat int64                      `json:"iat"`
		Exp int64                      `json:"exp"`
		Nbf *int64                     `json:"nbf"`
		CNF map[string]json.RawMessage `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.Iss != "https://wallet-provider.example.com" || claims.Sub != "demo-wallet" ||
		claims.Iat != 1790000000 || claims.Exp != 1790003600 || claims.Nbf != nil {
		t.Errorf("claims = %+v", claims)
	}
	if ok, err := jwk.Matches(claims.CNF["jwk"], &instance.PublicKey); err != nil || !ok {
		t.Errorf("cnf.jwk does not match the instance key (err %v)", err)
	}

	// The Appendix E extra claims round-trip through the existing parser.
	extra, err := ParseWalletAttestationClaims(compact)
	if err != nil {
		t.Fatalf("ParseWalletAttestationClaims: %v", err)
	}
	if extra.WalletName != "Demo Wallet" || extra.WalletLink != "https://wallet-provider.example.com/wallet" || extra.Status == nil {
		t.Errorf("extra claims = %+v", extra)
	}
}

func TestIssueWalletAttestation_X5CHeader(t *testing.T) {
	provider, instance := testP256(t), testP256(t)
	compact, err := IssueWalletAttestation(provider, jose.ES256, Header{X5C: []string{"MIIB"}}, validWalletAttestationClaims(&instance.PublicKey))
	if err != nil {
		t.Fatalf("IssueWalletAttestation: %v", err)
	}
	header, _, err := jose.DecodeUnverified(compact)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	if x5c, _ := header["x5c"].([]any); len(x5c) != 1 || header["kid"] != nil {
		t.Errorf("header = %v, want x5c only", header)
	}
}

func TestIssueWalletAttestation_Rejects(t *testing.T) {
	provider, instance := testP256(t), testP256(t)
	cases := map[string]func(*WalletAttestationClaims){
		"missing issuer":       func(c *WalletAttestationClaims) { c.Issuer = "" },
		"missing subject":      func(c *WalletAttestationClaims) { c.Subject = "" },
		"missing instance key": func(c *WalletAttestationClaims) { c.InstanceKey = nil },
		"missing expiry":       func(c *WalletAttestationClaims) { c.ExpiresAt = 0 },
		"expiry before iat":    func(c *WalletAttestationClaims) { c.ExpiresAt = c.IssuedAt },
		"unsupported key type": func(c *WalletAttestationClaims) { c.InstanceKey = "not a key" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claims := validWalletAttestationClaims(&instance.PublicKey)
			mutate(&claims)
			if _, err := IssueWalletAttestation(provider, jose.ES256, Header{}, claims); err == nil {
				t.Fatalf("IssueWalletAttestation(%s) = nil error, want error", name)
			}
		})
	}
}
