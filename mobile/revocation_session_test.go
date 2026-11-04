//go:build mobiletest

package mobile

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// With "revocation": ["issuer"], a credential is received only while the
// lists hold a current CRL from the issuer's CA that doesn't list its
// signer: none (fails closed), then a clean one by SetCRLs (received),
// then one revoking the signer (refused); a SetCRLs that isn't a CRL
// changes nothing.
func TestSessions_IssuerRevocation(t *testing.T) {
	env, err := startTestEnv(walletflowtest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	var cfg config
	if err := json.Unmarshal([]byte(env.ConfigJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Revocation = []string{"issuer"}
	text, err := marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := harness{env: env, keys: newGoKeyStore(), creds: newGoCredentialStore()}
	if h.w, err = NewWallet(text, h.keys, h.creds, env.Provider()); err != nil {
		t.Fatal(err)
	}
	clean, err := env.IssuerCRL(false)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := env.IssuerCRL(true)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.receivePreAuthorized(t); detail(err) != DetailNoCurrentCRL {
		t.Errorf("with no CRL for its issuer's CA: %v, want %s", err, DetailNoCurrentCRL)
	}
	if err := h.w.SetCRLs(clean); err != nil {
		t.Fatal(err)
	}
	if err := h.receivePreAuthorized(t); err != nil {
		t.Errorf("with a clean CRL: %v", err)
	}
	if err := h.w.SetCRLs(revoked); err != nil {
		t.Fatal(err)
	}
	if err := h.receivePreAuthorized(t); code(err) != CodeProtocol || detail(err) != DetailCertificateRevoked {
		t.Errorf("with the signer revoked: %v, want protocol:%s", err, DetailCertificateRevoked)
	}
	if err := h.w.SetCRLs(env.ConfigJSON()); code(err) != CodeInvalidInput {
		t.Errorf("SetCRLs(not PEM): %v, want invalid_input", err)
	}
	if err := h.receivePreAuthorized(t); err == nil {
		t.Error("a refused SetCRLs replaced the revoking list")
	}
}

// receivePreAuthorized receives the test issuer's SD-JWT VC through the
// pre-authorized code grant, returning RequestCredentials' error.
func (h harness) receivePreAuthorized(t *testing.T) error {
	t.Helper()
	offer, err := h.env.PreAuthorizedOffer("123456")
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.w.StartIssuance(NewOperation(0), offer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.RedeemPreAuthorizedCode(NewOperation(0), "123456"); err != nil {
		t.Fatal(err)
	}
	_, err = s.RequestCredentials(NewOperation(0))
	return err
}
