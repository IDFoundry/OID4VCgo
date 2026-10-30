package issuer_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// The offer's tx_code comes from the stored record's Transaction Code,
// so the PIN the Wallet asks for is the one redemption checks; the code
// is generated, 256 bits.
func TestCreatePreAuthorizedOffer(t *testing.T) {
	f := newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
	})
	ctx := context.Background()
	verified := &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1"}

	result, err := f.iss.CreatePreAuthorizedOffer(ctx, issuer.CreatePreAuthorizedOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"},
		CredentialIdentifiers: true, Subject: "holder-1", TxCode: "4821", TxCodeDescription: "sent by SMS",
		Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("CreatePreAuthorizedOffer: %v", err)
	}
	grant := result.Offer.Grants.PreAuthorizedCode
	if grant == nil || len(grant.PreAuthorizedCode) != 43 {
		t.Fatalf("grant = %+v, want a 256-bit code", grant)
	}
	if tx := grant.TxCode; tx == nil || tx.InputMode != oid4vci.TxCodeInputModeNumeric || tx.Length != 4 || tx.Description != "sent by SMS" {
		t.Errorf("tx_code = %+v, want numeric, 4 digits, the description", tx)
	}
	if result.URI == "" {
		t.Error("no offer URI")
	}
	redeem := func(code, txCode string) (issuer.RedeemedPreAuthorizedCode, error) {
		return f.iss.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: code, TxCode: txCode, Verified: verified})
	}
	if _, err := redeem(grant.PreAuthorizedCode, ""); err == nil {
		t.Error("redeemed without the Transaction Code the offer asks for")
	}
	got, err := redeem(grant.PreAuthorizedCode, "4821")
	if err != nil {
		t.Fatalf("redeem with the Transaction Code: %v", err)
	}
	if got.Subject != "holder-1" || len(got.AuthorizationDetails) != 1 || got.Scope[0] != "identity_credential" {
		t.Errorf("redeemed %+v", got)
	}

	// Without a Transaction Code the offer has no tx_code object, and
	// the code redeems without one.
	plain, err := f.iss.CreatePreAuthorizedOffer(ctx, issuer.CreatePreAuthorizedOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"}, Subject: "holder-2", Lifetime: time.Minute,
	})
	if err != nil || plain.Offer.Grants.PreAuthorizedCode.TxCode != nil {
		t.Fatalf("offer without a Transaction Code = %+v, %v", plain.Offer.Grants, err)
	}
	if _, err := redeem(plain.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode, ""); err != nil {
		t.Errorf("redeem without a Transaction Code: %v", err)
	}
	if text, err := f.iss.CreatePreAuthorizedOffer(ctx, issuer.CreatePreAuthorizedOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"}, Subject: "holder-3", TxCode: "ab12", Lifetime: time.Minute,
	}); err != nil || text.Offer.Grants.PreAuthorizedCode.TxCode.InputMode != oid4vci.TxCodeInputModeText {
		t.Errorf("an alphanumeric Transaction Code: %+v, %v", text.Offer.Grants, err)
	}

	for name, req := range map[string]issuer.CreatePreAuthorizedOfferRequest{
		"no configurations":           {Lifetime: time.Minute},
		"no lifetime":                 {CredentialConfigurationIDs: []string{"IdentityCredential"}},
		"description without tx_code": {CredentialConfigurationIDs: []string{"IdentityCredential"}, Lifetime: time.Minute, TxCodeDescription: "x"},
		"unknown configuration":       {CredentialConfigurationIDs: []string{"Nope"}, Lifetime: time.Minute},
		// Every holder redeemed without one would share sub "".
		"no subject": {CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"}, Lifetime: time.Minute},
		// The code would be spent, and every Credential Request refused.
		"grants nothing it offers": {CredentialConfigurationIDs: []string{"IdentityCredential"}, Subject: "holder-1", Lifetime: time.Minute},
	} {
		if _, err := f.iss.CreatePreAuthorizedOffer(ctx, req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Under production, a pre-authorized code grant goes through
// CreatePreAuthorizedOffer, so the offer's tx_code and the stored
// record's can't disagree; CreateCredentialOffer refuses one.
func TestCreateCredentialOffer_ProductionRefusesPreAuthorizedGrant(t *testing.T) {
	cfg, deps := preAuthorizedCodeProductionConfig(t)
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	_, err = iss.CreateCredentialOffer(ctx, issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"},
		Grants: &oid4vci.Grants{PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{
			PreAuthorizedCode: "caller-code", TxCode: &oid4vci.TxCode{InputMode: oid4vci.TxCodeInputModeNumeric, Length: 4},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "CreatePreAuthorizedOffer") {
		t.Errorf("CreateCredentialOffer with a pre-authorized grant under production: %v, want refused", err)
	}
	if _, err := iss.CreatePreAuthorizedOffer(ctx, issuer.CreatePreAuthorizedOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"},
		Subject: "holder-1", TxCode: "482193", Lifetime: time.Minute,
	}); err != nil {
		t.Errorf("CreatePreAuthorizedOffer under production: %v", err)
	}
	// Under production, a Transaction Code too short to resist
	// guessing, or a code living longer than a week, is refused.
	for name, req := range map[string]issuer.CreatePreAuthorizedOfferRequest{
		"a 4-digit tx_code":  {CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"}, Subject: "holder-1", TxCode: "4821", Lifetime: time.Minute},
		"a month's lifetime": {CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"}, Subject: "holder-1", TxCode: "482193", Lifetime: 30 * 24 * time.Hour},
	} {
		if _, err := iss.CreatePreAuthorizedOffer(ctx, req); err == nil {
			t.Errorf("%s under production: accepted", name)
		}
	}
	if _, err := iss.CreateCredentialOffer(ctx, issuer.CreateCredentialOfferRequest{CredentialConfigurationIDs: []string{"IdentityCredential"}}); err != nil {
		t.Errorf("CreateCredentialOffer without a pre-authorized grant: %v", err)
	}
	// IssuePreAuthorizedCode, for a code the caller made itself, is
	// refused likewise.
	err = iss.IssuePreAuthorizedCode(ctx, "caller-code", "482193", issuer.PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)})
	if err == nil || !strings.Contains(err.Error(), "CreatePreAuthorizedOffer") {
		t.Errorf("IssuePreAuthorizedCode under production: %v, want refused", err)
	}
}

// The store holds neither a code nor its Transaction Code, only their
// hashes: what it holds redeems nothing, and the code still redeems
// with its PIN.
func TestPreAuthorizedCodeStoreHoldsHashesOnly(t *testing.T) {
	f := newVerifiedPreAuthorizedCodeFixture(t, nil)
	result, err := f.iss.CreatePreAuthorizedOffer(context.Background(), issuer.CreatePreAuthorizedOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"},
		Subject: "holder-1", TxCode: "482193", Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("CreatePreAuthorizedOffer: %v", err)
	}
	code := result.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode

	f.codes.mu.Lock()
	var key string
	for k, record := range f.codes.issued {
		key = k
		if strings.Contains(k, code) {
			t.Errorf("store key %q holds the code", k)
		}
		if record.TxCodeHash == "" || strings.Contains(record.TxCodeHash, "482193") {
			t.Errorf("TxCodeHash = %q, want a hash of the Transaction Code", record.TxCodeHash)
		}
	}
	f.codes.mu.Unlock()
	if key == "" {
		t.Fatal("nothing stored")
	}

	if _, err := redeemVerified(f, key, "482193", nil); err == nil {
		t.Error("the store's key redeemed the code")
	}
	if _, err := redeemVerified(f, code, "000000", nil); err == nil {
		t.Error("a wrong Transaction Code redeemed the code")
	}
	if _, err := redeemVerified(f, code, "482193", nil); err != nil {
		t.Errorf("redeem with the Transaction Code: %v", err)
	}
}
