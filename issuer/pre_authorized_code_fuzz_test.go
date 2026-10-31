package issuer_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

// fuzzMaxTxCodeAttempts is the wrong tx_code limit of the issuers
// FuzzPreAuthorizedCodeRefusalKeepsCode redeems at.
const fuzzMaxTxCodeAttempts = 3

// preAuthorizedFuzzIssuer is a development Issuer for issuerURL, keeping
// its pre-authorized codes in codes, that redeems them for clients the
// Authorization Server verified.
func preAuthorizedFuzzIssuer(tb testing.TB, issuerURL string, codes issuer.PreAuthorizedCodeStore, now time.Time) *issuer.Issuer {
	tb.Helper()
	cfg := validConfig(tb)
	cfg.Issuer = mustIssuerURL(tb, issuerURL)
	cfg.Limits.AccessTokenLifetime = 5 * time.Minute
	cfg.Limits.MaxTxCodeAttempts = fuzzMaxTxCodeAttempts
	cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
	other := cfg.CredentialConfigurationsSupported["IdentityCredential"]
	other.Scope, other.VCT = "other_credential", "https://credentials.example.com/other"
	cfg.CredentialConfigurationsSupported["OtherCredential"] = other
	deps := validDependencies(tb)
	deps.Clock = fixedClock{now: now}
	deps.PreAuthorizedCodes = codes
	deps.AccessTokens = &fakeAccessTokenIssuer{}
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		tb.Fatalf("New(%s): %v", issuerURL, err)
	}
	return iss
}

// preAuthorizedAttempt is one Token Request in
// FuzzPreAuthorizedCodeRefusalKeepsCode, decoded from a byte: which
// tx_code it sends (bits 0–1), at which issuer (bit 2), with what the
// Authorization Server verified (bits 3–4), which authorization_details
// (bits 5–6), and through ExchangePreAuthorizedCode or
// RedeemPreAuthorizedCode (bit 7).
type preAuthorizedAttempt byte

// txCode is the tx_code the attempt sends: the issued one, none, the
// fuzzer's guess, or the issued one with a character more.
func (a preAuthorizedAttempt) txCode(issued, guess string) string {
	switch a & 3 {
	case 0:
		return issued
	case 1:
		return ""
	case 2:
		return guess
	}
	return issued + "x"
}

func (a preAuthorizedAttempt) atOtherIssuer() bool { return a&4 != 0 }

func (a preAuthorizedAttempt) verified() (*issuer.VerifiedTokenRequest, bool) {
	switch a >> 3 & 3 {
	case 0:
		return &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1"}, true
	case 1:
		return nil, false
	case 2:
		return &issuer.VerifiedTokenRequest{ClientID: "wallet-1"}, false
	}
	return &issuer.VerifiedTokenRequest{DPoPThumbprint: "jkt-1"}, false
}

// details is the attempt's authorization_details: none, the granted
// configuration, a supported one the code doesn't grant, or the
// granted one with credential_identifiers the client chose.
func (a preAuthorizedAttempt) details() ([]oid4vci.AuthorizationDetail, bool) {
	detail := oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: "IdentityCredential"}
	switch a >> 5 & 3 {
	case 0:
		return nil, true
	case 1:
		return []oid4vci.AuthorizationDetail{detail}, true
	case 2:
		detail.CredentialConfigurationID = "OtherCredential"
		return []oid4vci.AuthorizationDetail{detail}, false
	}
	detail.CredentialIdentifiers = []string{"victim-dataset"}
	return []oid4vci.AuthorizationDetail{detail}, false
}

// FuzzPreAuthorizedCodeRefusalKeepsCode issues a pre-authorized code
// (with or without a Transaction Code) and sends Token Requests for it
// that vary the tx_code, the issuer, what the Authorization Server
// verified and the authorization_details, through
// ExchangePreAuthorizedCode and RedeemPreAuthorizedCode, against the
// in-memory storage.PreAuthorizedCodeStore that two issuers share. A
// request succeeds exactly when every input is right and the code is
// still live; a refused one never consumes the code, so the right
// request still redeems it afterwards — unless wrong tx_codes reached
// the attempt limit, after which nothing redeems it.
func FuzzPreAuthorizedCodeRefusalKeepsCode(f *testing.F) {
	now := time.Now()
	codes := storage.NewPreAuthorizedCodeStore()
	a := preAuthorizedFuzzIssuer(f, "https://a.example.com", codes, now)
	b := preAuthorizedFuzzIssuer(f, "https://b.example.com", codes, now)
	f.Add("482193", "000000", false, []byte{0})
	f.Add("482193", "000000", true, []byte{2, 2, 1, 4, 3 << 3, 2 << 5, 3 << 5, 0})
	f.Add("482193", "482193", true, []byte{2, 1 << 7, 2})
	f.Add("", "", false, []byte{3, 1, 4, 1<<3 | 1<<7, 1 << 5})
	f.Add("1234", "12345", false, []byte{2, 2, 2, 0})
	f.Add("", "x", true, []byte{2, 2, 2, 2, 0})
	var n int
	f.Fuzz(func(t *testing.T, issuedTx, guess string, byConfiguration bool, ops []byte) {
		if len(ops) > 16 {
			ops = ops[:16]
		}
		ctx := context.Background()
		n++
		code := fmt.Sprintf("fuzz-code-%d", n)
		record := issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: now.Add(time.Hour), Subject: "subject-1"}
		if byConfiguration {
			record = issuer.PreAuthorizedCodeRecord{CredentialConfigurationIDs: []string{"IdentityCredential"}, ExpiresAt: now.Add(time.Hour)}
		}
		if err := a.IssuePreAuthorizedCode(ctx, code, issuedTx, record); err != nil {
			t.Skipf("IssuePreAuthorizedCode(%q): %v", issuedTx, err)
		}
		var consumed, exhausted bool
		wrong := 0
		for _, op := range append(ops, 0) { // the last: the right request
			attempt := preAuthorizedAttempt(op)
			txCode := attempt.txCode(issuedTx, guess)
			verified, verifiedOK := attempt.verified()
			details, detailsOK := attempt.details()
			iss := a
			if attempt.atOtherIssuer() {
				iss = b
			}
			req := issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: code, TxCode: txCode, Verified: verified, AuthorizationDetails: details}
			var err error
			if attempt&0x80 != 0 {
				_, err = iss.ExchangePreAuthorizedCode(ctx, req)
			} else {
				_, err = iss.RedeemPreAuthorizedCode(ctx, req)
			}
			right := !attempt.atOtherIssuer() && verifiedOK && detailsOK && txCode == issuedTx
			switch {
			case err == nil && !right:
				t.Fatalf("attempt %08b (tx_code %q, issued %q) succeeded", op, txCode, issuedTx)
			case err == nil && (consumed || exhausted):
				t.Fatalf("attempt %08b redeemed a code already consumed (%v) or out of attempts (%v)", op, consumed, exhausted)
			case err != nil && right && !consumed && !exhausted:
				t.Fatalf("the right request (%08b) was refused after %d wrong tx_codes: %v", op, wrong, err)
			}
			if err == nil {
				consumed = true
			}
			if errors.Is(err, issuer.ErrWrongTxCode) {
				wrong++
			}
			if wrong >= fuzzMaxTxCodeAttempts || errors.Is(err, issuer.ErrTooManyTxCodeAttempts) {
				exhausted = true
			}
		}
	})
}
