package issuer_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// A pre-authorized Token Request may carry authorization_details
// (§6.1.1); the Token Response then echoes them, with a
// credential_identifier each (§6.2). Their form, and whether the code
// grants them, are checked before the code is consumed. With authorization_servers in the metadata, each
// minted detail's locations is the Credential Issuer (§5.1.1).
func TestRedeemPreAuthorizedCode_AuthorizationDetails(t *testing.T) {
	verified := &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1"}
	detail := func(id string) oid4vci.AuthorizationDetail {
		return oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: id}
	}
	newFixture := func(t *testing.T, authorizationServers bool) preAuthorizedCodeFixture {
		return newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
			cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
			cfg.Limits.MaxDPoPProofAge = 0
			deps.DPoPReplay = nil
			if authorizationServers {
				cfg.AuthorizationServers = []fapi.URL{mustEndpointURL(t, "https://as.example.com")}
			}
		})
	}
	redeem := func(f preAuthorizedCodeFixture, code string, details ...oid4vci.AuthorizationDetail) (issuer.RedeemedPreAuthorizedCode, error) {
		return f.iss.RedeemPreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: code, Verified: verified, AuthorizationDetails: details})
	}
	record := func(f preAuthorizedCodeFixture) issuer.PreAuthorizedCodeRecord {
		return issuer.PreAuthorizedCodeRecord{Subject: "holder-1", Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)}
	}

	t.Run("requested and granted by scope", func(t *testing.T) {
		f := newFixture(t, true)
		f.issue(t, "code-1", record(f))
		got, err := redeem(f, "code-1", detail("IdentityCredential"))
		if err != nil {
			t.Fatalf("redeem: %v", err)
		}
		if len(got.AuthorizationDetails) != 1 || len(got.AuthorizationDetails[0].CredentialIdentifiers) != 1 ||
			len(got.AuthorizationDetails[0].Locations) != 1 || got.AuthorizationDetails[0].Locations[0] != testIssuer {
			t.Errorf("authorization_details = %+v, want one with an identifier and locations [%s]", got.AuthorizationDetails, testIssuer)
		}
	})
	t.Run("malformed, refused before the code is spent", func(t *testing.T) {
		f := newFixture(t, false)
		f.issue(t, "code-2", record(f))
		other := detail("IdentityCredential")
		other.Type = "payment_initiation"
		elsewhere := detail("IdentityCredential")
		elsewhere.Locations = []string{"https://elsewhere.example.com"}
		minted := detail("IdentityCredential")
		minted.CredentialIdentifiers = []string{"mine"}
		for name, d := range map[string][]oid4vci.AuthorizationDetail{
			"another type":           {other},
			"an unknown config":      {detail("Nope")},
			"one config twice":       {detail("IdentityCredential"), detail("IdentityCredential")},
			"locations elsewhere":    {elsewhere},
			"identifiers of its own": {minted},
		} {
			_, err := redeem(f, "code-2", d...)
			assertIssuerError(t, err, issuer.ErrorInvalidAuthorizationDetails)
			if t.Failed() {
				t.Logf("case %s", name)
			}
		}
		if got, err := redeem(f, "code-2"); err != nil || len(got.AuthorizationDetails) != 0 {
			t.Errorf("the code after refused requests: %+v, %v; want redeemed, without details", got, err)
		}
	})
	// What the code grants is checked by Consume's accept, before the
	// code is consumed, so this refusal leaves it redeemable.
	t.Run("a configuration the code doesn't grant, refused before the code is spent", func(t *testing.T) {
		f := newFixture(t, false)
		r := record(f)
		r.Scopes = []string{"another_scope"}
		f.issue(t, "code-3", r)
		_, err := redeem(f, "code-3", detail("IdentityCredential"))
		assertIssuerError(t, err, issuer.ErrorInvalidAuthorizationDetails)
		if got, err := redeem(f, "code-3"); err != nil || len(got.Scope) != 1 || got.Scope[0] != "another_scope" {
			t.Errorf("the code after the refused request: %+v, %v; want redeemed", got, err)
		}
		_, err = redeem(f, "code-3")
		assertIssuerError(t, err, issuer.ErrorInvalidGrant)
	})
}

// ParseAuthorizationDetails reads the form parameter: none, or a
// non-empty JSON array of objects.
func TestParseAuthorizationDetails(t *testing.T) {
	if got, err := issuer.ParseAuthorizationDetails(""); err != nil || got != nil {
		t.Errorf(`"": %v, %v`, got, err)
	}
	got, err := issuer.ParseAuthorizationDetails(`[{"type":"openid_credential","credential_configuration_id":"pid","locations":["https://issuer.example.com"]}]`)
	if err != nil || len(got) != 1 || got[0].CredentialConfigurationID != "pid" || len(got[0].Locations) != 1 {
		t.Errorf("one detail: %+v, %v", got, err)
	}
	for _, bad := range []string{"[]", "{}", "not json", `[{"type":"a","Type":"b"}]`} {
		_, err := issuer.ParseAuthorizationDetails(bad)
		assertIssuerError(t, err, issuer.ErrorInvalidAuthorizationDetails)
	}
}

// newVerifiedPreAuthorizedCodeFixture is a pre-authorized code fixture
// under VerifiedPreAuthorizedCode, its store replaced by wrap(codes)
// when wrap is set.
func newVerifiedPreAuthorizedCodeFixture(t *testing.T, wrap func(*fakePreAuthorizedCodeStore) issuer.PreAuthorizedCodeStore) preAuthorizedCodeFixture {
	t.Helper()
	return newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
		cfg.Limits.MaxDPoPProofAge = 0
		deps.DPoPReplay = nil
		if wrap != nil {
			deps.PreAuthorizedCodes = wrap(deps.PreAuthorizedCodes.(*fakePreAuthorizedCodeStore))
		}
	})
}

// redeemVerified redeems code with txCode and details under
// VerifiedPreAuthorizedCode.
func redeemVerified(f preAuthorizedCodeFixture, code, txCode string, details []oid4vci.AuthorizationDetail) (issuer.RedeemedPreAuthorizedCode, error) {
	return f.iss.RedeemPreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: code, TxCode: txCode, AuthorizationDetails: details,
		Verified: &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1"},
	})
}

// With a tx_code, the tx_code is checked first: a wrong one counts as a
// wrong attempt whatever authorization_details the request carries, and
// a right one with authorization_details the code doesn't grant is
// refused without spending the code or counting an attempt.
func TestRedeemPreAuthorizedCode_TxCodeBeforeAuthorizationDetails(t *testing.T) {
	f := newVerifiedPreAuthorizedCodeFixture(t, nil)
	f.issueWithTxCode(t, "code-1", "493536", issuer.PreAuthorizedCodeRecord{Scopes: []string{"another_scope"}, ExpiresAt: f.now.Add(time.Minute)})
	ungranted := []oid4vci.AuthorizationDetail{{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: "IdentityCredential"}}
	// Two wrong guesses of the three allowed, one carrying details the
	// code doesn't grant; refusals of those details with the right
	// tx_code in between count as none.
	_, err := redeemVerified(f, "code-1", "000000", ungranted)
	assertIssuerError(t, err, issuer.ErrorInvalidGrant)
	for range 3 {
		_, err = redeemVerified(f, "code-1", "493536", ungranted)
		assertIssuerError(t, err, issuer.ErrorInvalidAuthorizationDetails)
	}
	_, err = redeemVerified(f, "code-1", "000000", nil)
	assertIssuerError(t, err, issuer.ErrorInvalidGrant)
	if _, err := redeemVerified(f, "code-1", "493536", nil); err != nil {
		t.Fatalf("the right tx_code after refusals and two wrong guesses: %v", err)
	}
}

// An expired code is refused before it's consumed, so it stays refused
// as expired.
func TestRedeemPreAuthorizedCode_ExpiredIsRefusedEveryTime(t *testing.T) {
	f := newVerifiedPreAuthorizedCodeFixture(t, nil)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(-time.Second)})
	for range 2 {
		_, err := redeemVerified(f, "code-1", "", nil)
		assertIssuerError(t, err, issuer.ErrorInvalidGrant)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Errorf("err = %v, want the code's expiry", err)
		}
	}
}

// Concurrent redemptions of one code, half of them asking for a
// configuration it doesn't grant: exactly one of the others succeeds.
func TestRedeemPreAuthorizedCode_ConcurrentWithRefusedDetails(t *testing.T) {
	f := newVerifiedPreAuthorizedCodeFixture(t, nil)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"another_scope"}, ExpiresAt: f.now.Add(time.Minute)})
	ungranted := []oid4vci.AuthorizationDetail{{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: "IdentityCredential"}}
	const attempts = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, refusedWins := 0, 0
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var details []oid4vci.AuthorizationDetail
			if i%2 == 0 {
				details = ungranted
			}
			_, err := redeemVerified(f, "code-1", "", details)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
				if details != nil {
					refusedWins++
				}
			}
		}()
	}
	wg.Wait()
	if wins != 1 || refusedWins != 0 {
		t.Errorf("%d redemptions succeeded (%d with ungranted details), want exactly 1 without", wins, refusedWins)
	}
}

// acceptIgnoringStore is a PreAuthorizedCodeStore whose Consume never
// calls accept.
type acceptIgnoringStore struct{ *fakePreAuthorizedCodeStore }

func (s acceptIgnoringStore) Consume(ctx context.Context, code, wantTxCode string, maxAttempts int, _ func(issuer.PreAuthorizedCodeRecord) error) (issuer.PreAuthorizedCodeRecord, int, error) {
	return s.fakePreAuthorizedCodeStore.Consume(ctx, code, wantTxCode, maxAttempts, nil)
}

// A store that consumes a code without calling accept fails the
// redemption: none of the checks accept makes would have run (this
// code has expired).
func TestRedeemPreAuthorizedCode_RefusesStoreThatSkipsAccept(t *testing.T) {
	f := newVerifiedPreAuthorizedCodeFixture(t, func(codes *fakePreAuthorizedCodeStore) issuer.PreAuthorizedCodeStore {
		return acceptIgnoringStore{codes}
	})
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(-time.Second)})
	if _, err := redeemVerified(f, "code-1", "", nil); err == nil || !strings.Contains(err.Error(), "without calling accept") {
		t.Fatalf("err = %v, want the store refused", err)
	}
}
