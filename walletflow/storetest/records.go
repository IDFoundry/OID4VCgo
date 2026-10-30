package storetest

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// TestDeferredStoreContract exercises factory()'s stores against
// walletflow.DeferredStore's guarantees (see the package doc). With no
// lookup by ID, a record is found by listing. factory must return a
// fresh, empty store each call.
func TestDeferredStoreContract(t *testing.T, factory func() walletflow.DeferredStore) {
	t.Helper()
	runRecordContract(t, recordKind[walletflow.PendingDeferred]{
		id:      func(p walletflow.PendingDeferred) string { return p.ID },
		full:    fullDeferred,
		minimal: func(id string) walletflow.PendingDeferred { return walletflow.PendingDeferred{ID: id} },
	}, func() recordStore[walletflow.PendingDeferred] {
		s := factory()
		return recordStore[walletflow.PendingDeferred]{put: s.PutDeferred, list: s.ListDeferred, del: s.DeleteDeferred}
	})
}

// at is the fixtures' time n minutes and v seconds after contractBase.
func at(n, v int) time.Time {
	return contractBase.Add(time.Duration(n)*time.Minute + time.Duration(v)*time.Second)
}

// fixtureText is a fixture's string value for field, distinct per id
// and v.
func fixtureText(field, id string, v int) string { return fmt.Sprintf("%s-%s-%d", field, id, v) }

func fullCredential(id string, v int) walletflow.StoredCredential {
	text := func(field string) string { return fixtureText(field, id, v) }
	statusList := func(n int) *statuslist.StatusListRef {
		return &statuslist.StatusListRef{Idx: 1<<33 + uint64(10*v+n), URI: "https://status.example/" + text("list")} //nolint:gosec // G115: v and n are small and non-negative
	}
	copyOf := func(n int) walletflow.CredentialCopy {
		return walletflow.CredentialCopy{
			Credential: text(fmt.Sprintf("copy%d", n)), HolderKeyID: text(fmt.Sprintf("key%d", n)), Presented: true,
			ShownTo:    []string{walletflow.VerifierHash(text("verifier-a")), walletflow.VerifierHash(text("verifier-b"))},
			StatusList: statusList(n), ValidUntil: at(60+n, v), Reservation: text(fmt.Sprintf("reservation%d", n)),
		}
	}
	logo := func(field string) *walletflow.Logo {
		return &walletflow.Logo{URI: "https://issuer.example/" + text(field), AltText: text(field + "-alt")}
	}
	return walletflow.StoredCredential{
		ID: id, CredentialIssuer: "https://issuer.example/" + text("issuer"), ConfigurationID: text("config"),
		CredentialIdentifier: text("dataset"), Format: "dc+sd-jwt", VCT: "urn:vct:" + text("vct"), DocType: text("doctype"),
		Credential: text("copy0"), HolderKeyID: text("key0"), Copies: []walletflow.CredentialCopy{copyOf(0), copyOf(1)},
		Claims: map[string]any{
			"given_name": text("name"), "age": float64(40 + v), "adult": true, "nickname": nil,
			"address":     map[string]any{"locality": text("town"), "codes": []any{text("a"), float64(v)}},
			"nationality": []any{"DE", "FR"},
		},
		ReceivedAt: at(1, v),
		Display: walletflow.Display{
			IssuerName: text("issuer-name"), IssuerLogo: logo("issuer-logo"), Name: text("name"), Description: text("description"),
			Logo: logo("logo"), BackgroundColor: "#12345" + fmt.Sprint(v%10), TextColor: "#fedcb" + fmt.Sprint(v%10),
		},
		ValidUntil: at(60, v), StatusList: statusList(9), StatusListCWT: true,
		Status:  walletflow.CredentialStatus{Value: walletflow.StatusValid, CheckedAt: at(2, v)},
		GrantID: text("grant"), CopiesCorrelated: true,
	}
}

func fullAuthorization(state string, v int) walletflow.PendingAuthorization {
	text := func(field string) string { return fixtureText(field, state, v) }
	return walletflow.PendingAuthorization{
		State:     state,
		Session:   json.RawMessage(fmt.Sprintf(`{"pkce_verifier":%q,"nonce":%q,"n":%d,"nested":{"ok":true}}`, text("verifier"), text("nonce"), v)),
		ExpiresAt: at(10, v),
		Offer: oid4vci.CredentialOffer{
			CredentialIssuer:           "https://issuer.example/" + text("issuer"),
			CredentialConfigurationIDs: []string{text("config-a"), text("config-b")},
			Grants: &oid4vci.Grants{
				AuthorizationCode: &oid4vci.GrantAuthorizationCode{IssuerState: text("issuer-state"), AuthorizationServer: "https://as.example/" + text("as")},
				PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{
					PreAuthorizedCode: text("code"), AuthorizationServer: "https://as.example/" + text("pre-as"),
					TxCode: &oid4vci.TxCode{InputMode: oid4vci.TxCodeInputModeNumeric, Length: 4 + v%4, Description: text("pin")},
				},
			},
		},
		AuthorizationServer: "https://as.example/" + text("as"), InstanceKeyID: text("instance"), DPoPKeyID: text("dpop"),
		CreatedAt: at(0, v),
	}
}

func fullGrant(id string, v int) walletflow.RefreshGrant {
	text := func(field string) string { return fixtureText(field, id, v) }
	return walletflow.RefreshGrant{
		ID: id, CredentialIssuer: "https://issuer.example/" + text("issuer"), AuthorizationServer: "https://as.example/" + text("as"),
		ConfigurationID: text("config"), RefreshToken: fapi.NewSecret(text("refresh")), InstanceKeyID: text("instance"),
		CreatedAt: at(3, v), ClientAuth: walletflow.GrantAuthNone, DPoPKeyID: text("dpop"), TokenType: "Bearer",
		Redemption: text("redemption"), RedemptionExpiresAt: at(5, v),
	}
}

func fullDeferred(id string, v int) walletflow.PendingDeferred {
	text := func(field string) string { return fixtureText(field, id, v) }
	return walletflow.PendingDeferred{
		ID: id, CredentialIssuer: "https://issuer.example/" + text("issuer"), ConfigurationID: text("config"),
		TransactionID: text("transaction"), CredentialIdentifier: text("dataset"), AccessToken: fapi.NewSecret(text("token")),
		AccessTokenExpiresAt: at(20, v), DPoPKeyID: text("dpop"), HolderKeyIDs: []string{text("key0"), text("key1"), text("key2")},
		Interval: time.Duration(5+v) * time.Second, DeferredAt: at(4, v), GrantID: text("grant"), Replaces: text("replaces"),
		TokenType: "Bearer",
	}
}
