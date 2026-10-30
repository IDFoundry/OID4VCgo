package storetest

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// TestCredentialStoreContract exercises factory()'s stores against
// walletflow.CredentialStore's guarantees (see the package doc), Update's
// atomicity among them. factory must return a fresh, empty store each
// call.
func TestCredentialStoreContract(t *testing.T, factory func() walletflow.CredentialStore) {
	t.Helper()
	runRecordContract(t, credentialKind, func() recordStore[walletflow.StoredCredential] { return credentialHandle(factory()) })
	runUpdateContract(t, credentialKind, credentialUpdates, func() func() recordStore[walletflow.StoredCredential] {
		return sameHandle(credentialHandle(factory()))
	})
}

// TestSharedCredentialStoreContract exercises Update's atomicity across
// handles on one storage, as Wallets in separate processes sharing it
// have. Each call, factory must return an opener on a fresh, empty
// storage, which returns a new handle on it each call: a new connection
// pool on one database, say, or a new store over one directory.
func TestSharedCredentialStoreContract(t *testing.T, factory func() func() walletflow.CredentialStore) {
	t.Helper()
	runUpdateContract(t, credentialKind, credentialUpdates, func() func() recordStore[walletflow.StoredCredential] {
		open := factory()
		return func() recordStore[walletflow.StoredCredential] { return credentialHandle(open()) }
	})
}

// TestAuthorizationStoreContract exercises factory()'s stores against
// walletflow.AuthorizationStore's guarantees (see the package doc),
// ConsumeAuthorization's atomicity among them. An authorization is keyed
// by its State. factory must return a fresh, empty store each call.
func TestAuthorizationStoreContract(t *testing.T, factory func() walletflow.AuthorizationStore) {
	t.Helper()
	runRecordContract(t, authorizationKind, func() recordStore[walletflow.PendingAuthorization] { return authorizationHandle(factory()) })
	runConsumeContract(t, authorizationKind, func() func() recordStore[walletflow.PendingAuthorization] {
		return sameHandle(authorizationHandle(factory()))
	})
}

// TestSharedAuthorizationStoreContract exercises ConsumeAuthorization's
// atomicity across handles on one storage, as
// TestSharedCredentialStoreContract does Update's.
func TestSharedAuthorizationStoreContract(t *testing.T, factory func() func() walletflow.AuthorizationStore) {
	t.Helper()
	runConsumeContract(t, authorizationKind, func() func() recordStore[walletflow.PendingAuthorization] {
		open := factory()
		return func() recordStore[walletflow.PendingAuthorization] { return authorizationHandle(open()) }
	})
}

// TestGrantStoreContract exercises factory()'s stores against
// walletflow.GrantStore's guarantees (see the package doc), UpdateGrant's
// atomicity among them. factory must return a fresh, empty store each
// call.
func TestGrantStoreContract(t *testing.T, factory func() walletflow.GrantStore) {
	t.Helper()
	runRecordContract(t, grantKind, func() recordStore[walletflow.RefreshGrant] { return grantHandle(factory()) })
	runUpdateContract(t, grantKind, grantUpdates, func() func() recordStore[walletflow.RefreshGrant] {
		return sameHandle(grantHandle(factory()))
	})
}

// TestSharedGrantStoreContract exercises UpdateGrant's atomicity across
// handles on one storage, as TestSharedCredentialStoreContract does
// Update's.
func TestSharedGrantStoreContract(t *testing.T, factory func() func() walletflow.GrantStore) {
	t.Helper()
	runUpdateContract(t, grantKind, grantUpdates, func() func() recordStore[walletflow.RefreshGrant] {
		open := factory()
		return func() recordStore[walletflow.RefreshGrant] { return grantHandle(open()) }
	})
}

var credentialKind = recordKind[walletflow.StoredCredential]{
	id:      func(c walletflow.StoredCredential) string { return c.ID },
	full:    fullCredential,
	minimal: func(id string) walletflow.StoredCredential { return walletflow.StoredCredential{ID: id} },
}

func credentialHandle(s walletflow.CredentialStore) recordStore[walletflow.StoredCredential] {
	return recordStore[walletflow.StoredCredential]{put: s.Put, get: s.Get, list: s.List, del: s.Delete, update: s.Update}
}

// credentialUpdates change a credential's first copy, in place, as
// reserving it for a presentation does; a claim reserves the next unused
// copy.
var credentialUpdates = updatable[walletflow.StoredCredential]{
	add: func(c *walletflow.StoredCredential, n int) {
		if len(c.Copies) == 0 {
			c.Copies = []walletflow.CredentialCopy{{Credential: "copy", HolderKeyID: "key"}}
		}
		c.Copies[0].Presented = !c.Copies[0].Presented
		c.Copies[0].ShownTo = append(c.Copies[0].ShownTo, numbered(n))
	},
	has: func(c walletflow.StoredCredential, n int) bool {
		return len(c.Copies) > 0 && containsNumbered(c.Copies[0].ShownTo, n)
	},
	claimable: func(id string) walletflow.StoredCredential {
		c := walletflow.StoredCredential{ID: id}
		for i := range 3 {
			c.Copies = append(c.Copies, walletflow.CredentialCopy{Credential: "copy" + strconv.Itoa(i), HolderKeyID: "key" + strconv.Itoa(i)})
		}
		return c
	},
	slots: 3,
	claim: func(c *walletflow.StoredCredential, n int) (int, error) {
		i := slices.IndexFunc(c.Copies, func(cp walletflow.CredentialCopy) bool { return !cp.Presented })
		if i < 0 {
			return 0, errContract
		}
		c.Copies[i].Presented, c.Copies[i].Reservation = true, strconv.Itoa(n)
		return i, nil
	},
	owner: func(c walletflow.StoredCredential, i int) string { return c.Copies[i].Reservation },
}

var authorizationKind = recordKind[walletflow.PendingAuthorization]{
	id:   func(a walletflow.PendingAuthorization) string { return a.State },
	full: fullAuthorization,
	minimal: func(state string) walletflow.PendingAuthorization {
		return walletflow.PendingAuthorization{State: state, Session: json.RawMessage(`{"s":"` + state + `"}`)}
	},
}

func authorizationHandle(s walletflow.AuthorizationStore) recordStore[walletflow.PendingAuthorization] {
	return recordStore[walletflow.PendingAuthorization]{
		put: s.PutAuthorization, get: s.GetAuthorization, list: s.ListAuthorizations, del: s.DeleteAuthorization, durable: s.Durable,
		consume: s.ConsumeAuthorization,
	}
}

var grantKind = recordKind[walletflow.RefreshGrant]{
	id:   func(g walletflow.RefreshGrant) string { return g.ID },
	full: fullGrant,
	minimal: func(id string) walletflow.RefreshGrant {
		return walletflow.RefreshGrant{ID: id, RefreshToken: fapi.NewSecret("refresh-" + id)}
	},
}

func grantHandle(s walletflow.GrantStore) recordStore[walletflow.RefreshGrant] {
	return recordStore[walletflow.RefreshGrant]{put: s.PutGrant, get: s.GetGrant, list: s.ListGrants, del: s.DeleteGrant, durable: s.Durable, update: s.UpdateGrant}
}

// grantUpdates rotate a grant's refresh token; a claim claims its one
// redemption, as a refresh does before redeeming the token.
var grantUpdates = updatable[walletflow.RefreshGrant]{
	add: func(g *walletflow.RefreshGrant, n int) {
		g.RefreshToken = fapi.NewSecret(g.RefreshToken.Reveal() + "," + numbered(n))
	},
	has: func(g walletflow.RefreshGrant, n int) bool {
		return containsNumbered(strings.Split(g.RefreshToken.Reveal(), ","), n)
	},
	claimable: func(id string) walletflow.RefreshGrant {
		return walletflow.RefreshGrant{ID: id, RefreshToken: fapi.NewSecret("refresh")}
	},
	slots: 1,
	claim: func(g *walletflow.RefreshGrant, n int) (int, error) {
		if g.Redemption != "" {
			return 0, errContract
		}
		g.Redemption = strconv.Itoa(n)
		return 0, nil
	},
	owner: func(g walletflow.RefreshGrant, _ int) string { return g.Redemption },
}
