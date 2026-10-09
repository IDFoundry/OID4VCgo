package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// grantKind marks a record that's a refresh grant.
const grantKind = "grant"

// grantRecord is a walletflow.RefreshGrant as the CredentialStore keeps
// it, under the ID grantStoreID gives it.
type grantRecord struct {
	Kind                string    `json:"kind"`
	ID                  string    `json:"id"`
	CredentialIssuer    string    `json:"credential_issuer"`
	AuthorizationServer string    `json:"authorization_server"`
	ConfigurationID     string    `json:"configuration_id,omitempty"`
	RefreshToken        string    `json:"refresh_token"`
	InstanceKeyID       string    `json:"instance_key_id"`
	CreatedAt           time.Time `json:"created_at"`
	// ClientAuth is "none" for a grant that authenticates no client,
	// whose refresh token is bound to DPoPKeyID instead (empty for a
	// Bearer one, TokenType "Bearer"), with no instance_key_id; absent
	// for a Wallet Attestation's, as every grant written before it was
	// kept is.
	ClientAuth string `json:"client_auth,omitempty"`
	DPoPKeyID  string `json:"dpop_key_id,omitempty"`
	TokenType  string `json:"token_type,omitempty"`
}

func grantStoreID(id string) string { return "grant-" + id }

// grantStore is a CredentialStore as a walletflow.GrantStore.
type grantStore struct{ cs CredentialStore }

var _ walletflow.GrantStore = grantStore{}

func (s grantStore) PutGrant(_ context.Context, g walletflow.RefreshGrant) error {
	// The refresh token is kept deliberately, beside the credentials it
	// refreshes: redeeming it needs the wallet instance key, or the DPoP
	// key it's bound to, which never leave the KeyStore — a Bearer
	// grant's needs neither, which is why the record is under the
	// platform's data protection.
	raw, err := json.Marshal(grantRecord{ //nolint:gosec // G117: see above
		Kind: grantKind, ID: g.ID, CredentialIssuer: g.CredentialIssuer, AuthorizationServer: g.AuthorizationServer,
		ConfigurationID: g.ConfigurationID, RefreshToken: g.RefreshToken.Reveal(), InstanceKeyID: g.InstanceKeyID, CreatedAt: g.CreatedAt,
		ClientAuth: string(g.ClientAuth), DPoPKeyID: g.DPoPKeyID, TokenType: g.TokenType,
	})
	if err != nil {
		return newError(CodeInternal, err)
	}
	if err := s.cs.Put(grantStoreID(g.ID), raw); err != nil {
		return newError(CodePlatform, fmt.Errorf("store refresh grant: %w", err))
	}
	return nil
}

func (s grantStore) GetGrant(_ context.Context, id string) (walletflow.RefreshGrant, error) {
	raw, err := s.cs.Get(grantStoreID(id))
	if err != nil {
		return walletflow.RefreshGrant{}, newError(CodePlatform, fmt.Errorf("refresh grant: %w", err))
	}
	if len(raw) == 0 {
		return walletflow.RefreshGrant{}, fmt.Errorf("mobile: refresh grant: %w", walletflow.ErrNotFound)
	}
	g, err := refreshGrant(raw)
	if err != nil || g.ID != id {
		return walletflow.RefreshGrant{}, newError(CodePlatform, errors.New("a refresh grant's record is malformed"))
	}
	return g, nil
}

func (s grantStore) ListGrants(context.Context) ([]walletflow.RefreshGrant, error) {
	all, err := listRecords(s.cs)
	if err != nil {
		return nil, err
	}
	var out []walletflow.RefreshGrant
	for _, raw := range all {
		if kindOf(raw) != grantKind {
			continue
		}
		g, err := refreshGrant(raw)
		if err != nil {
			return nil, newError(CodePlatform, errors.New("a refresh grant's record is malformed"))
		}
		out = append(out, g)
	}
	return out, nil
}

func (s grantStore) DeleteGrant(_ context.Context, id string) error {
	if err := s.cs.Delete(grantStoreID(id)); err != nil {
		return newError(CodePlatform, fmt.Errorf("delete refresh grant: %w", err))
	}
	return nil
}

func (s grantStore) Durable() bool { return s.cs.Durable() }

func refreshGrant(raw []byte) (walletflow.RefreshGrant, error) {
	var r grantRecord
	if err := json.Unmarshal(raw, &r); err != nil || r.ID == "" || r.RefreshToken == "" {
		return walletflow.RefreshGrant{}, errors.New("malformed")
	}
	return walletflow.RefreshGrant{
		ID: r.ID, CredentialIssuer: r.CredentialIssuer, AuthorizationServer: r.AuthorizationServer,
		ConfigurationID: r.ConfigurationID, RefreshToken: fapi.NewSecret(r.RefreshToken), InstanceKeyID: r.InstanceKeyID, CreatedAt: r.CreatedAt,
		ClientAuth: walletflow.GrantAuth(r.ClientAuth), DPoPKeyID: r.DPoPKeyID, TokenType: r.TokenType,
	}, nil
}

// RefreshCredential replaces the copies of the credential credentialID
// names with a fresh batch, without the holder
// (walletflow.Wallet.RefreshCredential): with "request_refresh" set, the
// issuance kept a refresh token for it ("refreshable" in its summary). It returns {"abi", "credential":
// summary, "deferred": deferred credential or null}: the credential, its
// ID unchanged, with every copy unused; or, when the issuer deferred
// the new one, the credential as it was and the deferred credential to
// poll, which settles as a new credential. A credential that can't be
// refreshed is reissue_required: receive it again from a new offer.
func (w *Wallet) RefreshCredential(op *Operation, credentialID string) (string, error) {
	c, d, err := w.w.RefreshCredential(op.context(), credentialID)
	if err != nil {
		return "", classify(err)
	}
	s, err := w.summary(c)
	if err != nil {
		return "", err
	}
	var deferred *deferredJSON
	if d != nil {
		dj := deferredOf(d)
		deferred = &dj
	}
	return marshal(struct {
		result
		Credential credentialSummary `json:"credential"`
		Deferred   *deferredJSON     `json:"deferred"`
	}{result{ABIVersion}, s, deferred})
}
