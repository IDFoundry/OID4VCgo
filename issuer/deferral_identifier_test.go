package issuer_test

import (
	"context"
	"reflect"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// identifierDetail is an authorization detail granting configID,
// through credential_identifiers ids when there are any.
func identifierDetail(configID string, ids ...string) oid4vci.AuthorizationDetail {
	return oid4vci.AuthorizationDetail{
		Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: configID, CredentialIdentifiers: ids,
	}
}

// identifierAuth is deferralAuth's client and subject with details
// instead of a scope.
func identifierAuth(details ...oid4vci.AuthorizationDetail) issuer.AuthorizedRequest {
	return issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Subject: "holder-1", AuthorizationDetails: details}
}

// deferIssued defers req, with a fresh proof, under auth and issues it,
// returning its transaction_id.
func (f deferralFixture) deferIssued(t *testing.T, auth issuer.AuthorizedRequest, req issuer.CredentialRequest) string {
	t.Helper()
	ctx := context.Background()
	req.Proofs = map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}}
	req.Defer = &issuer.Deferral{Reference: "ref"}
	resp, err := f.iss.RequestCredential(ctx, auth, req)
	if err != nil {
		t.Fatalf("RequestCredential (deferred): %v", err)
	}
	if err := f.iss.IssueDeferredCredential(ctx, resp.TransactionID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
		t.Fatalf("IssueDeferredCredential: %v", err)
	}
	return resp.TransactionID
}

// TestDeferral_BindsCredentialIdentifier: a transaction requested by
// credential_identifier (§8.2) is collected only with a token that
// still authorizes that identifier (§9: "valid for the issuance of the
// Credential(s) previously requested"), not one granting the same
// configuration through another identifier; the refused poll leaves the
// transaction for the right token.
func TestDeferral_BindsCredentialIdentifier(t *testing.T) {
	ctx := context.Background()
	f := newDeferralFixture(t)
	original := identifierAuth(identifierDetail(testSDJWTConfigID, "dataset-A"))
	txID := f.deferIssued(t, original, issuer.CredentialRequest{CredentialIdentifier: "dataset-A"})

	before, err := f.store.Get(ctx, txID)
	if err != nil {
		t.Fatal(err)
	}
	if before.CredentialIdentifier != "dataset-A" || before.CredentialConfigurationID != testSDJWTConfigID {
		t.Fatalf("record = %+v, want credential_identifier dataset-A of %s", before, testSDJWTConfigID)
	}
	poll := func(auth issuer.AuthorizedRequest) (issuer.DeferredCredentialResult, error) {
		return f.iss.RequestDeferredCredential(ctx, auth, issuer.DeferredCredentialRequest{TransactionID: txID})
	}

	for name, auth := range map[string]issuer.AuthorizedRequest{
		"another identifier":                      identifierAuth(identifierDetail(testSDJWTConfigID, "dataset-B")),
		"the configuration without identifiers":   identifierAuth(identifierDetail(testSDJWTConfigID)),
		"the configuration by its scope":          {ClientIdentity: issuer.KnownClientID("test-client"), Subject: "holder-1", Scopes: deferralAuth.Scopes},
		"the identifier of another configuration": identifierAuth(identifierDetail(testMdocConfigID, "dataset-A")),
	} {
		res, err := poll(auth)
		if err == nil {
			t.Fatalf("%s: collected the transaction: %+v", name, res)
		}
		assertIssuerError(t, err, issuer.ErrorInvalidTransactionID)
		after, err := f.store.Get(ctx, txID)
		if err != nil {
			t.Fatalf("%s: the refused poll consumed the transaction: %v", name, err)
		}
		if !reflect.DeepEqual(after, before) {
			t.Fatalf("%s: the refused poll changed the record:\n%+v\nwant\n%+v", name, after, before)
		}
	}

	// A refreshed token still authorizing dataset-A, among others,
	// collects it.
	refreshed := identifierAuth(identifierDetail(testSDJWTConfigID, "dataset-B", "dataset-A"))
	res, err := poll(refreshed)
	if err != nil || len(res.Credentials) != 1 {
		t.Fatalf("poll with a token authorizing dataset-A = %+v, %v", res, err)
	}
}

// TestDeferral_ByConfigurationIDNeedsTheConfiguration: a transaction
// requested by credential_configuration_id records no identifier, and
// any token granting the configuration collects it, as before.
func TestDeferral_ByConfigurationIDNeedsTheConfiguration(t *testing.T) {
	ctx := context.Background()
	f := newDeferralFixture(t)
	auth := identifierAuth(identifierDetail(testSDJWTConfigID))
	txID := f.deferIssued(t, auth, issuer.CredentialRequest{CredentialConfigurationID: testSDJWTConfigID})
	record, err := f.store.Get(ctx, txID)
	if err != nil {
		t.Fatal(err)
	}
	if record.CredentialIdentifier != "" {
		t.Fatalf("record.CredentialIdentifier = %q, want none", record.CredentialIdentifier)
	}
	res, err := f.iss.RequestDeferredCredential(ctx, identifierAuth(identifierDetail(testSDJWTConfigID)), issuer.DeferredCredentialRequest{TransactionID: txID})
	if err != nil || len(res.Credentials) != 1 {
		t.Fatalf("poll with a configuration grant = %+v, %v", res, err)
	}
}
