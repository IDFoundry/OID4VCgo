package verifier_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Under claim_sets, a presentation may disclose the claims of the
// options it satisfies alone: a claim of an option it doesn't satisfy,
// one whose value fails its own values filter among them, is refused
// as unrequested (§6.4.1), unless AllowUnrequestedClaims. A
// presentation satisfying several options may carry each one's claims.
func TestVerifyResponse_ClaimSetsKeepOnlySatisfiedOptions(t *testing.T) {
	_, _, v := newTestVerifierWithConfig(t)
	issuerKey, holderKey := testP256Key(t), testP256Key(t)
	holderJWK, err := jwkFromECDSA(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	held := func(country string) wallet.HeldCredential {
		cred, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
			VCT: testVCT, CNF: map[string]any{"jwk": holderJWK},
			Additional: map[string]any{
				"given_name": sdjwtvc.SD("Jean"),
				"address":    sdjwtvc.SD(map[string]any{"country": sdjwtvc.SD(country), "street_address": sdjwtvc.SD("1 rue de la Paix")}),
			},
		}, sdjwtvc.IssueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256}
	}
	// "A German address, or failing that a name."
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{testVCT}})
	if err != nil {
		t.Fatal(err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{
			{ID: "country", Path: path("address", "country"), Values: []any{"DE"}},
			{ID: "street", Path: path("address", "street_address")},
			{ID: "name", Path: path("given_name")},
		},
		ClaimSets: [][]string{{"country", "street"}, {"name"}},
	}}}
	if err := query.Validate(); err != nil {
		t.Fatal(err)
	}
	address := []dcql.Path{path("address", "country"), path("address", "street_address")}
	name := []dcql.Path{path("given_name")}
	verify := func(country string, paths []dcql.Path, allowUnrequested bool) error {
		t.Helper()
		presented, err := wallet.PresentSDJWTVCSelective(held(country), v.ClientID(), "n-1", paths)
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query:         query,
			Response:      verifier.ParsedResponse{VPToken: map[string][]string{"pid": {presented}}},
			ExpectedNonce: "n-1", IssuerKeys: fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256},
			MaxKeyBindingAge: time.Hour, NoStatusCheck: true, AllowUnrequestedClaims: allowUnrequested,
		})
		return err
	}

	// A French address satisfies no option of its own: sent beside the
	// name, it's refused.
	var verr *verifier.Error
	if err := verify("FR", append(name, address...), false); !errors.As(err, &verr) || verr.Reason() != verifier.ReasonUnrequestedClaims {
		t.Errorf("a name and a French address: %v, want unrequested_claims", err)
	}
	if err := verify("FR", name, false); err != nil {
		t.Errorf("the name alone: %v", err)
	}
	if err := verify("FR", append(name, address...), true); err != nil {
		t.Errorf("a name and a French address with AllowUnrequestedClaims: %v", err)
	}
	// A German address satisfies the first option, the name the second.
	if err := verify("DE", append(name, address...), false); err != nil {
		t.Errorf("a name and a German address: %v", err)
	}
}
