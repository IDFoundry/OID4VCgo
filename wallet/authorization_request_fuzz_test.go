package wallet_test

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testverifier"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// FuzzParseAuthorizationRequest exercises ParseAuthorizationRequest
// against arbitrary strings — a Request Object is Verifier-supplied
// (or, in the request_uri flow, fetched from wherever the Verifier
// named), attacker-controlled wire data a Wallet must parse before it
// discloses anything. Notable: PR #110 found a real bug here
// (selectResponseEncryptionKey blindly trusting keys[0] instead of
// skipping unparseable decoy JWKs) — the exact class of defect fuzzing
// exists to catch, in this exact function. Builds one genuine,
// verifier.BuildAuthorizationRequest-produced Request Object as seed
// material so the fuzzer starts from something that actually parses.
func FuzzParseAuthorizationRequest(f *testing.F) {
	v := testverifier.New(f)
	clientID := v.ClientID()

	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		f.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "cred1", Format: "dc+sd-jwt", Meta: meta}}}

	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query, State: "fuzz-state"})
	if err != nil {
		f.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	f.Add(built.RequestObject)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, requestObject string) {
		_, _ = wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
			RequestObject: requestObject, ClientID: clientID,
		})
	})
}
