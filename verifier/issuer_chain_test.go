package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/verifier/verifiertest"
)

// The x5c chain trusted_authorities checks is the one whose leaf key
// verified the credential: an issuer trusted some other way (a kid or
// DID resolver) can't pass a query naming another CA by copying that
// CA's public chain into its header. The same chain, signed by its own
// leaf key, passes and comes back as IssuerChain.
func TestVerifyResponse_TrustedAuthoritiesChainIsTheSigners(t *testing.T) {
	caA, caAKey := verifiertest.ContractCA(t, "issuer-A-ca")
	leafA, leafAKey := verifiertest.ContractLeaf(t, "issuer-A", caA, caAKey)
	query := trustedAuthoritiesQuery(t, base64.RawURLEncoding.EncodeToString(caA.SubjectKeyId))

	present := func(signer *ecdsa.PrivateKey) error {
		t.Helper()
		_, _, v := newTestVerifierWithConfig(t)
		built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
		if err != nil {
			t.Fatal(err)
		}
		holderKey := testP256Key(t)
		holderJWK, err := jwkFromECDSA(&holderKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(map[string]any{"vct": testVCT, "cnf": map[string]any{"jwk": holderJWK}, "given_name": "Mallory"})
		if err != nil {
			t.Fatal(err)
		}
		issuerJWT, err := jose.Sign(jose.ES256, signer, map[string]any{"typ": "dc+sd-jwt", "x5c": []string{base64.StdEncoding.EncodeToString(leafA.Raw)}}, payload)
		if err != nil {
			t.Fatal(err)
		}
		pres, err := sdjwtvc.Parse(issuerJWT + "~")
		if err != nil {
			t.Fatal(err)
		}
		if pres.KeyBindingJWT, err = sdjwtvc.NewKeyBindingJWT(holderKey, jose.ES256, pres, sdjwtvc.SHA256, sdjwtvc.KeyBindingClaims{Audience: v.ClientID(), Nonce: built.Nonce}); err != nil {
			t.Fatal(err)
		}
		compact, err := pres.Compact()
		if err != nil {
			t.Fatal(err)
		}
		res, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query:              query,
			Response:           verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {compact}}},
			ExpectedNonce:      built.Nonce,
			IssuerKeys:         fixedSDJWTVCIssuerKeyResolver{pub: &signer.PublicKey, alg: jose.ES256},
			MaxKeyBindingAge:   time.Hour,
			TrustedAuthorities: dcql.AKITrustedAuthoritiesChecker{Roots: rootsOf(caA)},
		})
		if err == nil && len(res.Credentials) > 0 && len(res.Credentials[0].IssuerChain) != 1 {
			t.Errorf("IssuerChain = %d certificates, want the signer's one", len(res.Credentials[0].IssuerChain))
		}
		return err
	}

	if err := present(testP256Key(t)); err == nil || !strings.Contains(err.Error(), "trusted_authorities") && !strings.Contains(err.Error(), "trusted authorities") {
		t.Errorf("another issuer carrying A's chain: %v, want trusted_authorities refused", err)
	}
	if err := present(leafAKey); err != nil {
		t.Errorf("A's own credential: %v", err)
	}
}
