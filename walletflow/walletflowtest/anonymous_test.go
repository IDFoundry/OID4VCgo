package walletflowtest_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// An Anonymous issuer is one a wallet provisions from as OpenID4VCI 1.0
// allows outside HAIP: its pre-authorized code is redeemed with only a
// DPoP proof, no client authentication, and its credentials requested
// with jwt proofs, no key attestation. This is the wallet package's own
// sequence for it, with or without a nonce endpoint.
func TestAnonymous(t *testing.T) {
	for _, noNonce := range []bool{false, true} {
		env, err := walletflowtest.New(walletflowtest.Options{Anonymous: true, NoNonceEndpoint: noNonce})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(env.Close)
		ctx := context.Background()
		w, err := wallet.New(wallet.Config{
			Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: oid4vci.ES256,
			Fetch: fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 10 * time.Second, AllowLoopbackHTTP: true},
		}, wallet.Dependencies{HTTP: env.HTTP, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
		if err != nil {
			t.Fatal(err)
		}

		uri, err := env.PreAuthorizedOffer("", walletflowtest.MdocConfigurationID)
		if err != nil {
			t.Fatal(err)
		}
		offer, err := w.ResolveCredentialOffer(ctx, uri)
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := w.FetchCredentialIssuerMetadata(ctx, offer.CredentialIssuer)
		if err != nil {
			t.Fatal(err)
		}
		if (metadata.NonceEndpoint == nil) != noNonce {
			t.Fatalf("nonce endpoint %v; want none: %v", metadata.NonceEndpoint, noNonce)
		}
		if _, ok := metadata.CredentialConfigurationsSupported[walletflowtest.MdocConfigurationID].ProofTypesSupported[oid4vci.ProofTypeJWT]; !ok {
			t.Fatal("the jwt proof type isn't supported")
		}
		if offer.Grants.PreAuthorizedCode.TxCode != nil {
			t.Error("the offer asks for a PIN")
		}
		plan, err := wallet.PlanPreAuthorizedCode(offer, metadata)
		if err != nil {
			t.Fatal(err)
		}
		asMeta, err := w.FetchAuthorizationServerMetadata(ctx, plan.AuthorizationServer)
		if err != nil {
			t.Fatal(err)
		}
		if asMeta.AuthorizationEndpoint != "" || asMeta.PushedAuthorizationRequestEndpoint != "" {
			t.Errorf("authorization endpoints %q, %q; want none", asMeta.AuthorizationEndpoint, asMeta.PushedAuthorizationRequestEndpoint)
		}
		tokenEndpoint, err := fapi.ParseEndpointURL(asMeta.TokenEndpoint, fapi.AllowLoopbackHTTP())
		if err != nil {
			t.Fatal(err)
		}

		dpopKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		token, err := w.RequestPreAuthorizedCodeToken(ctx, tokenEndpoint, wallet.PreAuthorizedCodeTokenRequest{
			PreAuthorizedCode: plan.PreAuthorizedCode, DPoPKey: dpopKey,
		})
		if err != nil {
			t.Fatalf("anonymous token request: %v", err)
		}
		var nonce string
		if metadata.NonceEndpoint != nil {
			n, err := w.RequestNonce(ctx, *metadata.NonceEndpoint)
			if err != nil {
				t.Fatal(err)
			}
			nonce = n.CNonce
		}
		holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		req := wallet.CredentialRequest{Keys: []crypto.Signer{holder}, CredentialIssuer: offer.CredentialIssuer, Nonce: nonce}
		if len(token.AuthorizationDetails) == 1 && len(token.AuthorizationDetails[0].CredentialIdentifiers) > 0 {
			req.CredentialIdentifier = token.AuthorizationDetails[0].CredentialIdentifiers[0]
		} else {
			req.CredentialConfigurationID = walletflowtest.MdocConfigurationID
		}
		result, err := w.RequestCredential(ctx, w.DPoPResourceClient(token.AccessToken, dpopKey), metadata.CredentialEndpoint, req)
		if err != nil || len(result.Credentials) != 1 {
			t.Fatalf("RequestCredential = %+v, %v", result, err)
		}
		if _, err := wallet.VerifyIssuedCredential(ctx, wallet.VerifyIssuedCredentialParams{
			Configuration: metadata.CredentialConfigurationsSupported[walletflowtest.MdocConfigurationID],
			Credential:    result.Credentials[0].Credential, HolderKey: &holder.PublicKey, IssuerRoots: env.IssuerRoots,
		}); err != nil {
			t.Errorf("VerifyIssuedCredential: %v", err)
		}
	}
}
