package wallet

import (
	"context"
	"fmt"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// Responded is what Respond sent, and the Verifier's reply.
type Responded struct {
	// VPToken is the presentations sent, by Credential Query ID.
	VPToken map[string][]string

	// Reply is the Verifier's reply — its redirect_uri, for a
	// same-device flow, which the Wallet must send the browser to.
	Reply DirectPostResult
}

// Respond answers req — a verified Authorization Request, from
// ParseAuthorizationRequest or FetchAuthorizationRequest — with
// credentials, in one call: it presents what req's query asks of them
// (PresentCredentials, bound to req's client_id, nonce and response
// encryption key), encrypts the answer to req's response key
// (BuildDirectPostResponse, direct_post.jwt), and posts it to req's
// response_uri (SubmitDirectPostResponse). trustedAuthorities narrows
// which credentials may answer a query that names trusted authorities;
// nil answers only queries that name none.
//
// Show the holder PreviewPresentation's view of the same request and
// credentials first: Respond sends without asking.
func Respond(ctx context.Context, client fapihttp.HTTPClient, req AuthorizationRequest, credentials []HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) (Responded, error) {
	return respond(ctx, client, req, PresentationRequest{Credentials: credentials}, trustedAuthorities)
}

// respond presents what pr chooses (Credentials to match, or a
// Selection) for req and submits it.
func respond(ctx context.Context, client fapihttp.HTTPClient, req AuthorizationRequest, pr PresentationRequest, trustedAuthorities dcql.TrustedAuthoritiesChecker) (Responded, error) {
	pr.Query, pr.Audience, pr.Nonce = req.Query, req.ClientID, req.Nonce
	pr.ResponseURI, pr.ResponseEncryptionKey, pr.TrustedAuthorities = req.ResponseURI, req.ResponseEncryptionKey, trustedAuthorities
	vpToken, err := PresentCredentials(ctx, pr)
	if err != nil {
		return Responded{}, fmt.Errorf("wallet: respond: %w", err)
	}
	responseJWE, err := BuildDirectPostResponse(BuildDirectPostResponseParams{
		VPToken: vpToken, State: req.State, EncryptionKey: req.ResponseEncryptionKey,
		EncryptionKeyID: req.ResponseEncryptionKeyID, EncryptionEnc: req.ResponseEncryptionEnc,
	})
	if err != nil {
		return Responded{}, fmt.Errorf("wallet: respond: %w", err)
	}
	reply, err := SubmitDirectPostResponse(ctx, client, req.ResponseURI, responseJWE)
	if err != nil {
		return Responded{}, fmt.Errorf("wallet: respond: %w", err)
	}
	return Responded{VPToken: vpToken, Reply: reply}, nil
}
