package wallet

import (
	"context"
	"fmt"
	"time"

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
// credentials first: Respond sends without asking. Once the
// presentation is signed, cancelling ctx no longer stops it: it's sent,
// within 30 seconds, so the holder isn't left not knowing whether the
// Verifier has it.
//
// client posts to response_uri, the Verifier's choice: in production it
// must be one fapihttp.NewClient built, as SubmitDirectPostResponse
// says. (*Wallet).Respond uses the Wallet's own client instead.
func Respond(ctx context.Context, client fapihttp.HTTPClient, req AuthorizationRequest, credentials []HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) (Responded, error) {
	return respond(ctx, client, req, PresentationRequest{Credentials: credentials}, trustedAuthorities)
}

// Respond is the package-level Respond sent with this Wallet's own HTTP
// client (Dependencies.HTTP), which New has checked.
func (w *Wallet) Respond(ctx context.Context, req AuthorizationRequest, credentials []HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) (Responded, error) {
	return respond(ctx, w.deps.HTTP, req, PresentationRequest{Credentials: credentials}, trustedAuthorities)
}

// RespondSelection is the package-level RespondSelection sent with this
// Wallet's own HTTP client (Dependencies.HTTP), which New has checked:
// in production, the package-level form's client must be one
// fapihttp.NewClient built, as SubmitDirectPostResponse says.
func (w *Wallet) RespondSelection(ctx context.Context, req AuthorizationRequest, selection map[string][]HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) (Responded, error) {
	return respond(ctx, w.deps.HTTP, req, PresentationRequest{Selection: selection}, trustedAuthorities)
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
	// Signed, the presentation is what the holder consented to send:
	// it's sent even when ctx is cancelled meanwhile (the holder leaving
	// the screen, say), within submitTimeout, rather than cut off
	// mid-request, leaving the holder not knowing whether the Verifier
	// has it.
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), submitTimeout)
	defer cancel()
	reply, err := SubmitDirectPostResponse(sendCtx, client, req.ResponseURI, responseJWE)
	if err != nil {
		return Responded{}, fmt.Errorf("wallet: respond: %w", err)
	}
	return Responded{VPToken: vpToken, Reply: reply}, nil
}

// submitTimeout bounds sending a signed presentation once its caller's
// context no longer can.
const submitTimeout = 30 * time.Second
