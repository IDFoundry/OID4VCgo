package walletflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// StartDCAPIPresentation parses an OpenID4VP request delivered through
// the Digital Credentials API (OpenID4VP 1.0 Appendix A) — protocol and
// data as the platform hands them over, in any of the unsigned, signed
// and multi-signed forms (wallet.ParseDCAPIRequestData), and origin the
// calling page's or app's origin as the platform reports it, never
// taken from the request — and finds the held credentials that can
// answer it, without sending anything.
//
// It's a Presentation like StartPresentation's: show the holder
// Verifier (its Origin, and its Name when the request is signed),
// Queries and CredentialSets, Preview a Selection, then Respond or
// Decline. Neither sends anything: each returns, in
// Presented.DCAPIResponse, the encrypted response to hand back to the
// platform, which delivers it. Presentations are bound to
// "origin:" + origin. A copy presented counts as shown to that origin,
// for an unsigned request, or for a signed one to its client_id at that
// origin: two Verifiers whose requests come from one page are two
// Verifiers (Presentation.ShownTo).
//
// A *RequestRefusedError, whose DCAPIResponse the platform hands back to
// the page, is returned only for a request from the origin it names (a
// signed one's expected_origins) and, when signed, from a Verifier
// VerifierTrust accepts. Every other refusal is a plain error with
// nothing for the page: a signed request from another origin, refused
// first whatever else is wrong with it (wallet.ParseDCAPIRequest), one
// from an untrusted Verifier (ErrUntrustedVerifier), and one that
// can't be parsed (ErrMalformedRequest). Fail the platform's call the
// same way for each, so the page can't tell them apart: one replaying
// another Verifier's request can't learn whether the wallet trusts it.
func (w *Wallet) StartDCAPIPresentation(ctx context.Context, protocol string, data []byte, origin string) (*Presentation, error) {
	if protocol != wallet.DCAPIProtocolUnsigned && w.cfg.VerifierTrust == nil {
		return nil, fmt.Errorf("walletflow: Config.VerifierTrust is required to answer a signed request: %w", ErrNotConfigured)
	}
	req, err := w.core.ParseDCAPIRequestDataContext(ctx, protocol, data, origin)
	var rejected *wallet.RequestRejectedError
	if errors.As(err, &rejected) {
		// Returned to the page through the platform, in Appendix A.4's
		// error shape, as Decline's: "a single property with the name
		// error".
		response, encErr := json.Marshal(map[string]string{"error": rejected.Code})
		if encErr != nil {
			return nil, fmt.Errorf("walletflow: dc api request: %w", encErr)
		}
		return nil, &RequestRefusedError{Code: rejected.Code, Description: rejected.Description, DCAPIResponse: response}
	}
	if err != nil {
		if errors.Is(err, wallet.ErrUntrustedVerifier) || ctx.Err() != nil {
			return nil, fmt.Errorf("walletflow: dc api request: %w", err)
		}
		return nil, fmt.Errorf("walletflow: dc api request: %w: %w", ErrMalformedRequest, err)
	}
	return w.newPresentation(ctx, req)
}

// verifier is who a copy presented here counts as shown to (its
// VerifierHash, of verifierName).
func (p *Presentation) verifier() string { return VerifierHash(p.verifierName()) }

// verifierName is who a copy presented here counts as shown to: the
// client_id; for an unsigned DC API request, which has none, the
// origin; and for a signed one, the client_id at the origin. Either
// alone isn't enough there: one page may make the requests of several
// Verifiers, each signing with its own key, and a client_id is bound to
// that key, not to the page. A copy stored as shown to the origin alone,
// as one presented over a signed request before this was kept, counts
// as shown to another Verifier: a Verifier at that origin isn't shown
// it again as its own, and presenting it is Linkable — it may have been
// another Verifier's.
func (p *Presentation) verifierName() string {
	switch {
	case p.req.Origin == "":
		return p.req.ClientID
	case p.req.ClientID == "":
		return "origin:" + p.req.Origin
	default:
		// The origin, which has no space, first: unambiguous.
		return "origin:" + p.req.Origin + " client_id:" + p.req.ClientID
	}
}

// ShownTo reports whether the credential id names has been shown to
// this Verifier before: as StoredCredential.ShownTo, for the Verifier
// a DC API request identifies as walletflow does (StartDCAPIPresentation)
// — not, for a signed one, by its client_id or origin alone. False for
// a credential not held.
func (p *Presentation) ShownTo(id string) bool {
	c, ok := p.byID[id]
	return ok && c.ShownTo(p.verifierName())
}

// answerDCAPI presents held, bound to the request's origin and nonce,
// as a DC API response: the encrypted vp_token, in the data the
// platform hands back.
func (p *Presentation) answerDCAPI(ctx context.Context, held map[string][]wallet.HeldCredential) (Presented, error) {
	vpToken, err := wallet.PresentCredentials(ctx, wallet.PresentationRequest{
		Query: p.req.Query, Selection: held, Origin: p.req.Origin, Nonce: p.req.Nonce,
		ResponseEncryptionKey: p.req.ResponseEncryptionKey, TrustedAuthorities: trustedAuthorities,
	})
	if err != nil {
		return Presented{}, fmt.Errorf("walletflow: respond: %w", err)
	}
	responseJWE, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, EncryptionKey: p.req.ResponseEncryptionKey,
		EncryptionKeyID: p.req.ResponseEncryptionKeyID, EncryptionEnc: p.req.ResponseEncryptionEnc,
	})
	if err != nil {
		return Presented{}, fmt.Errorf("walletflow: respond: %w", err)
	}
	data, err := dcapiResponse(responseJWE)
	if err != nil {
		return Presented{}, err
	}
	presented := Presented{DCAPIResponse: data}
	for id := range vpToken {
		presented.QueryIDs = append(presented.QueryIDs, id)
	}
	sort.Strings(presented.QueryIDs)
	return presented, nil
}

// declineDCAPI answers a DC API request with the holder's refusal, as
// OpenID4VP Appendix A.4's protocol error: {"error": "access_denied"}
// in the data the platform hands back, not encrypted, since it carries
// nothing about the holder. Respond is refused after it.
func (p *Presentation) declineDCAPI() (Presented, error) {
	p.declined = "access_denied"
	data, err := json.Marshal(map[string]string{"error": p.declined})
	if err != nil {
		return Presented{}, fmt.Errorf("walletflow: decline: %w", err)
	}
	return Presented{DCAPIResponse: data}, nil
}

// dcapiResponse is the DC API response's data for responseJWE.
func dcapiResponse(responseJWE string) ([]byte, error) {
	data, err := json.Marshal(map[string]string{"response": responseJWE})
	if err != nil {
		return nil, fmt.Errorf("walletflow: dc api response: %w", err)
	}
	return data, nil
}
