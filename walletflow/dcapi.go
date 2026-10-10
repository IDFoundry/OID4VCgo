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
// "origin:" + origin, and a copy presented counts as shown to that
// origin.
func (w *Wallet) StartDCAPIPresentation(ctx context.Context, protocol string, data []byte, origin string) (*Presentation, error) {
	if protocol != wallet.DCAPIProtocolUnsigned && w.cfg.VerifierTrust == nil {
		return nil, errors.New("walletflow: Config.VerifierTrust is required to answer a signed request")
	}
	req, err := w.core.ParseDCAPIRequestData(protocol, data, origin)
	if err != nil {
		if errors.Is(err, wallet.ErrUntrustedVerifier) {
			return nil, fmt.Errorf("walletflow: dc api request: %w", err)
		}
		return nil, fmt.Errorf("walletflow: dc api request: %w: %w", ErrMalformedRequest, err)
	}
	return w.newPresentation(ctx, req)
}

// verifier is who a copy presented here counts as shown to: the
// client_id's hash, or for a DC API request the origin's, which every
// form of it has — an unsigned one has no client_id.
func (p *Presentation) verifier() string {
	if p.req.Origin != "" {
		return originVerifier(p.req.Origin)
	}
	return VerifierHash(p.req.ClientID)
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

// declineDCAPI answers a DC API request with the holder's refusal
// (access_denied), encrypted as every dc_api.jwt response is, for the
// platform to hand back. It's built once, and the same refusal returned
// again; Respond is refused after it.
func (p *Presentation) declineDCAPI() (Presented, error) {
	if p.declined == "" {
		responseJWE, err := wallet.BuildDirectPostErrorResponse(wallet.BuildDirectPostErrorResponseParams{
			Error: "access_denied", ErrorDescription: "the holder declined",
			EncryptionKey: p.req.ResponseEncryptionKey, EncryptionKeyID: p.req.ResponseEncryptionKeyID,
			EncryptionEnc: p.req.ResponseEncryptionEnc,
		})
		if err != nil {
			return Presented{}, fmt.Errorf("walletflow: decline: %w", err)
		}
		p.declined = responseJWE
	}
	data, err := dcapiResponse(p.declined)
	if err != nil {
		return Presented{}, err
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
