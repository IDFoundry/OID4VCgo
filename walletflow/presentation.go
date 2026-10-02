package walletflow

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Verifier is who's asking, for the holder to see.
type Verifier struct {
	// ClientID is the Verifier's client identifier, checked against the
	// Request Object's signature.
	ClientID string
	// Name is the subject common name of the Verifier's request-signing
	// certificate, which VerifierTrust accepted.
	Name string
	// Certificate is that certificate.
	Certificate *x509.Certificate
	// ResponseURI is where the answer would be sent.
	ResponseURI string
}

// Candidates are the held credentials that can answer one of the
// request's Credential Queries.
type Candidates struct {
	// QueryID is the DCQL Credential Query.
	QueryID string
	// Credentials can each answer it.
	Credentials []StoredCredential
}

// Disclosure is what presenting one credential would disclose.
type Disclosure struct {
	// QueryID is the Credential Query it answers.
	QueryID string
	// CredentialID is the stored credential presented.
	CredentialID string
	// Claims are the claim paths disclosed: ["family_name"] for an
	// SD-JWT VC, [namespace, element] for an mdoc. Claims the issuer
	// didn't make selectively disclosable are seen regardless.
	Claims []dcql.Path
}

// Presented is what Respond or Decline sent.
type Presented struct {
	// QueryIDs are the Credential Queries answered; none for Decline.
	QueryIDs []string
	// RedirectURI, when the Verifier returned one, is where the wallet
	// must now send the browser (OpenID4VP 1.0 §8.2).
	RedirectURI string
}

// Presentation answers one Authorization Request.
type Presentation struct {
	w          *Wallet
	req        wallet.AuthorizationRequest
	candidates []Candidates
	byID       map[string]StoredCredential

	mu       sync.Mutex
	answered bool
}

// StartPresentation fetches and verifies the OpenID4VP Authorization
// Request requestLink (an openid4vp:// link with client_id and
// request_uri) from a Verifier Config.VerifierTrust accepts, and finds
// the held credentials that can answer it, without sending anything.
// Show the holder Verifier and Candidates, then Respond or Decline.
func (w *Wallet) StartPresentation(ctx context.Context, requestLink string) (*Presentation, error) {
	if w.cfg.VerifierTrust == nil {
		return nil, errors.New("walletflow: Config.VerifierTrust is required to present")
	}
	link, err := wallet.ParseAuthorizationRequestLink(requestLink)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	// Checks the signing certificate chains to a trusted CA, the Request
	// Object's signature, and that client_id is bound to that
	// certificate.
	req, err := w.core.FetchAuthorizationRequest(ctx, link.RequestURI, link.ClientID)
	if err != nil {
		return nil, fmt.Errorf("walletflow: presentation request: %w", err)
	}
	return w.newPresentation(ctx, req)
}

func (w *Wallet) newPresentation(ctx context.Context, req wallet.AuthorizationRequest) (*Presentation, error) {
	stored, err := w.deps.Credentials.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("walletflow: list credentials: %w", err)
	}
	p := &Presentation{w: w, req: req, byID: make(map[string]StoredCredential, len(stored))}
	held := make([]wallet.HeldCredential, 0, len(stored))
	for _, c := range stored {
		p.byID[c.ID] = c
		held = append(held, heldCredential(c, nil))
	}
	// Every credential that can answer each query, not only the first:
	// the holder chooses. No match isn't an error here: the holder is
	// told, and may decline.
	matches, err := wallet.MatchDCQLQuery(ctx, everyMatch(req.Query), held, trustedAuthorities)
	if err != nil {
		return p, nil
	}
	byCredential := make(map[string]StoredCredential, len(stored))
	for _, c := range stored {
		byCredential[c.Credential] = c
	}
	for queryID, creds := range matches {
		cs := Candidates{QueryID: queryID}
		for _, h := range creds {
			cs.Credentials = append(cs.Credentials, byCredential[h.Credential])
		}
		p.candidates = append(p.candidates, cs)
	}
	sort.Slice(p.candidates, func(i, j int) bool { return p.candidates[i].QueryID < p.candidates[j].QueryID })
	return p, nil
}

// everyMatch is q with every Credential Query asking for all matching
// credentials, to list the candidates for each.
func everyMatch(q dcql.Query) dcql.Query {
	q.Credentials = slices.Clone(q.Credentials)
	for i := range q.Credentials {
		q.Credentials[i].Multiple = true
	}
	return q
}

// trustedAuthorities answers a query's trusted_authorities with the
// issuer certificate's Authority Key Identifier.
var trustedAuthorities = dcql.AKITrustedAuthoritiesChecker{}

// heldCredential is c as the wallet package presents it, signing with
// holderKey (nil to match without presenting).
func heldCredential(c StoredCredential, holderKey Key) wallet.HeldCredential {
	h := wallet.HeldCredential{Format: c.Format, Credential: c.Credential, HolderKeyAlg: oid4vci.ES256, MdocDocType: c.DocType}
	if holderKey != nil {
		h.HolderKey = holderKey
	}
	return h
}

// Verifier returns who's asking.
func (p *Presentation) Verifier() Verifier {
	v := Verifier{ClientID: p.req.ClientID, Certificate: p.req.VerifierCertificate, ResponseURI: p.req.ResponseURI}
	if p.req.VerifierCertificate != nil {
		v.Name = p.req.VerifierCertificate.Subject.CommonName
	}
	return v
}

// Candidates returns, for each Credential Query the held credentials
// can answer, the credentials that can answer it, ordered by QueryID.
// None means the wallet can't answer: Decline.
func (p *Presentation) Candidates() []Candidates { return p.candidates }

// Preview reports what Respond(ctx, credentialIDs) would disclose,
// without sending anything: show it to the holder for consent.
func (p *Presentation) Preview(ctx context.Context, credentialIDs []string) ([]Disclosure, error) {
	held, err := p.chosen(ctx, credentialIDs, false)
	if err != nil {
		return nil, err
	}
	preview, err := wallet.PreviewPresentation(ctx, p.req.Query, held, trustedAuthorities)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w: %w", ErrNoMatchingCredential, err)
	}
	ids := p.idsByCredential(credentialIDs)
	out := make([]Disclosure, 0, len(preview))
	for _, c := range preview {
		out = append(out, Disclosure{QueryID: c.QueryID, CredentialID: ids[c.Credential.Credential], Claims: c.Claims})
	}
	return out, nil
}

// Respond presents credentialIDs — chosen from Candidates; nil means
// every candidate, letting the request's query choose — bound to the
// Verifier's nonce and client_id, and sends them in an encrypted
// direct_post.jwt response. Holder keys sign here, so a KeyStore that
// requires user presence prompts now. A Presentation is answered once.
func (p *Presentation) Respond(ctx context.Context, credentialIDs []string) (Presented, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.answered {
		return Presented{}, ErrWrongStep
	}
	held, err := p.chosen(ctx, credentialIDs, true)
	if err != nil {
		return Presented{}, err
	}
	responded, err := wallet.Respond(ctx, p.w.deps.HTTP, p.req, held, trustedAuthorities)
	if err != nil {
		return Presented{}, fmt.Errorf("walletflow: respond: %w", err)
	}
	p.answered = true
	presented := Presented{RedirectURI: responded.Reply.RedirectURI}
	for id := range responded.VPToken {
		presented.QueryIDs = append(presented.QueryIDs, id)
	}
	sort.Strings(presented.QueryIDs)
	return presented, nil
}

// Decline tells the Verifier the holder declined (access_denied, in an
// encrypted direct_post.jwt error response). An error from the Verifier
// is returned, but the Presentation is answered all the same: the
// holder's refusal stands.
func (p *Presentation) Decline(ctx context.Context) (Presented, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.answered {
		return Presented{}, ErrWrongStep
	}
	responseJWE, err := wallet.BuildDirectPostErrorResponse(wallet.BuildDirectPostErrorResponseParams{
		Error: "access_denied", ErrorDescription: "the holder declined", State: p.req.State,
		EncryptionKey: p.req.ResponseEncryptionKey, EncryptionKeyID: p.req.ResponseEncryptionKeyID,
		EncryptionEnc: p.req.ResponseEncryptionEnc,
	})
	if err != nil {
		return Presented{}, fmt.Errorf("walletflow: decline: %w", err)
	}
	p.answered = true
	reply, err := wallet.SubmitDirectPostResponse(ctx, p.w.deps.HTTP, p.req.ResponseURI, responseJWE)
	if err != nil {
		return Presented{}, fmt.Errorf("walletflow: decline: %w", err)
	}
	return Presented{RedirectURI: reply.RedirectURI}, nil
}

// chosen returns credentialIDs as held credentials (every candidate for
// nil), with their holder keys when withKeys is set. Every ID must be a
// candidate.
func (p *Presentation) chosen(ctx context.Context, credentialIDs []string, withKeys bool) ([]wallet.HeldCredential, error) {
	var candidates []string
	for _, cs := range p.candidates {
		for _, c := range cs.Credentials {
			if !slices.Contains(candidates, c.ID) {
				candidates = append(candidates, c.ID)
			}
		}
	}
	if len(candidates) == 0 {
		return nil, ErrNoMatchingCredential
	}
	if credentialIDs == nil {
		credentialIDs = candidates
	}
	held := make([]wallet.HeldCredential, 0, len(credentialIDs))
	for _, id := range credentialIDs {
		if !slices.Contains(candidates, id) {
			return nil, fmt.Errorf("walletflow: credential %q doesn't answer the request", id)
		}
		c := p.byID[id]
		var key Key
		if withKeys {
			k, err := p.w.deps.Keys.Key(ctx, c.HolderKeyID)
			if err != nil {
				return nil, fmt.Errorf("walletflow: credential %q's holder key: %w", id, err)
			}
			key = k
		}
		held = append(held, heldCredential(c, key))
	}
	return held, nil
}

// idsByCredential maps each chosen credential's text to its ID.
func (p *Presentation) idsByCredential(credentialIDs []string) map[string]string {
	ids := make(map[string]string, len(p.byID))
	for id, c := range p.byID {
		if credentialIDs == nil || slices.Contains(credentialIDs, id) {
			ids[c.Credential] = id
		}
	}
	return ids
}
