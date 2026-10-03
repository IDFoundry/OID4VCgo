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

// Query is one of the request's DCQL Credential Queries (OpenID4VP 1.0
// §6.1), with the held credentials that can answer it.
type Query struct {
	ID string
	// Multiple is whether it takes more than one credential; otherwise
	// a Selection gives it exactly one.
	Multiple bool
	// Credentials can each answer it; none when nothing held can.
	Credentials []StoredCredential
}

// CredentialSet is one of the request's credential_sets (§6.2): ways to
// answer it, each the Credential Query IDs that together do, most
// preferred first. A Required set must be answered by one of its
// options; an optional one may be left out.
type CredentialSet struct {
	Options  [][]string
	Required bool
}

// Selection is what to present: for each Credential Query ID, the IDs
// of the stored credentials chosen to answer it. The wallet presents
// exactly this, after checking it answers the request (ValidateSelection
// in the wallet package); it never picks a credential of its own.
type Selection map[string][]string

// ErrInvalidSelection is wrapped by Preview and Respond for a Selection
// that doesn't answer the request as it asks: an unknown query or
// credential, a credential that doesn't answer its query, more than one
// for a query that takes one, a required credential set left
// unanswered, or two alternatives of one set answered (a set takes one
// of its options, OpenID4VP 1.0 §6.4.2).
var ErrInvalidSelection = wallet.ErrInvalidSelection

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
	w       *Wallet
	req     wallet.AuthorizationRequest
	queries []Query
	byID    map[string]StoredCredential

	mu       sync.Mutex
	answered bool
	// declined is the holder's refusal, built once: sent again, as is,
	// when sending it failed in transit.
	declined string
}

// StartPresentation fetches and verifies the OpenID4VP Authorization
// Request requestLink (an openid4vp:// link with client_id and
// request_uri) from a Verifier Config.VerifierTrust accepts, and finds
// the held credentials that can answer it, without sending anything.
// Show the holder Verifier, Queries and CredentialSets, choose a
// Selection (or start from DefaultSelection), Preview it, then Respond
// or Decline.
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
	byCredential := make(map[string]StoredCredential, len(stored))
	for _, c := range stored {
		p.byID[c.ID] = c
		byCredential[c.Credential] = c
		held = append(held, heldCredential(c, nil))
	}
	// Each Credential Query, in the request's order, with every
	// credential that can answer it on its own: the holder, or the
	// application's policy, chooses. One nothing answers has none; none
	// at all isn't an error here: the holder is told, and may decline.
	for _, cq := range req.Query.Credentials {
		q := Query{ID: cq.ID, Multiple: cq.Multiple}
		all := cq
		all.Multiple = true
		if matches, err := wallet.MatchDCQLQuery(ctx, dcql.Query{Credentials: []dcql.CredentialQuery{all}}, held, trustedAuthorities); err == nil {
			for _, h := range matches[cq.ID] {
				q.Credentials = append(q.Credentials, byCredential[h.Credential])
			}
		}
		p.queries = append(p.queries, q)
	}
	return p, nil
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

// Queries returns the request's Credential Queries, in its order, each
// with the held credentials that can answer it. None answerable means
// the wallet can't answer: Decline.
func (p *Presentation) Queries() []Query { return p.queries }

// CredentialSets returns the request's credential_sets; none means
// every query must be answered.
func (p *Presentation) CredentialSets() []CredentialSet {
	out := make([]CredentialSet, 0, len(p.req.Query.CredentialSets))
	for _, cs := range p.req.Query.CredentialSets {
		out = append(out, CredentialSet{Options: cs.Options, Required: cs.IsRequired()})
	}
	return out
}

// DefaultSelection is the Selection the wallet would make itself, for an
// application with no policy of its own, or to start from: the first
// answerable option of each credential set, and each query's first
// credential (all of them when it takes several). It returns
// ErrNoMatchingCredential when the request can't be answered.
func (p *Presentation) DefaultSelection(ctx context.Context) (Selection, error) {
	held := make([]wallet.HeldCredential, 0, len(p.byID))
	byCredential := make(map[string]string, len(p.byID))
	for id, c := range p.byID {
		held = append(held, heldCredential(c, nil))
		byCredential[c.Credential] = id
	}
	matches, err := wallet.DefaultSelection(ctx, p.req.Query, held, trustedAuthorities)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w: %w", ErrNoMatchingCredential, err)
	}
	sel := make(Selection, len(matches))
	for q, hs := range matches {
		for _, h := range hs {
			sel[q] = append(sel[q], byCredential[h.Credential])
		}
	}
	return sel, nil
}

// Preview reports what Respond(ctx, sel) would disclose, without
// signing or sending anything: show it to the holder for consent. It
// returns an error wrapping ErrInvalidSelection for a Selection that
// doesn't answer the request.
func (p *Presentation) Preview(ctx context.Context, sel Selection) ([]Disclosure, error) {
	held, _, err := p.held(ctx, sel, false)
	if err != nil {
		return nil, err
	}
	preview, err := wallet.PreviewSelection(ctx, p.req.Query, held, trustedAuthorities)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	ids := p.idsByCredential()
	out := make([]Disclosure, 0, len(preview))
	for _, c := range preview {
		out = append(out, Disclosure{QueryID: c.QueryID, CredentialID: ids[c.Credential.Credential], Claims: c.Claims})
	}
	return out, nil
}

// Respond presents exactly sel — each query's chosen credentials,
// checked to answer the request (ErrInvalidSelection otherwise) — bound
// to the Verifier's nonce and client_id, in an encrypted direct_post.jwt
// response. Each credential's next unused copy is presented. Holder keys
// sign here, so a KeyStore that requires user presence prompts now. A
// Presentation is answered once.
func (p *Presentation) Respond(ctx context.Context, sel Selection) (Presented, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.answered || p.declined != "" {
		return Presented{}, ErrWrongStep
	}
	held, picked, err := p.held(ctx, sel, true)
	if err != nil {
		return Presented{}, err
	}
	responded, err := wallet.RespondSelection(ctx, p.w.deps.HTTP, p.req, held, trustedAuthorities)
	if err != nil && deliveryUnknown(err) {
		// The Verifier may have it: sending again could present twice,
		// with the same nonce. Its copies count as presented.
		p.answered = true
		p.markPresented(ctx, picked)
		return Presented{}, fmt.Errorf("walletflow: respond: %w: %w", ErrDeliveryUnknown, err)
	}
	if err != nil {
		return Presented{}, fmt.Errorf("walletflow: respond: %w", err)
	}
	p.markPresented(ctx, picked)
	p.answered = true
	presented := Presented{RedirectURI: responded.Reply.RedirectURI}
	for id := range responded.VPToken {
		presented.QueryIDs = append(presented.QueryIDs, id)
	}
	sort.Strings(presented.QueryIDs)
	return presented, nil
}

// Decline tells the Verifier the holder declined (access_denied, in an
// encrypted direct_post.jwt error response). The refusal stands from the
// first call: Respond is refused after it. If sending it failed in
// transit, Decline can be called again to send the same refusal; an
// error the Verifier answered with is returned, and the Presentation is
// answered all the same.
func (p *Presentation) Decline(ctx context.Context) (Presented, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.answered {
		return Presented{}, ErrWrongStep
	}
	if p.declined == "" {
		responseJWE, err := wallet.BuildDirectPostErrorResponse(wallet.BuildDirectPostErrorResponseParams{
			Error: "access_denied", ErrorDescription: "the holder declined", State: p.req.State,
			EncryptionKey: p.req.ResponseEncryptionKey, EncryptionKeyID: p.req.ResponseEncryptionKeyID,
			EncryptionEnc: p.req.ResponseEncryptionEnc,
		})
		if err != nil {
			return Presented{}, fmt.Errorf("walletflow: decline: %w", err)
		}
		p.declined = responseJWE
	}
	reply, err := wallet.SubmitDirectPostResponse(ctx, p.w.deps.HTTP, p.req.ResponseURI, p.declined)
	if err != nil && deliveryUnknown(err) {
		// Not known to have arrived: Decline may send it again.
		return Presented{}, fmt.Errorf("walletflow: decline: %w", err)
	}
	p.answered = true
	if err != nil {
		return Presented{}, fmt.Errorf("walletflow: decline: %w", err)
	}
	return Presented{RedirectURI: reply.RedirectURI}, nil
}

// held is sel as the wallet package presents it: each credential's
// copy to present next, with its holder key when withKeys is set, and
// which copy of each credential it picked. An ID that isn't a stored
// credential is an invalid selection; whether each answers its query is
// the wallet package's to check.
func (p *Presentation) held(ctx context.Context, sel Selection, withKeys bool) (map[string][]wallet.HeldCredential, map[string]int, error) {
	if len(sel) == 0 {
		return nil, nil, fmt.Errorf("walletflow: %w: nothing is selected", ErrInvalidSelection)
	}
	out := make(map[string][]wallet.HeldCredential, len(sel))
	picked := map[string]int{}
	for q, ids := range sel {
		for _, id := range ids {
			c, ok := p.byID[id]
			if !ok {
				return nil, nil, fmt.Errorf("walletflow: %w: no credential %q", ErrInvalidSelection, id)
			}
			i, cp := c.nextCopy()
			picked[id] = i
			var key Key
			if withKeys {
				k, err := p.w.deps.Keys.Key(ctx, cp.HolderKeyID)
				if err != nil {
					return nil, nil, fmt.Errorf("walletflow: credential %q's holder key: %w", id, err)
				}
				key = k
			}
			c.Credential = cp.Credential
			out[q] = append(out[q], heldCredential(c, key))
		}
	}
	return out, picked, nil
}

// markPresented records that the picked copies have been presented, so
// the next presentation uses others. It's best effort: a copy not
// marked is presented again, which a Verifier may link.
func (p *Presentation) markPresented(ctx context.Context, picked map[string]int) {
	ctx = context.WithoutCancel(ctx)
	for id, i := range picked {
		c, err := p.w.deps.Credentials.Get(ctx, id)
		if err != nil {
			continue
		}
		c.Copies = slices.Clone(c.AllCopies())
		if i < len(c.Copies) {
			c.Copies[i].Presented = true
			_ = p.w.deps.Credentials.Put(ctx, c)
		}
	}
}

// idsByCredential maps the text of every copy of every credential to
// its ID.
func (p *Presentation) idsByCredential() map[string]string {
	ids := make(map[string]string, len(p.byID))
	for id, c := range p.byID {
		for _, cp := range c.AllCopies() {
			ids[cp.Credential] = id
		}
	}
	return ids
}
