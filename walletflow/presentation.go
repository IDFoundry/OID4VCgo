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
	// registration is the Verifier's, checked when it started.
	registration Registration

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
	p.registration = p.checkRegistration(w.deps.Clock())
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

// Linkable reports whether presenting the credential id names to this
// Verifier now, under Config.CopyPolicy, would hand it a copy another
// Verifier has seen, so the two could link the holder: every copy has
// been presented elsewhere. False for a credential not held.
func (p *Presentation) Linkable(id string) bool {
	c, ok := p.byID[id]
	if !ok {
		return false
	}
	verifier := VerifierHash(p.req.ClientID)
	_, cp, _ := c.copyFor(p.w.cfg.CopyPolicy, verifier)
	return slices.ContainsFunc(cp.ShownTo, func(h string) bool { return h != verifier })
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
	held, err := p.held(ctx, sel)
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
	reserved, err := p.reserve(ctx, sel)
	if err != nil {
		return Presented{}, err
	}
	held, err := p.withKeys(ctx, reserved)
	if err != nil {
		p.release(ctx, reserved)
		return Presented{}, err
	}
	responded, err := wallet.RespondSelection(ctx, p.w.deps.HTTP, p.req, held, trustedAuthorities)
	if err != nil && deliveryUnknown(err) {
		// The Verifier may have it: sending again could present twice,
		// with the same nonce. Its copies stay presented.
		p.answered = true
		return Presented{}, fmt.Errorf("walletflow: respond: %w: %w", ErrDeliveryUnknown, err)
	}
	if err != nil {
		// Not sent: the copies weren't seen.
		p.release(ctx, reserved)
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

// checkShape refuses a selection that names nothing, a query with no
// credential, or one credential twice for the same query.
func checkShape(sel Selection) error {
	if len(sel) == 0 {
		return fmt.Errorf("walletflow: %w: nothing is selected", ErrInvalidSelection)
	}
	for q, ids := range sel {
		if len(ids) == 0 {
			return fmt.Errorf("walletflow: %w: query %q has no credential selected", ErrInvalidSelection, q)
		}
		for i, id := range ids {
			if slices.Contains(ids[:i], id) {
				return fmt.Errorf("walletflow: %w: credential %q is selected twice for query %q", ErrInvalidSelection, id, q)
			}
		}
	}
	return nil
}

// held is sel as the wallet package previews it: each credential's next
// copy, from the credentials as they were when the request arrived,
// without keys. An ID that isn't a stored credential is an invalid
// selection; whether each answers its query is the wallet package's to
// check.
func (p *Presentation) held(_ context.Context, sel Selection) (map[string][]wallet.HeldCredential, error) {
	if err := checkShape(sel); err != nil {
		return nil, err
	}
	out := make(map[string][]wallet.HeldCredential, len(sel))
	for q, ids := range sel {
		for _, id := range ids {
			c, ok := p.byID[id]
			if !ok {
				return nil, fmt.Errorf("walletflow: %w: no credential %q", ErrInvalidSelection, id)
			}
			_, cp := c.nextCopy()
			c.Credential = cp.Credential
			out[q] = append(out[q], heldCredential(c, nil))
		}
	}
	return out, nil
}

// reservedCopy is a copy Respond is presenting: credential id's copy
// index, marked presented in the store.
type reservedCopy struct {
	query string
	c     StoredCredential // with Credential the copy's
	id    string
	index int
	keyID string
	// reused is a copy this Verifier had seen already (CopyPerVerifier):
	// reserving it changed nothing, so there's nothing to release.
	reused bool
	// wasPresented and wasShown are what the copy recorded before it was
	// reserved, for release.
	wasPresented, wasShown bool
}

// reserve picks each selected credential's copy from the store, as it is
// now, by Config.CopyPolicy, and marks it presented to this Verifier
// there before anything is sent, so a presentation answered at the same
// time picks another.
// Credentials deleted since the request arrived are an invalid
// selection.
func (p *Presentation) reserve(ctx context.Context, sel Selection) ([]reservedCopy, error) {
	if err := checkShape(sel); err != nil {
		return nil, err
	}
	w := p.w
	verifier := VerifierHash(p.req.ClientID)
	w.credMu.Lock()
	defer w.credMu.Unlock()
	current := map[string]StoredCredential{}
	var out []reservedCopy
	for _, q := range sortedQueries(sel) {
		for _, id := range sel[q] {
			c, ok := current[id]
			if !ok {
				var err error
				if c, err = w.deps.Credentials.Get(ctx, id); err != nil {
					if errors.Is(err, ErrNotFound) {
						return nil, fmt.Errorf("walletflow: %w: no credential %q", ErrInvalidSelection, id)
					}
					return nil, fmt.Errorf("walletflow: credential %q: %w", id, err)
				}
				c.Copies = slices.Clone(c.AllCopies())
			}
			i, cp, reused := c.copyFor(w.cfg.CopyPolicy, verifier)
			r := reservedCopy{query: q, id: id, index: i, keyID: cp.HolderKeyID, reused: reused,
				wasPresented: cp.Presented, wasShown: slices.Contains(cp.ShownTo, verifier)}
			c.Copies[i].Presented = true
			if !r.wasShown {
				c.Copies[i].ShownTo = append(slices.Clone(cp.ShownTo), verifier)
			}
			current[id] = c
			r.c = c
			r.c.Credential = cp.Credential
			out = append(out, r)
		}
	}
	for id, c := range current {
		if err := w.deps.Credentials.Put(ctx, c); err != nil {
			return nil, fmt.Errorf("walletflow: store credential %q: %w", id, err)
		}
	}
	return out, nil
}

// release undoes what reserve recorded for a response that wasn't
// sent, unless the credential has changed since. It's best effort: a
// copy left marked is one fewer to use, never one presented twice.
func (p *Presentation) release(ctx context.Context, reserved []reservedCopy) {
	ctx = context.WithoutCancel(ctx)
	w := p.w
	verifier := VerifierHash(p.req.ClientID)
	w.credMu.Lock()
	defer w.credMu.Unlock()
	changed := map[string]StoredCredential{}
	for _, r := range reserved {
		if r.reused {
			continue
		}
		c, ok := changed[r.id]
		if !ok {
			var err error
			if c, err = w.deps.Credentials.Get(ctx, r.id); err != nil {
				continue
			}
			c.Copies = slices.Clone(c.AllCopies())
		}
		if r.index < len(c.Copies) && c.Copies[r.index].HolderKeyID == r.keyID {
			cp := &c.Copies[r.index]
			cp.Presented = r.wasPresented
			if !r.wasShown {
				cp.ShownTo = slices.DeleteFunc(slices.Clone(cp.ShownTo), func(h string) bool { return h == verifier })
			}
			changed[r.id] = c
		}
	}
	for _, c := range changed {
		_ = w.deps.Credentials.Put(ctx, c)
	}
}

// withKeys is reserved as the wallet package presents it, each copy with
// its holder key.
func (p *Presentation) withKeys(ctx context.Context, reserved []reservedCopy) (map[string][]wallet.HeldCredential, error) {
	out := map[string][]wallet.HeldCredential{}
	for _, r := range reserved {
		k, err := p.w.deps.Keys.Key(ctx, r.keyID)
		if err != nil {
			return nil, fmt.Errorf("walletflow: credential %q's holder key: %w", r.id, err)
		}
		out[r.query] = append(out[r.query], heldCredential(r.c, k))
	}
	return out, nil
}

func sortedQueries(sel Selection) []string {
	qs := make([]string, 0, len(sel))
	for q := range sel {
		qs = append(qs, q)
	}
	sort.Strings(qs)
	return qs
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
