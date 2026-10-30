package walletflow

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// ResponseURI is where the answer would be sent; none for a DC API
	// request, whose answer goes back through the platform.
	ResponseURI string
	// Origin, for a DC API request, is the calling page's or app's
	// origin as the platform reported it: what identifies the Verifier
	// of an unsigned request, which has no ClientID or Certificate, and
	// with ClientID a signed one's.
	Origin string
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
	// SD-JWT VC, [namespace, element] for an mdoc.
	Claims []dcql.Path
	// AlwaysDisclosed are the SD-JWT VC claims disclosed beyond Claims:
	// those the issuer didn't make selectively disclosable, and what
	// shares a Disclosure with a claim — the plaintext members of a
	// disclosed object or array element a claim sits within, the other
	// elements of an array disclosed as one
	// (wallet.PreviewedCredential.AlwaysDisclosed). Show them with
	// Claims.
	AlwaysDisclosed []dcql.Path
	// Retained are the claims the Verifier says it intends to keep: an
	// mdoc's elements its query marks intent_to_retain (OpenID4VP
	// Appendix B.2.4). Show them to the holder with Claims, as ISO/IEC
	// 18013-5 has a wallet show the reader's intent to retain.
	Retained []dcql.Path
}

// Presented is what Respond or Decline sent.
type Presented struct {
	// QueryIDs are the Credential Queries answered; none for Decline.
	QueryIDs []string
	// Linkable are the credentials presented with a copy another
	// Verifier had already seen (Presentation.Linkable said so), by ID:
	// the two Verifiers could link these presentations.
	Linkable []string
	// RedirectURI, when the Verifier returned one, is where the wallet
	// must now send the browser (OpenID4VP 1.0 §8.2).
	RedirectURI string
	// DCAPIResponse, for a DC API request, is the response's data to
	// hand back to the platform: {"response": <the encrypted response>}
	// (OpenID4VP 1.0 Appendix A.4). Nothing was sent: the platform
	// delivers it.
	DCAPIResponse []byte
}

// Presentation answers one Authorization Request.
type Presentation struct {
	w       *Wallet
	req     wallet.AuthorizationRequest
	queries []Query
	byID    map[string]StoredCredential
	order   []string // byID's IDs, in the CredentialStore's order
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
// the held credentials that can answer it, without sending anything
// but the fetch: a GET of request_uri, or for a link with
// request_uri_method=post a POST of a fresh wallet_nonce and the
// wallet's metadata (OpenID4VP 1.0 §5.10).
// Show the holder Verifier, Queries and CredentialSets, choose a
// Selection (or start from DefaultSelection), Preview it, then Respond
// or Decline.
func (w *Wallet) StartPresentation(ctx context.Context, requestLink string) (*Presentation, error) {
	if w.cfg.VerifierTrust == nil {
		return nil, fmt.Errorf("walletflow: Config.VerifierTrust is required to present: %w", ErrNotConfigured)
	}
	link, err := wallet.ParseAuthorizationRequestLink(requestLink)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	// Checks the signing certificate chains to a trusted CA, the Request
	// Object's signature, and that client_id is bound to that
	// certificate; after a POST, that the Request Object carries the
	// wallet_nonce sent.
	req, err := w.fetchAuthorizationRequest(ctx, link)
	var rejected *wallet.RequestRejectedError
	if errors.As(err, &rejected) {
		return nil, w.refuse(ctx, rejected)
	}
	if err != nil {
		return nil, fmt.Errorf("walletflow: presentation request: %w", err)
	}
	return w.newPresentation(ctx, req)
}

// fetchAuthorizationRequest fetches link's request_uri: by GET, unless
// the link says request_uri_method=post (OpenID4VP 1.0 §5.10), when it
// POSTs a fresh wallet_nonce and walletMetadata, and the Request Object
// must carry that wallet_nonce back, so one fetched for another request
// can't be replayed.
func (w *Wallet) fetchAuthorizationRequest(ctx context.Context, link wallet.AuthorizationRequestLink) (wallet.AuthorizationRequest, error) {
	if link.RequestURIMethod != wallet.RequestURIMethodPost {
		return w.core.FetchAuthorizationRequest(ctx, link.RequestURI, link.ClientID)
	}
	var nonce [32]byte
	if _, err := io.ReadFull(w.deps.Random, nonce[:]); err != nil {
		return wallet.AuthorizationRequest{}, fmt.Errorf("wallet_nonce: %w", err)
	}
	return w.core.FetchAuthorizationRequestPost(ctx, link.RequestURI, link.ClientID, base64.RawURLEncoding.EncodeToString(nonce[:]), walletMetadata)
}

// walletMetadata is the wallet metadata (OpenID4VP 1.0 §10) sent with
// a request_uri POST: what a presentation can be, as the wallet package
// makes it. An SD-JWT VC's issuer signature is one VerifyIssuedCredential
// accepted on receipt (ES256 or EdDSA), its Key Binding JWT ES256; an
// mdoc's IssuerAuth likewise (COSE -7 or -8), its DeviceSignature ES256
// (-7). Requests are accepted only from an x509_hash Client Identifier.
// It asks for no encrypted Request Object, which the wallet can't
// decrypt: jwks, the only wallet metadata that does (§5.10), isn't
// sent. The authorization_encryption_* parameters, about the
// Authorization Response, aren't either: the response's encryption
// follows the Verifier's client_metadata.
var walletMetadata = json.RawMessage(`{"vp_formats_supported":{` +
	`"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256"]},` +
	`"mso_mdoc":{"issuerauth_alg_values":[-7,-8],"deviceauth_alg_values":[-7]}},` +
	`"client_id_prefixes_supported":["x509_hash"]}`)

// refuse tells the Verifier its authentic request r is refused, by an
// error response to its response_uri (OpenID4VP §8.5), and returns
// the *RequestRefusedError. A request with nowhere to send it, or no
// key to encrypt it to, is refused locally.
func (w *Wallet) refuse(ctx context.Context, r *wallet.RequestRejectedError) error {
	refused := &RequestRefusedError{Code: r.Code, Description: r.Description}
	if r.ResponseURI == "" || r.ResponseEncryptionKey == nil {
		refused.sendErr = errors.New("the request names no response_uri or encryption key")
		return refused
	}
	responseJWE, err := wallet.BuildDirectPostErrorResponse(wallet.BuildDirectPostErrorResponseParams{
		Error: r.Code, ErrorDescription: r.Description, State: r.State,
		EncryptionKey: r.ResponseEncryptionKey, EncryptionKeyID: r.ResponseEncryptionKeyID, EncryptionEnc: r.ResponseEncryptionEnc,
	})
	if err != nil {
		refused.sendErr = err
		return refused
	}
	reply, err := wallet.SubmitDirectPostResponse(ctx, w.deps.HTTP, r.ResponseURI, responseJWE)
	if err != nil {
		refused.sendErr = err
		return refused
	}
	refused.RedirectURI = reply.RedirectURI
	return refused
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
		p.order = append(p.order, c.ID)
		h := heldCredential(c, nil)
		// Only what the Verifier says it can verify is offered
		// (vp_formats_supported, OpenID4VP 1.0 §11.1).
		if !req.VPFormats.Accepts(h) {
			continue
		}
		byCredential[c.Credential] = c
		held = append(held, h)
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
	p.registration = p.checkRegistration(ctx, w.deps.Clock())
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
	v := Verifier{ClientID: p.req.ClientID, Certificate: p.req.VerifierCertificate, ResponseURI: p.req.ResponseURI, Origin: p.req.Origin}
	if p.req.VerifierCertificate != nil {
		// The certificate's, which its CA vetted, shown as an issuer's
		// display text is (displayText).
		v.Name = displayText(p.req.VerifierCertificate.Subject.CommonName, maxDisplayName)
	}
	return v
}

// Linkable reports whether presenting the credential id names to this
// Verifier now, under Config.CopyPolicy, would hand it a copy another
// Verifier has seen, so the two could link the holder: every copy has
// been presented elsewhere. False for a credential not held.
func (p *Presentation) Linkable(id string) bool {
	c, ok := p.byID[id]
	return ok && p.w.linkable(c, p.verifier())
}

// linkable reports whether presenting c to the Verifier whose
// VerifierHash is verifier, under Config.CopyPolicy, would use a copy
// another Verifier has seen, or one correlated with it
// (StoredCredential.CopiesCorrelated).
func (w *Wallet) linkable(c StoredCredential, verifier string) bool {
	_, cp, _ := c.copyFor(w.cfg.CopyPolicy, verifier, w.deps.Clock())
	return c.linkableTo(cp, verifier)
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
// credential, as Queries lists them, even when it takes several: the
// holder adds the others. It returns ErrNoMatchingCredential when the
// request can't be answered.
func (p *Presentation) DefaultSelection(ctx context.Context) (Selection, error) {
	held := make([]wallet.HeldCredential, 0, len(p.byID))
	byCredential := make(map[string]string, len(p.byID))
	for _, id := range p.order {
		c := p.byID[id]
		h := heldCredential(c, nil)
		// As the queries offer: what the Verifier can take.
		if !p.req.VPFormats.Accepts(h) {
			continue
		}
		held = append(held, h)
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
		out = append(out, Disclosure{QueryID: c.QueryID, CredentialID: ids[c.Credential.Credential], Claims: c.Claims, AlwaysDisclosed: c.AlwaysDisclosed, Retained: c.Retained})
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
	if p.req.Origin != "" {
		presented, err := p.answerDCAPI(ctx, held)
		if err != nil {
			p.release(ctx, reserved)
			return Presented{}, err
		}
		// Handed to the platform from here: its copies count as seen.
		p.answered = true
		presented.Linkable = linkableOf(reserved)
		return presented, nil
	}
	responded, err := wallet.RespondSelection(ctx, p.w.deps.HTTP, p.req, held, trustedAuthorities)
	if err != nil && deliveryUnknown(err) {
		// The Verifier may have it: sending again could present twice,
		// with the same nonce. Its copies stay presented.
		p.answered = true
		return Presented{}, fmt.Errorf("walletflow: respond: %w: %w", ErrDeliveryUnknown, err)
	}
	if errors.Is(err, wallet.ErrResponseDelivered) {
		// The Verifier replied, so it has the presentation, whatever it
		// replied: its copies stay presented, and it isn't sent again.
		p.answered = true
		return Presented{}, fmt.Errorf("walletflow: respond: %w", err)
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
	presented.Linkable = linkableOf(reserved)
	return presented, nil
}

// linkableOf is the IDs of reserved's credentials presented with a copy
// another Verifier had seen, sorted.
func linkableOf(reserved []reservedCopy) []string {
	var out []string
	for _, r := range reserved {
		if r.linkable && !slices.Contains(out, r.id) {
			out = append(out, r.id)
		}
	}
	sort.Strings(out)
	return out
}

// Decline tells the Verifier the holder declined (access_denied, in an
// encrypted direct_post.jwt error response; for a DC API request,
// OpenID4VP Appendix A.4's {"error": "access_denied"} in
// Presented.DCAPIResponse). The refusal stands from the
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
	if p.req.Origin != "" {
		return p.declineDCAPI()
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

// checkSelectable is checkShape, and refuses a credential the Verifier
// can't take: one its vp_formats_supported doesn't accept, which the
// queries didn't offer.
func (p *Presentation) checkSelectable(sel Selection) error {
	if err := checkShape(sel); err != nil {
		return err
	}
	for q, ids := range sel {
		for _, id := range ids {
			if c, ok := p.byID[id]; ok && !p.req.VPFormats.Accepts(heldCredential(c, nil)) {
				return fmt.Errorf("walletflow: %w: query %q: the Verifier doesn't accept credential %q's format or algorithms", ErrInvalidSelection, q, id)
			}
		}
	}
	return nil
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
	if err := p.checkSelectable(sel); err != nil {
		return nil, err
	}
	out := make(map[string][]wallet.HeldCredential, len(sel))
	for q, ids := range sel {
		for _, id := range ids {
			c, ok := p.byID[id]
			if !ok {
				return nil, fmt.Errorf("walletflow: %w: no credential %q", ErrInvalidSelection, id)
			}
			// The copy Respond would present, under the copy policy: under
			// CopyPerVerifier a returning Verifier gets the copy it saw,
			// whose claims Preview must then show.
			_, cp, _ := c.copyFor(p.w.cfg.CopyPolicy, p.verifier(), p.w.deps.Clock())
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
	// linkable is a copy another Verifier has seen.
	linkable bool
	// reservation is the presentation's mark on the copy
	// (CredentialCopy.Reservation).
	reservation string
}

// reserve picks each selected credential's copy from the store, as it is
// now, by Config.CopyPolicy, and marks it presented to this Verifier
// there before anything is sent, so a presentation answered at the same
// time — by this Wallet or another sharing the store — picks another.
// Credentials deleted since the request arrived are an invalid
// selection.
func (p *Presentation) reserve(ctx context.Context, sel Selection) ([]reservedCopy, error) {
	if err := p.checkSelectable(sel); err != nil {
		return nil, err
	}
	return p.w.reserve(ctx, sel, p.verifier(), p.Linkable, p.byID)
}

// reserve is Presentation.reserve for the Verifier whose VerifierHash is
// verifier; linkable is what the holder was told about each credential
// (Presentation.Linkable), which a reserved copy must agree with, and
// shown the credentials as the holder was shown them, which the stored
// ones must still be. Each credential's copy is reserved in one
// CredentialStore.Update; when one can't be, those already reserved are
// released.
func (w *Wallet) reserve(ctx context.Context, sel Selection, verifier string, linkable func(id string) bool, shown map[string]StoredCredential) ([]reservedCopy, error) {
	mark, err := randomID(w.deps.Random)
	if err != nil {
		return nil, err
	}
	// One credential selected for several queries is presented with one
	// copy throughout the response, as Preview showed: two copies would
	// give the Verifier two holder keys and status entries of one
	// credential, burning a copy and linking the two to one holder.
	chosen := map[string]reservedCopy{}
	var out, done []reservedCopy
	for _, q := range sortedQueries(sel) {
		for _, id := range sel[q] {
			if prev, ok := chosen[id]; ok {
				again := prev
				// Released with the first: nothing to undo for this one.
				again.query, again.reused = q, true
				out = append(out, again)
				continue
			}
			was, wasShown := shown[id]
			r, err := w.reserveOne(ctx, reserveRequest{id: id, query: q, mark: mark, verifier: verifier, toldLinkable: linkable(id)}, was, wasShown)
			if err != nil {
				w.release(ctx, done, verifier)
				return nil, err
			}
			chosen[id] = r
			done = append(done, r)
			out = append(out, r)
		}
	}
	return out, nil
}

// reserveRequest is what reserveOne reserves: credential id's copy to
// answer query with, for verifier, marked mark (CredentialCopy.
// Reservation); toldLinkable is whether the holder was told presenting
// it would be linkable.
type reserveRequest struct {
	id, query, mark, verifier string
	toldLinkable              bool
}

// reserveOne reserves req's copy in one CredentialStore.Update:
// ErrCredentialChanged when, shown to the holder as was, it's been
// refreshed since, as its claims, or which of them are always disclosed,
// may not be what the holder saw; an invalid selection when it's been
// deleted.
func (w *Wallet) reserveOne(ctx context.Context, req reserveRequest, was StoredCredential, shown bool) (reservedCopy, error) {
	var r reservedCopy
	var refused error
	err := w.deps.Credentials.Update(ctx, req.id, func(c *StoredCredential) error {
		if shown && !was.ReceivedAt.Equal(c.ReceivedAt) {
			refused = fmt.Errorf("walletflow: credential %q: %w", req.id, ErrCredentialChanged)
			return refused
		}
		var err error
		r, err = w.reserveCopy(c, req)
		refused = err
		return err
	})
	switch {
	case err == nil:
		return r, nil
	case refused != nil && errors.Is(err, refused):
		return reservedCopy{}, err
	case errors.Is(err, ErrNotFound):
		return reservedCopy{}, fmt.Errorf("walletflow: %w: no credential %q", ErrInvalidSelection, req.id)
	}
	return reservedCopy{}, fmt.Errorf("walletflow: store credential %q: %w", req.id, err)
}

// reserveCopy picks c's copy to answer req.query with, by
// Config.CopyPolicy, and marks it in c presented to req.verifier, with
// req.mark its latest reservation.
func (w *Wallet) reserveCopy(c *StoredCredential, req reserveRequest) (reservedCopy, error) {
	c.Copies = slices.Clone(c.AllCopies())
	i, cp, reused := c.copyFor(w.cfg.CopyPolicy, req.verifier, w.deps.Clock())
	linkable := c.linkableTo(cp, req.verifier)
	if linkable && !req.toldLinkable {
		// What the holder saw said otherwise: don't send it.
		return reservedCopy{}, fmt.Errorf("walletflow: credential %q: %w", req.id, ErrLinkable)
	}
	r := reservedCopy{query: req.query, id: req.id, index: i, keyID: cp.HolderKeyID, reused: reused,
		wasPresented: cp.Presented, wasShown: slices.Contains(cp.ShownTo, req.verifier), linkable: linkable, reservation: req.mark}
	// Marked even when reused: an earlier presentation that reserved it
	// for this Verifier, and isn't sent, mustn't undo what this one sends.
	c.Copies[i].Reservation = req.mark
	c.Copies[i].Presented = true
	if !r.wasShown {
		c.Copies[i].ShownTo = append(slices.Clone(cp.ShownTo), req.verifier)
	}
	r.c = *c
	r.c.Credential = cp.Credential
	return r, nil
}

// release undoes what reserve recorded for a response that wasn't
// sent, unless the credential has changed since or another presentation
// — in this Wallet or another sharing the store — has reserved the copy
// since (CredentialCopy.Reservation): what that one recorded, which
// release's snapshot would undo, stands whether or not it was sent. It's
// best effort: a copy left marked is one fewer to use, never one
// presented twice.
func (p *Presentation) release(ctx context.Context, reserved []reservedCopy) {
	p.w.release(ctx, reserved, p.verifier())
}

// release is Presentation.release for the Verifier whose VerifierHash
// is verifier.
func (w *Wallet) release(ctx context.Context, reserved []reservedCopy, verifier string) {
	ctx = context.WithoutCancel(ctx)
	for _, r := range reserved {
		if r.reused {
			continue
		}
		// One credential's copy per reservation (reserve): one Update each.
		_ = w.deps.Credentials.Update(ctx, r.id, func(c *StoredCredential) error {
			if r.index >= len(c.Copies) {
				return errUnchanged
			}
			cp := &c.Copies[r.index]
			if cp.HolderKeyID != r.keyID || cp.Reservation != r.reservation {
				return errUnchanged
			}
			cp.Presented, cp.Reservation = r.wasPresented, ""
			if !r.wasShown {
				cp.ShownTo = slices.DeleteFunc(slices.Clone(cp.ShownTo), func(h string) bool { return h == verifier })
			}
			return nil
		})
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
