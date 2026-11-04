package walletflow

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
)

// MdocRequest is one document an org-iso-mdoc request asks for.
type MdocRequest struct {
	// DocType is the requested document type.
	DocType string
	// Elements are the requested data elements, by namespace then
	// identifier.
	Elements []MdocElement
	// Credentials are the held mdocs of DocType; none when nothing held
	// can answer.
	Credentials []StoredCredential
}

// MdocElement is one requested data element.
type MdocElement struct {
	// Namespace and Identifier name the element.
	Namespace, Identifier string
	// Retain is whether the reader says it will keep the value.
	Retain bool
}

// MdocPresentation answers one org-iso-mdoc request: an mdoc asked for
// over the Digital Credentials API (ISO/IEC TS 18013-7 Annex C), as iOS
// hands one to a document provider.
type MdocPresentation struct {
	w        *Wallet
	in       mdocdcapi.Incoming
	reader   *x509.Certificate
	requests []MdocRequest
	byID     map[string]StoredCredential

	mu       sync.Mutex
	answered bool
}

// StartMdocPresentation parses data, an org-iso-mdoc request, from the
// page at origin — both as the platform reports them — checks who
// signed it against Config.MdocReaderRoots and MdocReaderLeafPolicy,
// and finds the held mdocs that can answer it, without answering. With
// Config.RequireTrustedMdocReader, a request no recognized reader
// signed is refused with an error wrapping ErrUntrustedVerifier. Show the holder Origin,
// Reader and Requests, then Respond; to decline, the app cancels the
// platform's request: nothing is sent to the reader.
func (w *Wallet) StartMdocPresentation(ctx context.Context, data []byte, origin string) (*MdocPresentation, error) {
	in, err := mdocdcapi.ParseRequest(data, origin)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w: %w", ErrMalformedRequest, err)
	}
	p := &MdocPresentation{w: w, in: in, byID: map[string]StoredCredential{}}
	if w.cfg.MdocReaderRoots != nil {
		reader, err := in.VerifyReaderTrust(mdocdcapi.ReaderTrust{
			Roots: w.cfg.MdocReaderRoots, LeafPolicy: w.cfg.MdocReaderLeafPolicy, Revocation: w.cfg.MdocReaderRevocation, Now: w.deps.Clock(),
		})
		if err != nil && w.cfg.RequireTrustedMdocReader {
			return nil, fmt.Errorf("walletflow: %w: %w", ErrUntrustedVerifier, err)
		}
		// Otherwise an unrecognized reader isn't refused: the holder sees
		// the origin instead.
		p.reader = reader
	}
	stored, err := w.deps.Credentials.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("walletflow: list credentials: %w", err)
	}
	for _, d := range in.Documents {
		r := MdocRequest{DocType: d.DocType, Elements: mdocElements(d)}
		for _, c := range stored {
			if c.Format == mdoc.CredentialFormat && c.DocType == d.DocType {
				r.Credentials = append(r.Credentials, c)
				p.byID[c.ID] = c
			}
		}
		p.requests = append(p.requests, r)
	}
	return p, nil
}

// mdocElements lists d's elements, sorted.
func mdocElements(d mdocdcapi.RequestedDocument) []MdocElement {
	var out []MdocElement
	for ns, els := range d.Elements {
		for el, retain := range els {
			out = append(out, MdocElement{Namespace: ns, Identifier: el, Retain: retain})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Identifier < out[j].Identifier
	})
	return out
}

// Origin is the requesting page's origin, which the platform reported.
func (p *MdocPresentation) Origin() string { return p.in.Origin }

// Reader is the certificate of the reader that signed the request, when
// it chains to Config.MdocReaderRoots; nil otherwise, when all the
// holder can be shown is Origin.
func (p *MdocPresentation) Reader() *x509.Certificate { return p.reader }

// Requests are the requested documents, in the request's order.
func (p *MdocPresentation) Requests() []MdocRequest { return p.requests }

// Linkable reports whether presenting the credential id names to this
// origin now would hand it a copy another Verifier has seen, as
// Presentation.Linkable does.
func (p *MdocPresentation) Linkable(id string) bool {
	c, ok := p.byID[id]
	return ok && p.w.linkable(c, p.verifier())
}

// MdocLinkable reports whether presenting c to the page at origin over
// the Digital Credentials API now would use a copy another Verifier has
// seen, as MdocPresentation.Linkable does: for a consent screen shown
// before the request itself is available — iOS releases it to a
// document provider only once the holder agrees.
func (w *Wallet) MdocLinkable(c StoredCredential, origin string) bool {
	return w.linkable(c, originVerifier(origin))
}

// verifier identifies the origin among the Verifiers credential copies
// were shown to.
func (p *MdocPresentation) verifier() string { return originVerifier(p.in.Origin) }

// originVerifier is the VerifierHash a page at origin is known by, as
// an OpenID4VP Verifier without a client_id of its own is known over
// the Digital Credentials API ("origin:" prefix, OpenID4VP 1.0
// Appendix A.2).
func originVerifier(origin string) string {
	return VerifierHash("origin:" + origin)
}

// MdocPresented is Respond's answer.
type MdocPresented struct {
	// EncryptedResponse is the CBOR EncryptedResponse to return to the
	// platform: on iOS, ISO18013MobileDocumentResponse's responseData.
	EncryptedResponse []byte
	// Linkable is whether a copy presented had been seen by another
	// Verifier (Linkable said so): for several documents, whether any
	// was.
	Linkable bool
	// LinkableCredentials are the credentials presented with such a
	// copy, by ID, in the order of the documents they answer.
	LinkableCredentials []string
}

// MdocAnswer is one document request an mdoc presentation answers:
// request number Request, with the held mdoc CredentialID, disclosing
// exactly Elements, each a [namespace, identifier] the request asked
// for.
type MdocAnswer struct {
	Request      int
	CredentialID string
	Elements     [][2]string
}

// Respond presents the held mdoc credentialID for request number
// request, disclosing exactly elements — each a [namespace, identifier]
// the request asked for (ErrInvalidSelection otherwise) — with the
// credential's next unused copy, its holder key signing over the
// session transcript. A KeyStore that requires user presence prompts
// now. An MdocPresentation is answered once. It is RespondDocuments
// with one answer.
func (p *MdocPresentation) Respond(ctx context.Context, request int, credentialID string, elements [][2]string) (MdocPresented, error) {
	return p.RespondDocuments(ctx, []MdocAnswer{{Request: request, CredentialID: credentialID, Elements: elements}})
}

// RespondDocuments presents several of the request's documents in one
// EncryptedResponse, each answer as Respond presents one, in the
// request's order, each signed by its own holder key. A document the
// holder doesn't answer is left out. It refuses (ErrInvalidSelection)
// no answers, a request answered twice, a credential answering two
// requests, and answers to two requests of one document type (a
// Document names only its type), as Respond refuses each answer. Every
// copy is reserved before any key signs; each KeyStore that requires user presence
// prompts in turn, and if one fails or the holder cancels, nothing is
// returned and every copy is released.
func (p *MdocPresentation) RespondDocuments(ctx context.Context, answers []MdocAnswer) (MdocPresented, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.answered {
		return MdocPresented{}, ErrWrongStep
	}
	ordered, err := orderAnswers(answers, func(i int) string { return p.requests[i].DocType }, func(a MdocAnswer) error { return p.checkSelection(a.Request, a.CredentialID, a.Elements) })
	if err != nil {
		return MdocPresented{}, err
	}
	verifier := p.verifier()
	reserved, err := p.w.reserveAnswers(ctx, ordered, verifier, p.Linkable, p.byID)
	if err != nil {
		return MdocPresented{}, err
	}
	encrypted, err := p.respond(ctx, ordered, reserved)
	if err != nil {
		// Nothing left the wallet: the copies weren't seen.
		p.w.release(ctx, reserved, verifier)
		return MdocPresented{}, err
	}
	p.answered = true
	linkable := linkableCredentials(reserved)
	return MdocPresented{EncryptedResponse: encrypted, Linkable: len(linkable) > 0, LinkableCredentials: linkable}, nil
}

// orderAnswers checks answers — each with check, then that no request
// is answered twice, no credential answers two, and no two answer
// requests of one document type (docType gives a checked request's) —
// and returns them in the request's order.
func orderAnswers(answers []MdocAnswer, docType func(request int) string, check func(MdocAnswer) error) ([]MdocAnswer, error) {
	if len(answers) == 0 {
		return nil, fmt.Errorf("walletflow: %w: no document to answer", ErrInvalidSelection)
	}
	requests, credentials, types := map[int]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range answers {
		if err := check(a); err != nil {
			return nil, err
		}
		if requests[a.Request] {
			return nil, fmt.Errorf("walletflow: %w: document request %d answered twice", ErrInvalidSelection, a.Request)
		}
		// One mdoc twice would show the reader the same holder key and
		// status entry in two documents, telling it nothing new.
		if credentials[a.CredentialID] {
			return nil, fmt.Errorf("walletflow: %w: credential %q answers two document requests", ErrInvalidSelection, a.CredentialID)
		}
		// A response's Document names only its docType, nothing ties it
		// to a DocRequest: a reader couldn't tell which of two requests of
		// one type each document answers, and this repository's readers
		// refuse a response with two documents of one type.
		dt := docType(a.Request)
		if types[dt] {
			return nil, fmt.Errorf("walletflow: %w: two document requests of type %q answered; answer one", ErrInvalidSelection, dt)
		}
		requests[a.Request], credentials[a.CredentialID], types[dt] = true, true, true
	}
	out := slices.Clone(answers)
	slices.SortStableFunc(out, func(a, b MdocAnswer) int { return a.Request - b.Request })
	return out, nil
}

// reserveAnswers reserves a copy of each answer's credential, as
// reserve does, returning them in answers' order.
func (w *Wallet) reserveAnswers(ctx context.Context, answers []MdocAnswer, verifier string, linkable func(id string) bool, shown map[string]StoredCredential) ([]reservedCopy, error) {
	sel := Selection{}
	for i, a := range answers {
		sel[strconv.Itoa(i)] = []string{a.CredentialID}
	}
	reserved, err := w.reserve(ctx, sel, verifier, linkable, shown)
	if err != nil {
		return nil, err
	}
	out := make([]reservedCopy, len(answers))
	for _, r := range reserved {
		i, _ := strconv.Atoi(r.query)
		out[i] = r
	}
	return out, nil
}

// linkableCredentials are the reserved copies' credentials another
// Verifier has seen, by ID, in order; nil when none.
func linkableCredentials(reserved []reservedCopy) []string {
	var out []string
	for _, r := range reserved {
		if r.linkable {
			out = append(out, r.id)
		}
	}
	return out
}

// heldMdoc is the reserved copy's mdoc and its holder key.
func (w *Wallet) heldMdoc(ctx context.Context, r reservedCopy) (mdoc.IssuerSigned, Key, error) {
	raw, err := base64.RawURLEncoding.DecodeString(r.c.Credential)
	if err != nil {
		return mdoc.IssuerSigned{}, nil, fmt.Errorf("walletflow: credential %q: %w", r.id, err)
	}
	issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return mdoc.IssuerSigned{}, nil, fmt.Errorf("walletflow: credential %q: %w", r.id, err)
	}
	k, err := w.deps.Keys.Key(ctx, r.keyID)
	if err != nil {
		return mdoc.IssuerSigned{}, nil, fmt.Errorf("walletflow: credential %q's holder key: %w", r.id, err)
	}
	return issuerSigned, k, nil
}

// checkSelection refuses a request, credential or elements Respond
// can't present.
func (p *MdocPresentation) checkSelection(request int, credentialID string, elements [][2]string) error {
	if request < 0 || request >= len(p.requests) {
		return fmt.Errorf("walletflow: %w: no document request %d", ErrInvalidSelection, request)
	}
	if c, ok := p.byID[credentialID]; !ok || c.DocType != p.requests[request].DocType {
		return fmt.Errorf("walletflow: %w: credential %q doesn't answer document request %d", ErrInvalidSelection, credentialID, request)
	}
	if len(elements) == 0 {
		return fmt.Errorf("walletflow: %w: no element to disclose", ErrInvalidSelection)
	}
	for _, e := range elements {
		if !p.in.Documents[request].Requested(e[0], e[1]) {
			return fmt.Errorf("walletflow: %w: %s/%s wasn't requested", ErrInvalidSelection, e[0], e[1])
		}
	}
	return nil
}

// respond builds the EncryptedResponse answering answers with the
// copies reserved for them.
func (p *MdocPresentation) respond(ctx context.Context, answers []MdocAnswer, reserved []reservedCopy) ([]byte, error) {
	out := make([]mdocdcapi.Answer, 0, len(answers))
	for i, a := range answers {
		issuerSigned, k, err := p.w.heldMdoc(ctx, reserved[i])
		if err != nil {
			return nil, err
		}
		out = append(out, mdocdcapi.Answer{Document: a.Request, IssuerSigned: issuerSigned, Holder: k, Elements: a.Elements})
	}
	// ctx too: once it ends, no further holder key signs, as in person.
	encrypted, err := p.in.RespondDocuments(ctx, out)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	return encrypted, nil
}
