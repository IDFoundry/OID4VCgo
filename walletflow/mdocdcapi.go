package walletflow

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
)

// MdocRequest is one document an org-iso-mdoc request asks for.
type MdocRequest struct {
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
// signed it against Config.MdocReaderRoots, and finds the held mdocs
// that can answer it, without answering. Show the holder Origin,
// Reader and Requests, then Respond; to decline, the app cancels the
// platform's request: nothing is sent to the reader.
func (w *Wallet) StartMdocPresentation(ctx context.Context, data []byte, origin string) (*MdocPresentation, error) {
	in, err := mdocdcapi.ParseRequest(data, origin)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	p := &MdocPresentation{w: w, in: in, byID: map[string]StoredCredential{}}
	if w.cfg.MdocReaderRoots != nil {
		// An untrusted reader isn't refused: the holder sees the origin
		// instead.
		p.reader, _ = in.VerifyReader(w.cfg.MdocReaderRoots, w.deps.Clock())
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

// verifier identifies the origin among the Verifiers credential copies
// were shown to: as an OpenID4VP Verifier without a client_id of its
// own is known over the Digital Credentials API ("origin:" prefix,
// OpenID4VP 1.0 Appendix A.2).
func (p *MdocPresentation) verifier() string {
	return VerifierHash("origin:" + p.in.Origin)
}

// MdocPresented is Respond's answer.
type MdocPresented struct {
	// EncryptedResponse is the CBOR EncryptedResponse to return to the
	// platform: on iOS, ISO18013MobileDocumentResponse's responseData.
	EncryptedResponse []byte
	// Linkable is whether the copy presented had been seen by another
	// Verifier (Linkable said so).
	Linkable bool
}

// Respond presents the held mdoc credentialID for request number
// request, disclosing exactly elements — each a [namespace, identifier]
// the request asked for (ErrInvalidSelection otherwise) — with the
// credential's next unused copy, its holder key signing over the
// session transcript. A KeyStore that requires user presence prompts
// now. An MdocPresentation is answered once.
func (p *MdocPresentation) Respond(ctx context.Context, request int, credentialID string, elements [][2]string) (MdocPresented, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.answered {
		return MdocPresented{}, ErrWrongStep
	}
	if err := p.checkSelection(request, credentialID, elements); err != nil {
		return MdocPresented{}, err
	}
	verifier := p.verifier()
	reserved, err := p.w.reserve(ctx, Selection{"": {credentialID}}, verifier, p.Linkable)
	if err != nil {
		return MdocPresented{}, err
	}
	encrypted, err := p.respond(ctx, request, reserved[0], elements)
	if err != nil {
		// Nothing left the wallet: the copy wasn't seen.
		p.w.release(ctx, reserved, verifier)
		return MdocPresented{}, err
	}
	p.answered = true
	return MdocPresented{EncryptedResponse: encrypted, Linkable: reserved[0].linkable}, nil
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

// respond builds the EncryptedResponse with the reserved copy.
func (p *MdocPresentation) respond(ctx context.Context, request int, r reservedCopy, elements [][2]string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(r.c.Credential)
	if err != nil {
		return nil, fmt.Errorf("walletflow: credential %q: %w", r.id, err)
	}
	issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("walletflow: credential %q: %w", r.id, err)
	}
	k, err := p.w.deps.Keys.Key(ctx, r.keyID)
	if err != nil {
		return nil, fmt.Errorf("walletflow: credential %q's holder key: %w", r.id, err)
	}
	encrypted, err := p.in.Respond(request, issuerSigned, k, elements)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	return encrypted, nil
}
