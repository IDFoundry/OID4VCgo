package mdocdcapi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/readerauth"
	"github.com/idfoundry/oid4vcgo/internal/weborigin"
)

// Protocol is the Digital Credentials API protocol identifier for this
// mechanism (Annex C.1).
const Protocol = "org-iso-mdoc"

// nonceBytes is the EncryptionInfo nonce's length: Annex C.2 requires
// at least 16 bytes of entropy.
const nonceBytes = 32

// ReaderKey signs a request as one mdoc reader: a document provider
// shows, and decides whether to answer, by the certificate.
type ReaderKey struct {
	// Signer is the reader's private key: ECDSA on P-256, P-384 or
	// P-521, or Ed25519.
	Signer crypto.Signer
	// Chain is its certificate chain, leaf first, carried in each
	// signature's x5chain header (ISO/IEC 18013-5 §12.5). The leaf
	// certifies Signer's public key.
	Chain []*x509.Certificate
}

// RequestParams is the input to BuildRequest.
type RequestParams struct {
	// Origin is the serialized origin of the page that calls the
	// Digital Credentials API, from the Verifier's configuration — for
	// example "https://verifier.example". REQUIRED. It is normalized as
	// a browser serializes an origin (scheme and host lowercased, no
	// trailing "/" or default port), and must then be https or, as
	// browsers offer the Digital Credentials API to secure contexts
	// only, loopback http; Pending.Origin is the normalized form.
	Origin string
	// Origins, if set, are the origins of the Verifier's own pages,
	// normalized as Origin is: BuildRequest refuses an Origin that isn't
	// one of them, so one taken from the request (its Origin header,
	// say) can't bind the response to a page the Verifier doesn't
	// serve. Set them in production: BuildRequest takes no
	// AssuranceLevel and so can't require them, but VerifyParams.Origins,
	// required under verifier.AssuranceProduction, refuses the response
	// to a request built for any other origin — after the wallet has
	// answered it.
	Origins []string
	// DocType is the requested document type, for example
	// "org.iso.18013.5.1.mDL". REQUIRED.
	DocType string
	// Elements are the requested data elements, by namespace, each
	// with whether the Verifier intends to retain it (IntentToRetain).
	// At least one. REQUIRED.
	Elements map[string]map[string]bool
	// Documents, instead of DocType and Elements, asks for several
	// documents in one request: a DocRequest each, in order, at most
	// MaxDocRequests, each of a different type. The holder may answer
	// any of them; VerifyResponseDocuments verifies the response.
	Documents []DocumentRequest
	// Readers sign the request, each with a ReaderAuthAll; the first
	// also signs the DocRequest's ReaderAuth, for an mdoc that only
	// checks that. A document provider app may refuse, or not even be
	// offered for, an unsigned request.
	Readers []ReaderKey
	// Random supplies the nonce and the response encryption key. nil
	// means crypto/rand.
	Random io.Reader
	// Lifetime is how long the request stays answerable
	// (Pending.ExpiresAt). Zero means DefaultLifetime; at most
	// MaxLifetime.
	Lifetime time.Duration
	// Now is the time the request is built at. nil means time.Now.
	Now func() time.Time
}

// DocumentRequest is one document a request asks for: its type and
// its data elements, by namespace, each with whether the Verifier
// intends to retain it.
type DocumentRequest struct {
	DocType  string
	Elements map[string]map[string]bool
}

// documents are the documents p asks for.
func (p RequestParams) documents() []DocumentRequest {
	if len(p.Documents) > 0 {
		return p.Documents
	}
	return []DocumentRequest{{DocType: p.DocType, Elements: p.Elements}}
}

// DefaultLifetime is RequestParams.Lifetime's default, and MaxLifetime
// its largest value: a request is answered while the page waits on
// navigator.credentials.get.
const (
	DefaultLifetime = 5 * time.Minute
	MaxLifetime     = time.Hour
)

// RequestData is the request's "data" member for
// navigator.credentials.get (Annex C.2), as JSON.
type RequestData struct {
	// DeviceRequest is the CBOR DeviceRequest, base64url-encoded.
	DeviceRequest string `json:"deviceRequest"`
	// EncryptionInfo is the CBOR EncryptionInfo (the nonce and the key
	// the response is sealed to), base64url-encoded.
	EncryptionInfo string `json:"encryptionInfo"`
}

// Pending is what VerifyResponse needs from BuildRequest, kept by the
// Verifier — never sent to the page. RecipientKey decrypts the
// response: keep it as secret as any private key, and only as long as
// the request.
//
// A request is answered once: take its Pending out of wherever it's
// kept — atomically, so that two responses arriving together can't
// both find it — before calling VerifyResponse, and don't put it back.
// VerifyResponse keeps no state: a response verifies as often as it's
// presented with the same Pending, so one that's been captured could
// otherwise be replayed for as long as the Pending is kept, up to its
// ExpiresAt. Keep it server-side, never in a cookie or other
// client-held session: RecipientKey is a private key.
type Pending struct {
	// Origin is the page's origin the request was built for: the
	// response's session transcript binds it.
	Origin string
	// DocType and Elements are what was requested: VerifyResponse
	// refuses a document of another type, or an element not asked for.
	DocType  string
	Elements map[string]map[string]bool
	// Documents, for a request of several documents
	// (RequestParams.Documents), are what it asked for, in order:
	// DocType and Elements are then empty. VerifyResponseDocuments
	// refuses a document of a type not among them, or an element its
	// type's request didn't ask for.
	Documents []DocumentRequest
	// EncryptionInfo is the request's, as sent.
	EncryptionInfo string
	// RecipientKey is the private key the response is sealed to.
	RecipientKey *ecdh.PrivateKey
	// ExpiresAt is when the request stops being answerable:
	// VerifyResponse refuses a response after it, or a Pending without
	// one.
	ExpiresAt time.Time
}

// documents are the documents p's request asked for.
func (p Pending) documents() []DocumentRequest {
	if len(p.Documents) > 0 {
		return p.Documents
	}
	return []DocumentRequest{{DocType: p.DocType, Elements: p.Elements}}
}

// Request is BuildRequest's result.
type Request struct {
	// Data goes to the page, for navigator.credentials.get.
	Data RequestData
	// Pending stays with the Verifier, for VerifyResponse.
	Pending Pending
}

// itemsRequest is ISO/IEC 18013-5 §10.2.3's ItemsRequest.
type itemsRequest struct {
	DocType    string                     `cbor:"docType"`
	NameSpaces map[string]map[string]bool `cbor:"nameSpaces"`
}

// encryptionInfo is Annex C.2's EncryptionInfo: ["dcapi",
// EncryptionParameters].
type encryptionParameters struct {
	Nonce              []byte       `cbor:"nonce"`
	RecipientPublicKey mdoc.CoseKey `cbor:"recipientPublicKey"`
}

// BuildRequest builds an org-iso-mdoc request for one document, or for
// RequestParams.Documents, with a fresh nonce and response encryption
// key.
func BuildRequest(p RequestParams) (Request, error) {
	p.Origin = weborigin.Normalize(p.Origin)
	if err := checkRequestParams(p); err != nil {
		return Request{}, err
	}
	random := p.Random
	if random == nil {
		random = rand.Reader
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	lifetime := p.Lifetime
	if lifetime == 0 {
		lifetime = DefaultLifetime
	}

	recipient, err := ecdh.P256().GenerateKey(random)
	if err != nil {
		return Request{}, fmt.Errorf("mdocdcapi: generate response encryption key: %w", err)
	}
	encryptionInfo, err := buildEncryptionInfo(random, recipient.PublicKey())
	if err != nil {
		return Request{}, err
	}
	transcript, err := sessionTranscript(encryptionInfo, p.Origin)
	if err != nil {
		return Request{}, err
	}
	deviceRequest, err := buildDeviceRequest(p, transcript)
	if err != nil {
		return Request{}, err
	}
	pending := Pending{Origin: p.Origin, EncryptionInfo: encryptionInfo, RecipientKey: recipient, ExpiresAt: now().Add(lifetime)}
	if len(p.Documents) > 0 {
		for _, d := range p.Documents {
			pending.Documents = append(pending.Documents, DocumentRequest{DocType: d.DocType, Elements: cloneElements(d.Elements)})
		}
	} else {
		pending.DocType, pending.Elements = p.DocType, cloneElements(p.Elements)
	}
	return Request{
		Data:    RequestData{DeviceRequest: deviceRequest, EncryptionInfo: encryptionInfo},
		Pending: pending,
	}, nil
}

func checkRequestParams(p RequestParams) error {
	if err := weborigin.CheckPage(p.Origin, true); err != nil {
		return fmt.Errorf("mdocdcapi: %w", err)
	}
	if err := checkAllowed(p.Origin, p.Origins, true); err != nil {
		return err
	}
	if p.Lifetime < 0 || p.Lifetime > MaxLifetime {
		return fmt.Errorf("mdocdcapi: Lifetime %s is outside 0..%s", p.Lifetime, MaxLifetime)
	}
	if len(p.Documents) > 0 && (p.DocType != "" || len(p.Elements) > 0) {
		return errors.New("mdocdcapi: set DocType and Elements, or Documents, not both")
	}
	if len(p.Documents) > MaxDocRequests {
		return fmt.Errorf("mdocdcapi: %d documents requested, over %d", len(p.Documents), MaxDocRequests)
	}
	docs := p.documents()
	for i, d := range docs {
		if err := checkDocumentRequest(d); err != nil {
			return err
		}
		for _, prev := range docs[:i] {
			if prev.DocType == d.DocType {
				return fmt.Errorf("mdocdcapi: %q requested twice", d.DocType)
			}
		}
	}
	for i, r := range p.Readers {
		if _, err := readerauth.CheckKey(r.Signer, r.Chain); err != nil {
			return fmt.Errorf("mdocdcapi: reader %d: %w", i, err)
		}
	}
	return nil
}

// checkDocumentRequest refuses a document request without a type or an
// element, or with an unnamed namespace or element.
func checkDocumentRequest(d DocumentRequest) error {
	if d.DocType == "" {
		return errors.New("mdocdcapi: DocType is required")
	}
	if len(d.Elements) == 0 {
		return errors.New("mdocdcapi: at least one data element must be requested")
	}
	for ns, elements := range d.Elements {
		if ns == "" || len(elements) == 0 {
			return fmt.Errorf("mdocdcapi: namespace %q must be named and request at least one element", ns)
		}
		for el := range elements {
			if el == "" {
				return fmt.Errorf("mdocdcapi: namespace %q requests an unnamed element", ns)
			}
		}
	}
	return nil
}

// buildEncryptionInfo is Base64EncryptionInfo for recipient.
func buildEncryptionInfo(random io.Reader, recipient *ecdh.PublicKey) (string, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", fmt.Errorf("mdocdcapi: nonce: %w", err)
	}
	point := recipient.Bytes() // 0x04 || X || Y
	key := mdoc.CoseKey{Kty: 2, Crv: 1, X: point[1:33], Y: point[33:]}
	raw, err := encMode.Marshal([]any{"dcapi", encryptionParameters{Nonce: nonce, RecipientPublicKey: key}})
	if err != nil {
		return "", fmt.Errorf("mdocdcapi: encode EncryptionInfo: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// buildDeviceRequest is Base64DeviceRequest: a DocRequest for each
// requested document, each signed by the first reader, and the whole
// signed by each reader.
func buildDeviceRequest(p RequestParams, transcript []byte) (string, error) {
	docs := p.documents()
	docRequests := make([]any, 0, len(docs))
	items := make([][]byte, 0, len(docs))
	for _, d := range docs {
		itemsRequestBytes, err := wrapTag24(itemsRequest{DocType: d.DocType, NameSpaces: d.Elements})
		if err != nil {
			return "", fmt.Errorf("mdocdcapi: encode ItemsRequest: %w", err)
		}
		docRequest := map[string]any{"itemsRequest": cbor.RawMessage(itemsRequestBytes)}
		if len(p.Readers) > 0 {
			detached, err := readerauth.AuthenticationBytes(transcript, itemsRequestBytes)
			if err != nil {
				return "", fmt.Errorf("mdocdcapi: encode ReaderAuthentication: %w", err)
			}
			readerAuth, err := signReaderAuth(p.Readers[0], "ReaderAuthentication", detached)
			if err != nil {
				return "", err
			}
			docRequest["readerAuth"] = cbor.RawMessage(readerAuth)
		}
		docRequests = append(docRequests, docRequest)
		items = append(items, itemsRequestBytes)
	}
	deviceRequest := map[string]any{"version": "1.0", "docRequests": docRequests}
	if len(p.Readers) > 0 {
		// Every reader signs the same ReaderAuthenticationAll.
		detached, err := readerauth.AuthenticationAllBytes(transcript, items, nil)
		if err != nil {
			return "", fmt.Errorf("mdocdcapi: encode ReaderAuthenticationAll: %w", err)
		}
		all := make([]any, 0, len(p.Readers))
		for _, r := range p.Readers {
			sig, err := signReaderAuth(r, "ReaderAuthenticationAll", detached)
			if err != nil {
				return "", err
			}
			all = append(all, cbor.RawMessage(sig))
		}
		// "1.1" when readerAuthAll is present (ISO/IEC 18013-5 §10.2.2).
		deviceRequest["version"], deviceRequest["readerAuthAll"] = "1.1", all
	}
	raw, err := encMode.Marshal(deviceRequest)
	if err != nil {
		return "", fmt.Errorf("mdocdcapi: encode DeviceRequest: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// signReaderAuth is a ReaderAuth or ReaderAuthAll: a COSE_Sign1 with a
// null payload over detached, the encoded ReaderAuthenticationBytes or
// ReaderAuthenticationAllBytes (internal/readerauth builds both) that
// name is, the reader's chain in the unprotected x5chain header.
func signReaderAuth(r ReaderKey, name string, detached []byte) ([]byte, error) {
	sig, err := readerauth.Sign(r.Signer, r.Chain, detached)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: sign %s: %w", name, err)
	}
	return sig, nil
}

func cloneElements(elements map[string]map[string]bool) map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(elements))
	for ns, els := range elements {
		out[ns] = make(map[string]bool, len(els))
		for el, retain := range els {
			out[ns][el] = retain
		}
	}
	return out
}
