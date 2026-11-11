package proximity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"slices"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/mdocresponse"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// BuildDeviceResponse builds the DeviceResponse (§8.3.2.1.2.2) answering
// req: issuerSigned, an mdoc of req.DocType, trimmed to elements — the
// elements of req.Elements the user consented to; any req didn't
// request is refused, so nothing it didn't ask for is disclosed — and a
// device signature (§9.1.3.6) by holder, the mdoc's device key, over
// sessionTranscriptBytes (DeviceSession.SessionTranscriptBytes), with
// no device-signed elements. Encrypt the result with
// DeviceSession.Encrypt. It is BuildDocument and MarshalDeviceResponse
// with one document.
//
// When nothing matches the request or the user declines, don't call
// this: send DeviceSession.Termination instead, as Multipaz does.
func BuildDeviceResponse(req DocRequest, issuerSigned mdoc.IssuerSigned, holder crypto.Signer, sessionTranscriptBytes []byte, elements [][2]string) ([]byte, error) {
	doc, err := BuildDocument(req, issuerSigned, holder, sessionTranscriptBytes, elements)
	if err != nil {
		return nil, err
	}
	return MarshalDeviceResponse(doc)
}

// BuildDocument builds the Document (§8.3.2.1.2.2) answering req, as
// BuildDeviceResponse describes, for MarshalDeviceResponse to carry
// beside the Documents answering the request's other DocRequests.
func BuildDocument(req DocRequest, issuerSigned mdoc.IssuerSigned, holder crypto.Signer, sessionTranscriptBytes []byte, elements [][2]string) (oid4vpmdoc.Document, error) {
	if err := checkAnswer(req, issuerSigned, elements); err != nil {
		return oid4vpmdoc.Document{}, err
	}
	return buildDocument(issuerSigned, req.DocType, holder, sessionTranscriptBytes, elements)
}

// MarshalDeviceResponse encodes a DeviceResponse with status 0 carrying
// docs, in order: a Document for each DocRequest the holder answers,
// any subset of the request's (§8.3.2.1.2.2). A DocRequest the holder
// doesn't answer is left out, with no documentErrors. Encrypt the
// result with DeviceSession.Encrypt.
func MarshalDeviceResponse(docs ...oid4vpmdoc.Document) ([]byte, error) {
	b, err := mdocresponse.Marshal(docs...)
	if err != nil {
		return nil, fmt.Errorf("proximity: build DeviceResponse: %w", err)
	}
	return b, nil
}

// buildDeviceResponse is BuildDeviceResponse without its checks against
// the request.
func buildDeviceResponse(issuerSigned mdoc.IssuerSigned, docType string, holder crypto.Signer, sessionTranscriptBytes []byte, elements [][2]string) ([]byte, error) {
	doc, err := buildDocument(issuerSigned, docType, holder, sessionTranscriptBytes, elements)
	if err != nil {
		return nil, err
	}
	return MarshalDeviceResponse(doc)
}

// buildDocument is BuildDocument without its checks against the
// request.
func buildDocument(issuerSigned mdoc.IssuerSigned, docType string, holder crypto.Signer, sessionTranscriptBytes []byte, elements [][2]string) (oid4vpmdoc.Document, error) {
	if holder == nil {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: no device key")
	}
	if len(sessionTranscriptBytes) == 0 {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: no session transcript (session not established)")
	}
	selected := issuerSigned.SelectNameSpaces(elements)
	if len(selected.NameSpaces) == 0 {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: the credential holds none of the elements to disclose")
	}
	alg, err := keyAlg(holder.Public())
	if err != nil {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: %w", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(holder, alg, sessionTranscriptBytes, docType, map[string]map[string]interface{}{})
	if err != nil {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: %w", err)
	}
	return oid4vpmdoc.Document{DocType: docType, IssuerSigned: selected, DeviceSigned: deviceSigned}, nil
}

// checkAnswer refuses elements req didn't request, and an mdoc that
// isn't of req's docType.
func checkAnswer(req DocRequest, issuerSigned mdoc.IssuerSigned, elements [][2]string) error {
	if err := checkRequested(req, elements); err != nil {
		return err
	}
	if held, err := mdocresponse.UnverifiedDocType(issuerSigned, MaxMessageBytes); err != nil {
		return fmt.Errorf("proximity: build DeviceResponse: %w", err)
	} else if held != req.DocType {
		return fmt.Errorf("proximity: build DeviceResponse: the mdoc is a %q, the request is for %q", held, req.DocType)
	}
	return nil
}

// KeyAgreer is a device key that can agree a key with a peer — ECKA-DH
// inside the key store — for MAC device authentication (§9.1.3.5). It
// returns the shared secret Z, the SEC1 x-coordinate: for P-256, 32
// octets. The peer is on the device key's curve, or Agree fails.
type KeyAgreer interface {
	Agree(peer *ecdsa.PublicKey) ([]byte, error)
}

// BuildDeviceResponseMAC is BuildDeviceResponse with MAC device
// authentication (§9.1.3.5, §12.4.5) instead of a signature: holder,
// the mdoc's device key, agrees a key with eReaderKey
// (DeviceSession.EReaderKey), and the DeviceResponse carries deviceMac
// under the EMacKey derived from it. Unlike a signature, the reader can
// check a MAC but can't show anyone else the holder made it; the
// issuer-signed elements stay as provable as with a signature. It is
// BuildDocumentMAC and MarshalDeviceResponse with one document.
func BuildDeviceResponseMAC(req DocRequest, issuerSigned mdoc.IssuerSigned, holder KeyAgreer, eReaderKey *ecdsa.PublicKey, sessionTranscriptBytes []byte, elements [][2]string) ([]byte, error) {
	doc, err := BuildDocumentMAC(req, issuerSigned, holder, eReaderKey, sessionTranscriptBytes, elements)
	if err != nil {
		return nil, err
	}
	return MarshalDeviceResponse(doc)
}

// BuildDocumentMAC is BuildDocument with MAC device authentication, as
// BuildDeviceResponseMAC describes. Each Document in a DeviceResponse
// authenticates on its own: one may carry a MAC and another a
// signature.
func BuildDocumentMAC(req DocRequest, issuerSigned mdoc.IssuerSigned, holder KeyAgreer, eReaderKey *ecdsa.PublicKey, sessionTranscriptBytes []byte, elements [][2]string) (oid4vpmdoc.Document, error) {
	if err := checkAnswer(req, issuerSigned, elements); err != nil {
		return oid4vpmdoc.Document{}, err
	}
	if holder == nil {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: no device key")
	}
	if eReaderKey == nil {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: no reader key (session not established)")
	}
	if _, ok := mdocCurves[eReaderKey.Curve]; !ok {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: DeviceMac needs a reader key on P-256, P-384 or P-521, got %s", eReaderKey.Curve.Params().Name)
	}
	if len(sessionTranscriptBytes) == 0 {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: no session transcript (session not established)")
	}
	selected := issuerSigned.SelectNameSpaces(elements)
	if len(selected.NameSpaces) == 0 {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: the credential holds none of the elements to disclose")
	}
	z, err := holder.Agree(eReaderKey)
	if err != nil {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: key agreement: %w", err)
	}
	deviceSigned, err := mdoc.ComputeDeviceMACFromSharedSecret(z, sessionTranscriptBytes, req.DocType, map[string]map[string]interface{}{})
	if err != nil {
		return oid4vpmdoc.Document{}, fmt.Errorf("proximity: build DeviceResponse: %w", err)
	}
	return oid4vpmdoc.Document{DocType: req.DocType, IssuerSigned: selected, DeviceSigned: deviceSigned}, nil
}

// checkRequested refuses an empty disclosure, and any element req
// doesn't request.
func checkRequested(req DocRequest, elements [][2]string) error {
	if req.DocType == "" {
		return fmt.Errorf("proximity: build DeviceResponse: no document request")
	}
	if len(elements) == 0 {
		return fmt.Errorf("proximity: build DeviceResponse: no element to disclose")
	}
	for _, e := range elements {
		if !slices.Contains(req.Elements, e) {
			return fmt.Errorf("proximity: build DeviceResponse: %s/%s wasn't requested", e[0], e[1])
		}
	}
	return nil
}

// mdocCurves are the EC curves DeviceMac agrees keys on
// (credential/mdoc's).
var mdocCurves = map[elliptic.Curve]bool{elliptic.P256(): true, elliptic.P384(): true, elliptic.P521(): true}

// keyAlg is the COSE algorithm a key signs with — a device key, or a
// document signer's (cose.AlgForKey): ES256, ES384 or ES512 for P-256,
// P-384 or P-521, EdDSA for Ed25519. Its errors name the key's curve or
// type; the caller says whose key it is.
func keyAlg(pub crypto.PublicKey) (oid4vci.COSEAlg, error) {
	return cose.AlgForKey(pub)
}

// ErrNoDocument is ReaderSession.Verify's result for a DeviceResponse
// with status 0 and no documents, only documentErrors: the mdoc has
// nothing to return for the request.
var ErrNoDocument = errors.New("proximity: DeviceResponse returned no document")

// responseDocument is one parsed, not yet verified, document.
type responseDocument struct {
	docType      string
	issuerSigned mdoc.IssuerSigned
	deviceSigned mdoc.DeviceSigned
}

// parseDeviceResponse decodes a DeviceResponse with exactly one
// document — the reader requested one.
func parseDeviceResponse(b []byte) (responseDocument, error) {
	docs, err := parseDeviceResponseDocuments(b, 1)
	if err != nil {
		return responseDocument{}, err
	}
	return docs[0], nil
}

// parseDeviceResponseDocuments decodes a DeviceResponse with from one
// to requested documents, each of a different type — the reader asked
// for requested documents, each type once. The decoding is
// mdocresponse.Decode's (oid4vpmdoc.UnmarshalDeviceResponse is HAIP's
// exactly-one-document form, and refuses a response carrying only
// documentErrors, which a proximity reader reports instead), its faults
// reported as ErrCBORDecoding.
func parseDeviceResponseDocuments(b []byte, requested int) ([]responseDocument, error) {
	resp, err := mdocresponse.Decode(b, MaxMessageBytes, MaxDocRequests)
	if errors.Is(err, mdocresponse.ErrDecoding) {
		return nil, fmt.Errorf("proximity: decode DeviceResponse: %w: %w", ErrCBORDecoding, err)
	}
	if err != nil {
		return nil, fmt.Errorf("proximity: %w", err)
	}
	if resp.Status != DeviceResponseStatusOK {
		return nil, &DeviceResponseStatusError{Status: resp.Status}
	}
	switch {
	case len(resp.Documents) == 0:
		return nil, fmt.Errorf("%w (documentErrors %v)", ErrNoDocument, resp.DocumentErrors)
	case len(resp.Documents) > requested && requested == 1:
		return nil, fmt.Errorf("proximity: DeviceResponse has %d documents for one request", len(resp.Documents))
	case len(resp.Documents) > requested:
		return nil, fmt.Errorf("proximity: DeviceResponse has %d documents for %d requested", len(resp.Documents), requested)
	}

	out := make([]responseDocument, 0, len(resp.Documents))
	for _, doc := range resp.Documents {
		out = append(out, responseDocument{docType: doc.DocType, issuerSigned: doc.IssuerSigned, deviceSigned: doc.DeviceSigned})
	}
	return out, nil
}
