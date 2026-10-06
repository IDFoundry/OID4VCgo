package proximity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// BuildDeviceResponse builds the DeviceResponse (§8.3.2.1.2.2) answering
// req: issuerSigned, an mdoc of req.DocType, trimmed to elements — the
// elements of req.Elements the user consented to; any req didn't
// request is refused, so nothing it didn't ask for is disclosed — and a
// device signature (§9.1.3.6) by holder, the mdoc's device key, over
// sessionTranscriptBytes (DeviceSession.SessionTranscriptBytes), with
// no device-signed elements. Encrypt the result with
// DeviceSession.Encrypt.
//
// When nothing matches the request or the user declines, don't call
// this: send DeviceSession.Termination instead, as Multipaz does.
func BuildDeviceResponse(req DocRequest, issuerSigned mdoc.IssuerSigned, holder crypto.Signer, sessionTranscriptBytes []byte, elements [][2]string) ([]byte, error) {
	if err := checkRequested(req, elements); err != nil {
		return nil, err
	}
	if held, err := msoDocType(issuerSigned); err != nil {
		return nil, fmt.Errorf("proximity: build DeviceResponse: %w", err)
	} else if held != req.DocType {
		return nil, fmt.Errorf("proximity: build DeviceResponse: the mdoc is a %q, the request is for %q", held, req.DocType)
	}
	return buildDeviceResponse(issuerSigned, req.DocType, holder, sessionTranscriptBytes, elements)
}

// buildDeviceResponse is BuildDeviceResponse without its checks against
// the request.
func buildDeviceResponse(issuerSigned mdoc.IssuerSigned, docType string, holder crypto.Signer, sessionTranscriptBytes []byte, elements [][2]string) ([]byte, error) {
	if holder == nil {
		return nil, fmt.Errorf("proximity: build DeviceResponse: no device key")
	}
	if len(sessionTranscriptBytes) == 0 {
		return nil, fmt.Errorf("proximity: build DeviceResponse: no session transcript (session not established)")
	}
	selected := issuerSigned.SelectNameSpaces(elements)
	if len(selected.NameSpaces) == 0 {
		return nil, fmt.Errorf("proximity: build DeviceResponse: the credential holds none of the elements to disclose")
	}
	alg, err := keyAlg(holder.Public())
	if err != nil {
		return nil, fmt.Errorf("proximity: build DeviceResponse: %w", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(holder, alg, sessionTranscriptBytes, docType, map[string]map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("proximity: build DeviceResponse: %w", err)
	}
	// oid4vpmdoc's encoding is §8.3.2.1.2.2's single-document
	// DeviceResponse exactly: version, documents, status 0.
	b, err := oid4vpmdoc.MarshalDeviceResponse(oid4vpmdoc.Document{
		DocType: docType, IssuerSigned: selected, DeviceSigned: deviceSigned,
	})
	if err != nil {
		return nil, fmt.Errorf("proximity: build DeviceResponse: %w", err)
	}
	return b, nil
}

// msoDocType is the docType in issuerSigned's MSO — the holder's own
// mdoc, read without verifying it.
func msoDocType(issuerSigned mdoc.IssuerSigned) (string, error) {
	_, _, payload, err := cose.DecodeUnverifiedMax(issuerSigned.IssuerAuth, MaxMessageBytes)
	if err != nil {
		return "", fmt.Errorf("decode IssuerAuth: %w", err)
	}
	msoBytes, err := unwrapTag24(payload)
	if err != nil {
		return "", fmt.Errorf("decode MSO: %w", err)
	}
	var mso struct {
		DocType string `cbor:"docType"`
	}
	if err := decMode.Unmarshal(msoBytes, &mso); err != nil {
		return "", fmt.Errorf("decode MSO: %w", err)
	}
	return mso.DocType, nil
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

// keyAlg is the COSE algorithm a key signs with — a device key, or a
// document signer's: ES256 for P-256, EdDSA for Ed25519, the two
// credential/mdoc supports.
func keyAlg(pub crypto.PublicKey) (oid4vci.COSEAlg, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return 0, fmt.Errorf("unsupported device key curve %s", k.Curve.Params().Name)
		}
		return cose.ES256, nil
	case ed25519.PublicKey:
		return cose.EdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported device key type %T", pub)
	}
}

// deviceResponseStatusOK is §8.3.2.1.2.3's DeviceResponse status 0.
const deviceResponseStatusOK = 0

// wireDeviceResponse is the reader's own view of DeviceResponse
// (§8.3.2.1.2.2). oid4vpmdoc.UnmarshalDeviceResponse is HAIP's
// exactly-one-document form and refuses a response carrying only
// documentErrors; a proximity reader reports that instead.
type wireDeviceResponse struct {
	Version        string             `cbor:"version"`
	Documents      []wireDocument     `cbor:"documents"`
	DocumentErrors []map[string]int64 `cbor:"documentErrors"`
	Status         uint64             `cbor:"status"`
}

type wireDocument struct {
	DocType      string          `cbor:"docType"`
	IssuerSigned cbor.RawMessage `cbor:"issuerSigned"`
	DeviceSigned cbor.RawMessage `cbor:"deviceSigned"`
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
	if len(b) > MaxMessageBytes {
		return responseDocument{}, fmt.Errorf("proximity: DeviceResponse is %d bytes, over %d: %w", len(b), MaxMessageBytes, ErrCBORDecoding)
	}
	var resp wireDeviceResponse
	if err := decMode.Unmarshal(b, &resp); err != nil {
		return responseDocument{}, fmt.Errorf("proximity: decode DeviceResponse: %w: %w", ErrCBORDecoding, err)
	}
	if !strings.HasPrefix(resp.Version, "1.") {
		return responseDocument{}, fmt.Errorf("proximity: DeviceResponse version %q, want 1.x", resp.Version)
	}
	if resp.Status != deviceResponseStatusOK {
		return responseDocument{}, fmt.Errorf("proximity: DeviceResponse status %d", resp.Status)
	}
	switch len(resp.Documents) {
	case 0:
		return responseDocument{}, fmt.Errorf("%w (documentErrors %v)", ErrNoDocument, resp.DocumentErrors)
	case 1:
	default:
		return responseDocument{}, fmt.Errorf("proximity: DeviceResponse has %d documents for one request", len(resp.Documents))
	}

	doc := resp.Documents[0]
	if doc.DocType == "" || doc.IssuerSigned == nil || doc.DeviceSigned == nil {
		return responseDocument{}, fmt.Errorf("proximity: Document needs docType, issuerSigned and deviceSigned: %w", ErrCBORDecoding)
	}
	issuerSigned, err := mdoc.UnmarshalIssuerSignedMax(doc.IssuerSigned, MaxMessageBytes)
	if err != nil {
		return responseDocument{}, fmt.Errorf("proximity: issuerSigned: %w: %w", ErrCBORDecoding, err)
	}
	deviceSigned, err := mdoc.UnmarshalDeviceSignedMax(doc.DeviceSigned, MaxMessageBytes)
	if err != nil {
		return responseDocument{}, fmt.Errorf("proximity: deviceSigned: %w: %w", ErrCBORDecoding, err)
	}
	return responseDocument{docType: doc.DocType, issuerSigned: issuerSigned, deviceSigned: deviceSigned}, nil
}
