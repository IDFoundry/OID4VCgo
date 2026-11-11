// Package mdocresponse encodes and decodes an ISO/IEC 18013-5
// DeviceResponse (§8.3.2.1.2.2) carrying one or more documents, as an
// in-person response (package proximity) or an ISO/IEC TS 18013-7
// Annex C response (package mdocdcapi) may.
//
// Package oid4vpmdoc's encoding is the single-document one OpenID4VP
// and HAIP use: HAIP §5.3.1 returns each mdoc in its own
// DeviceResponse. Neither of the protocols here is bound by that, so a
// holder answering several DocRequests answers them in one
// DeviceResponse. With one document, Marshal's bytes are
// oid4vpmdoc.MarshalDeviceResponse's.
package mdocresponse

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/strictcbor"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// version is the DeviceResponse version §8.3.2.1.2.2 defines.
const version = "1.0"

// statusOK is §8.3.2.1.2.3 Table 8's status 0, OK.
const statusOK = 0

type wireDocument struct {
	DocType      string          `cbor:"docType"`
	IssuerSigned cbor.RawMessage `cbor:"issuerSigned"`
	DeviceSigned cbor.RawMessage `cbor:"deviceSigned"`
}

type wireDeviceResponse struct {
	Version        string             `cbor:"version"`
	Documents      []wireDocument     `cbor:"documents,omitempty"`
	DocumentErrors []map[string]int64 `cbor:"documentErrors,omitempty"`
	Status         uint64             `cbor:"status"`
}

// ErrDecoding is the error, wrapped, for a DeviceResponse over its size
// limit, one that isn't CBOR of its shape, or a document missing a
// member or whose issuerSigned or deviceSigned doesn't decode.
var ErrDecoding = errors.New("mdocresponse: malformed DeviceResponse")

// Response is a decoded DeviceResponse: its documents, each decoded, its
// documentErrors and its status, neither judged.
type Response struct {
	Documents      []oid4vpmdoc.Document
	DocumentErrors []map[string]int64
	Status         uint64
}

// Marshal encodes a DeviceResponse with status 0 carrying docs, in
// order. It refuses no documents, or a document without a docType.
func Marshal(docs ...oid4vpmdoc.Document) ([]byte, error) {
	if len(docs) == 0 {
		return nil, errors.New("mdocresponse: a DeviceResponse needs a document")
	}
	wire := wireDeviceResponse{Version: version, Status: statusOK, Documents: make([]wireDocument, 0, len(docs))}
	for i, d := range docs {
		if d.DocType == "" {
			return nil, fmt.Errorf("mdocresponse: document %d has no docType", i)
		}
		issuerSigned, err := d.IssuerSigned.Marshal()
		if err != nil {
			return nil, fmt.Errorf("mdocresponse: document %d issuerSigned: %w", i, err)
		}
		deviceSigned, err := d.DeviceSigned.Marshal()
		if err != nil {
			return nil, fmt.Errorf("mdocresponse: document %d deviceSigned: %w", i, err)
		}
		wire.Documents = append(wire.Documents, wireDocument{DocType: d.DocType, IssuerSigned: issuerSigned, DeviceSigned: deviceSigned})
	}
	b, err := cbor.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("mdocresponse: encode DeviceResponse: %w", err)
	}
	return b, nil
}

// Unmarshal decodes data, at most maxBytes, as a DeviceResponse with
// status 0 and from one to maxDocuments documents, each with a
// distinct docType: a reader asks for each document type once. It
// verifies nothing.
func Unmarshal(data []byte, maxBytes, maxDocuments int) ([]oid4vpmdoc.Document, error) {
	resp, err := Decode(data, maxBytes, maxDocuments)
	if err != nil {
		return nil, err
	}
	if resp.Status != statusOK {
		return nil, fmt.Errorf("mdocresponse: DeviceResponse status %d, want %d (OK)", resp.Status, statusOK)
	}
	if len(resp.Documents) == 0 {
		return nil, errors.New("mdocresponse: DeviceResponse has no documents")
	}
	return resp.Documents, nil
}

// Decode decodes data, at most maxBytes, as a DeviceResponse of version
// 1.x with at most maxDocuments documents, each with a distinct docType,
// leaving its status and whether it has any documents to the caller —
// Unmarshal requires status 0 and a document; an in-person reader
// reports a status, or documentErrors alone, as itself. A size, CBOR or
// document-member fault wraps ErrDecoding. It verifies nothing.
func Decode(data []byte, maxBytes, maxDocuments int) (Response, error) {
	if len(data) > maxBytes {
		return Response{}, fmt.Errorf("%w: DeviceResponse is %d bytes, over %d", ErrDecoding, len(data), maxBytes)
	}
	var wire wireDeviceResponse
	if err := decMode.Unmarshal(data, &wire); err != nil {
		return Response{}, fmt.Errorf("%w: %w", ErrDecoding, err)
	}
	if !strings.HasPrefix(wire.Version, "1.") {
		return Response{}, fmt.Errorf("mdocresponse: DeviceResponse version %q, want 1.x", wire.Version)
	}
	if len(wire.Documents) > maxDocuments {
		return Response{}, fmt.Errorf("mdocresponse: DeviceResponse has %d documents, over %d", len(wire.Documents), maxDocuments)
	}
	out := Response{DocumentErrors: wire.DocumentErrors, Status: wire.Status}
	seen := map[string]bool{}
	for i, d := range wire.Documents {
		if d.DocType == "" || d.IssuerSigned == nil || d.DeviceSigned == nil {
			return Response{}, fmt.Errorf("%w: document %d needs docType, issuerSigned and deviceSigned", ErrDecoding, i)
		}
		if seen[d.DocType] {
			return Response{}, fmt.Errorf("mdocresponse: DeviceResponse has two %q documents", d.DocType)
		}
		seen[d.DocType] = true
		issuerSigned, err := mdoc.UnmarshalIssuerSignedMax(d.IssuerSigned, maxBytes)
		if err != nil {
			return Response{}, fmt.Errorf("%w: document %d issuerSigned: %w", ErrDecoding, i, err)
		}
		deviceSigned, err := mdoc.UnmarshalDeviceSignedMax(d.DeviceSigned, maxBytes)
		if err != nil {
			return Response{}, fmt.Errorf("%w: document %d deviceSigned: %w", ErrDecoding, i, err)
		}
		out.Documents = append(out.Documents, oid4vpmdoc.Document{DocType: d.DocType, IssuerSigned: issuerSigned, DeviceSigned: deviceSigned})
	}
	return out, nil
}

// UnverifiedDocType is the docType in issuerSigned's Mobile Security
// Object, its IssuerAuth at most maxBytes, read without verifying the
// signature: a holder answering a request checks the mdoc it holds is
// of the requested type before its device key signs, so it never
// presents one document as another.
func UnverifiedDocType(issuerSigned mdoc.IssuerSigned, maxBytes int) (string, error) {
	_, _, payload, err := cose.DecodeUnverifiedMax(issuerSigned.IssuerAuth, maxBytes)
	if err != nil {
		return "", fmt.Errorf("decode IssuerAuth: %w", err)
	}
	var tag cbor.RawTag
	if err := decMode.Unmarshal(payload, &tag); err != nil {
		return "", fmt.Errorf("decode MSO: %w", err)
	}
	if tag.Number != 24 {
		return "", fmt.Errorf("decode MSO: tag %d, want 24", tag.Number)
	}
	var msoBytes []byte
	if err := decMode.Unmarshal(tag.Content, &msoBytes); err != nil {
		return "", fmt.Errorf("decode MSO: tag 24 content: %w", err)
	}
	var mso struct {
		DocType string `cbor:"docType"`
	}
	if err := decMode.Unmarshal(msoBytes, &mso); err != nil {
		return "", fmt.Errorf("decode MSO: %w", err)
	}
	if mso.DocType == "" {
		return "", errors.New("decode MSO: no docType")
	}
	return mso.DocType, nil
}

// decMode decodes an untrusted DeviceResponse within credential/mdoc's
// bounds, as oid4vpmdoc's does.
var decMode = func() strictcbor.DecMode {
	mode, err := cbor.DecOptions{
		MaxNestedLevels:   mdoc.MaxCBORNestedLevels,
		MaxArrayElements:  mdoc.MaxCBORContainerItems,
		MaxMapPairs:       mdoc.MaxCBORContainerItems,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic("mdocresponse: build CBOR decoder: " + err.Error())
	}
	return strictcbor.Wrap(mode)
}()
