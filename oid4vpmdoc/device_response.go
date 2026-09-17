package oid4vpmdoc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
)

// deviceResponseVersion is the only value ISO/IEC 18013-5 §10.3.2
// currently defines for DeviceResponse's own "version" member.
const deviceResponseVersion = "1.0"

// mdocResponseStatusOK is ISO/IEC 18013-5 §10.3.6 Table 3's own
// "status" value 0 ("OK ... normal processing").
const mdocResponseStatusOK = 0

// Document is a DeviceResponse's own single "documents" array entry
// (ISO/IEC 18013-5 §10.3.3) — this package models only the fields an
// OID4VP Presentation actually needs; "errors" isn't modeled, matching
// credential/mdoc's own scope.
type Document struct {
	// DocType is the returned document's own type (e.g.
	// "org.iso.18013.5.1.mDL") — must match the docType the Issuer
	// and Device authenticated (credential/mdoc's own Issue/
	// SignDeviceSignature/ComputeDeviceMAC all take it as a separate
	// parameter, not derived from IssuerSigned itself).
	DocType string

	IssuerSigned mdoc.IssuerSigned
	DeviceSigned mdoc.DeviceSigned
}

type wireDocument struct {
	DocType      string          `cbor:"docType"`
	IssuerSigned cbor.RawMessage `cbor:"issuerSigned"`
	DeviceSigned cbor.RawMessage `cbor:"deviceSigned"`
}

type wireDeviceResponse struct {
	Version   string         `cbor:"version"`
	Documents []wireDocument `cbor:"documents,omitempty"`
	Status    uint64         `cbor:"status"`
}

// MarshalDeviceResponse builds and encodes a DeviceResponse (ISO/IEC
// 18013-5 §10.3.2/§10.3.3) carrying exactly doc — see the package doc
// comment for why this package never builds a multi-document one.
// Status is always 0 ("OK").
func MarshalDeviceResponse(doc Document) ([]byte, error) {
	if doc.DocType == "" {
		return nil, fmt.Errorf("oid4vpmdoc: marshal device response: doc_type is required")
	}
	issuerSignedBytes, err := doc.IssuerSigned.Marshal()
	if err != nil {
		return nil, fmt.Errorf("oid4vpmdoc: marshal device response: issuer_signed: %w", err)
	}
	deviceSignedBytes, err := doc.DeviceSigned.Marshal()
	if err != nil {
		return nil, fmt.Errorf("oid4vpmdoc: marshal device response: device_signed: %w", err)
	}

	wire := wireDeviceResponse{
		Version: deviceResponseVersion,
		Documents: []wireDocument{{
			DocType:      doc.DocType,
			IssuerSigned: issuerSignedBytes,
			DeviceSigned: deviceSignedBytes,
		}},
		Status: mdocResponseStatusOK,
	}
	b, err := cbor.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("oid4vpmdoc: marshal device response: %w", err)
	}
	return b, nil
}

// UnmarshalDeviceResponse decodes data as a DeviceResponse and returns
// its own single Document — Marshal's inverse. It performs no
// signature/MAC verification; use credential/mdoc.Verify/
// VerifyDeviceSignature/VerifyDeviceMAC for that. Returns an error if
// status isn't 0 ("OK") or documents doesn't have exactly one entry.
func UnmarshalDeviceResponse(data []byte) (Document, error) {
	var wire wireDeviceResponse
	if err := cbor.Unmarshal(data, &wire); err != nil {
		return Document{}, fmt.Errorf("oid4vpmdoc: unmarshal device response: %w", err)
	}
	if wire.Status != mdocResponseStatusOK {
		return Document{}, fmt.Errorf("oid4vpmdoc: unmarshal device response: status %d, want %d (OK)", wire.Status, mdocResponseStatusOK)
	}
	if len(wire.Documents) != 1 {
		return Document{}, fmt.Errorf("oid4vpmdoc: unmarshal device response: got %d documents, want exactly 1", len(wire.Documents))
	}

	d := wire.Documents[0]
	issuerSigned, err := mdoc.UnmarshalIssuerSigned(d.IssuerSigned)
	if err != nil {
		return Document{}, fmt.Errorf("oid4vpmdoc: unmarshal device response: issuer_signed: %w", err)
	}
	deviceSigned, err := mdoc.UnmarshalDeviceSigned(d.DeviceSigned)
	if err != nil {
		return Document{}, fmt.Errorf("oid4vpmdoc: unmarshal device response: device_signed: %w", err)
	}
	return Document{DocType: d.DocType, IssuerSigned: issuerSigned, DeviceSigned: deviceSigned}, nil
}
