package proximity

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// tag24 is RFC 8949 §3.4.5.1's "encoded CBOR data item" tag, which
// ISO/IEC 18013-5 uses for every #6.24(bstr .cbor X) in its CDDL.
const tag24 = 24

// MaxMessageBytes bounds every message this package decodes or
// decrypts — a SessionEstablishment, a SessionData, a DeviceEngagement
// or a decrypted DeviceRequest/DeviceResponse — before any CBOR work
// is done on it. Larger than credential/mdoc.MaxBytes and
// oid4vpmdoc.MaxBytes (1 MiB) since a proximity DeviceResponse can
// carry several documents, each with a portrait; this package passes
// its own ceiling down to them.
const MaxMessageBytes = 2 << 20 // 2 MiB

// nullHandover is the CBOR null Handover a QR code engagement uses
// (§9.1.5.1).
var nullHandover = cbor.RawMessage{0xf6}

var (
	encMode = mustEncMode()
	// sortedEncMode encodes the maps this package builds from Go maps
	// (ItemsRequest's nameSpaces) in a stable order, so the same request
	// always encodes to the same bytes.
	sortedEncMode = mustSortedEncMode()
	decMode       = mustDecMode()
)

func mustEncMode() cbor.EncMode {
	mode, err := cbor.EncOptions{}.EncMode()
	if err != nil {
		panic(fmt.Sprintf("proximity: build CBOR encoder: %v", err))
	}
	return mode
}

func mustSortedEncMode() cbor.EncMode {
	mode, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		panic(fmt.Sprintf("proximity: build CBOR encoder: %v", err))
	}
	return mode
}

func mustDecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{
		MaxArrayElements: 1 << 16,
		MaxMapPairs:      1 << 16,
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("proximity: build CBOR decoder: %v", err))
	}
	return mode
}

// wrapTag24 encodes b, already-encoded CBOR, as #6.24(bstr .cbor X).
func wrapTag24(b []byte) ([]byte, error) {
	return encMode.Marshal(cbor.Tag{Number: tag24, Content: b})
}

// unwrapTag24 decodes raw as #6.24(bstr) and returns the bstr's content.
func unwrapTag24(raw []byte) ([]byte, error) {
	var tag cbor.RawTag
	if err := decMode.Unmarshal(raw, &tag); err != nil {
		return nil, err
	}
	if tag.Number != tag24 {
		return nil, fmt.Errorf("tag %d, want %d", tag.Number, tag24)
	}
	var content []byte
	if err := decMode.Unmarshal(tag.Content, &content); err != nil {
		return nil, fmt.Errorf("tag 24 content: %w", err)
	}
	return content, nil
}
