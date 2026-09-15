package mdoc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// encMode/decMode encode time.Time as CBOR tag 0 (tdate, RFC 8949
// §3.4.1) with an RFC 3339 string body — ValidityInfo's "signed",
// "validFrom", "validUntil" and "expectedUpdate" members (§12.3.4) are
// tdate, distinct from the tag-1004 full-date strings a namespace's own
// data elements may use (which this package never constructs or
// inspects — see the package doc comment).
var (
	encMode = mustEncMode()
	decMode = mustDecMode()
)

func mustEncMode() cbor.EncMode {
	mode, err := cbor.EncOptions{
		Time:    cbor.TimeRFC3339,
		TimeTag: cbor.EncTagRequired,
	}.EncMode()
	if err != nil {
		panic(fmt.Sprintf("mdoc: build CBOR encoder: %v", err))
	}
	return mode
}

func mustDecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{
		TimeTag: cbor.DecTagRequired,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("mdoc: build CBOR decoder: %v", err))
	}
	return mode
}

// tag24 is CBOR tag 24, "encoded CBOR data item" (RFC 8949 §3.4.5.1),
// used throughout §10.3.3 (IssuerSignedItemBytes, MobileSecurityObjectBytes,
// DeviceNameSpacesBytes) to embed one CBOR data item as a byte string
// inside another, so it can be hashed or signed as an opaque, uniquely
// re-encodable unit.
const tag24 = 24

// wrapTag24 CBOR-encodes v and wraps the result as #6.24(bstr .cbor v).
func wrapTag24(v interface{}) ([]byte, error) {
	inner, err := encMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("mdoc: marshal tag 24 content: %w", err)
	}
	wrapped, err := encMode.Marshal(cbor.Tag{Number: tag24, Content: inner})
	if err != nil {
		return nil, fmt.Errorf("mdoc: marshal tag 24: %w", err)
	}
	return wrapped, nil
}

// unwrapTag24 decodes a #6.24(bstr .cbor v) value produced by wrapTag24
// into v.
func unwrapTag24(data []byte, v interface{}) error {
	var t cbor.Tag
	if err := decMode.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("mdoc: unmarshal tag 24: %w", err)
	}
	if t.Number != tag24 {
		return fmt.Errorf("mdoc: expected CBOR tag %d, got %d", tag24, t.Number)
	}
	inner, ok := t.Content.([]byte)
	if !ok {
		return fmt.Errorf("mdoc: tag %d content is not a byte string", tag24)
	}
	if err := decMode.Unmarshal(inner, v); err != nil {
		return fmt.Errorf("mdoc: unmarshal tag 24 content: %w", err)
	}
	return nil
}
