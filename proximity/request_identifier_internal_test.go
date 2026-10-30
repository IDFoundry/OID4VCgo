package proximity

import (
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// A request naming a data element with a control or bidirectional
// formatting character, which could forge a line of the consent
// screen, is refused as invalid.
func TestParseDeviceRequest_RefusesForgedIdentifiers(t *testing.T) {
	request := func(docType, ns, el string) []byte {
		t.Helper()
		items, err := cbor.Marshal(map[string]any{"docType": docType, "nameSpaces": map[string]any{ns: map[string]bool{el: false}}})
		if err != nil {
			t.Fatal(err)
		}
		tagged, err := cbor.Marshal(cbor.Tag{Number: 24, Content: items})
		if err != nil {
			t.Fatal(err)
		}
		b, err := cbor.Marshal(map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": cbor.RawMessage(tagged)}}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := ParseDeviceRequest(request("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "age_over_18")); err != nil {
		t.Fatalf("a plain request: %v", err)
	}
	for name, b := range map[string][]byte{
		"element with a newline":        request("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "age_over_18\nRetain: no"),
		"namespace with an override":    request("org.iso.18013.5.1.mDL", "org.iso\u202e.18013.5.1", "age_over_18"),
		"docType with a control char":   request("org.iso.18013.5.1.mDL\x00", "org.iso.18013.5.1", "age_over_18"),
		"element with a line separator": request("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "age_over_18\u2028Retain: no"),
		"element with a para separator": request("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "age_over_18\u2029portrait: not shared"),
		"element with a zero-width sp":  request("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "family\u200bname"),
		"element with a tag character":  request("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "family_name\U000e0041"),
	} {
		if _, err := ParseDeviceRequest(b); !errors.Is(err, ErrCBORValidation) {
			t.Errorf("%s: %v, want a validation error", name, err)
		}
	}
}
