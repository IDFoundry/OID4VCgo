package readerauth

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// tag24 is RFC 8949 §3.4.5.1's "encoded CBOR data item" tag, which
// ISO/IEC 18013-5 uses for every #6.24(bstr .cbor X) in its CDDL.
const tag24 = 24

// encMode encodes the arrays below. They hold only text strings and
// already-encoded items, so every deterministic profile encodes them
// to the same bytes as this default one.
var encMode = func() cbor.EncMode {
	mode, err := cbor.EncOptions{}.EncMode()
	if err != nil {
		panic(fmt.Sprintf("readerauth: build CBOR encoder: %v", err))
	}
	return mode
}()

// AuthenticationBytes is ISO/IEC 18013-5 §9.1.4's
// ReaderAuthenticationBytes, #6.24(bstr .cbor ["ReaderAuthentication",
// SessionTranscript, ItemsRequestBytes]): what a DocRequest's
// readerAuth signs, detached. sessionTranscript is the encoded
// SessionTranscript itself, not its tag-24 SessionTranscriptBytes;
// itemsRequestBytes is the tagged ItemsRequestBytes as received, which
// is inserted as it is, never re-encoded.
func AuthenticationBytes(sessionTranscript, itemsRequestBytes []byte) ([]byte, error) {
	if len(sessionTranscript) == 0 {
		return nil, errors.New("readerauth: no session transcript")
	}
	if len(itemsRequestBytes) == 0 {
		return nil, errors.New("readerauth: no ItemsRequestBytes")
	}
	return wrap("ReaderAuthentication", []any{
		"ReaderAuthentication", cbor.RawMessage(sessionTranscript), cbor.RawMessage(itemsRequestBytes),
	})
}

// AuthenticationAllBytes is the second edition's
// ReaderAuthenticationAllBytes, #6.24(bstr .cbor
// ["ReaderAuthenticationAll", SessionTranscript, [* ItemsRequestBytes],
// DeviceRequestInfoBytes / null]): what a readerAuthAll signs,
// detached. itemsRequestBytes are every DocRequest's ItemsRequestBytes
// in the request's order, and deviceRequestInfoBytes the tagged
// DeviceRequestInfoBytes as received, or nil for a request without
// one, which is encoded as null. Each is inserted as it is, so unknown
// fields and the reader's map order stay signed.
func AuthenticationAllBytes(sessionTranscript []byte, itemsRequestBytes [][]byte, deviceRequestInfoBytes []byte) ([]byte, error) {
	if len(sessionTranscript) == 0 {
		return nil, errors.New("readerauth: no session transcript")
	}
	items := make([]any, len(itemsRequestBytes))
	for i, b := range itemsRequestBytes {
		if len(b) == 0 {
			return nil, fmt.Errorf("readerauth: no ItemsRequestBytes for document request %d", i)
		}
		items[i] = cbor.RawMessage(b)
	}
	var info any
	if deviceRequestInfoBytes != nil {
		if len(deviceRequestInfoBytes) == 0 {
			return nil, errors.New("readerauth: empty DeviceRequestInfoBytes")
		}
		info = cbor.RawMessage(deviceRequestInfoBytes)
	}
	return wrap("ReaderAuthenticationAll", []any{
		"ReaderAuthenticationAll", cbor.RawMessage(sessionTranscript), items, info,
	})
}

// wrap encodes authentication and wraps it as #6.24(bstr).
func wrap(name string, authentication []any) ([]byte, error) {
	inner, err := encMode.Marshal(authentication)
	if err != nil {
		return nil, fmt.Errorf("readerauth: encode %s: %w", name, err)
	}
	out, err := encMode.Marshal(cbor.Tag{Number: tag24, Content: inner})
	if err != nil {
		return nil, fmt.Errorf("readerauth: encode %sBytes: %w", name, err)
	}
	return out, nil
}
