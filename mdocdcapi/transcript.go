package mdocdcapi

import (
	"crypto/sha256"
	"fmt"
	"net/url"

	"github.com/fxamacker/cbor/v2"
)

// tag24 is CBOR tag 24, an encoded CBOR data item (RFC 8949 §3.4.5.1).
const tag24 = 24

// encMode encodes deterministically (RFC 8949 §4.2.1), so a structure
// this package signs or hashes has one encoding.
var encMode = func() cbor.EncMode {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("mdocdcapi: build CBOR encoder: %v", err))
	}
	return mode
}()

// wrapTag24 is #6.24(bstr .cbor v).
func wrapTag24(v any) ([]byte, error) {
	inner, err := encMode.Marshal(v)
	if err != nil {
		return nil, err
	}
	return encMode.Marshal(cbor.Tag{Number: tag24, Content: inner})
}

// sessionTranscript is Annex C.5's SessionTranscript, CBOR encoded:
//
//	[null, null, ["dcapi", SHA-256(CBOR([Base64EncryptionInfo, SerializedOrigin]))]]
//
// It is HPKE's info for the response, and what device and reader
// authentication sign; sessionTranscriptBytes is the tag 24 form
// credential/mdoc's device authentication takes.
func sessionTranscript(base64EncryptionInfo, origin string) ([]byte, error) {
	dcapiInfo, err := encMode.Marshal([]any{base64EncryptionInfo, origin})
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: encode dcapiInfo: %w", err)
	}
	hash := sha256.Sum256(dcapiInfo)
	transcript, err := encMode.Marshal([]any{nil, nil, []any{"dcapi", hash[:]}})
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: encode SessionTranscript: %w", err)
	}
	return transcript, nil
}

// sessionTranscriptBytes is #6.24(bstr .cbor SessionTranscript).
func sessionTranscriptBytes(transcript []byte) ([]byte, error) {
	return encMode.Marshal(cbor.Tag{Number: tag24, Content: transcript})
}

// checkOrigin requires origin to be a serialized web origin
// (https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin):
// a scheme, a host and an optional port, with no path, query, fragment
// or user info — the form the browser gives the mdoc.
func checkOrigin(origin string) error {
	u, err := url.Parse(origin)
	switch {
	case err != nil:
		return fmt.Errorf("mdocdcapi: origin %q isn't a URL: %w", origin, err)
	case u.Scheme == "" || u.Host == "":
		return fmt.Errorf("mdocdcapi: origin %q needs a scheme and a host", origin)
	case u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "":
		return fmt.Errorf("mdocdcapi: origin %q must be a scheme, host and optional port only (no trailing slash)", origin)
	}
	return nil
}
