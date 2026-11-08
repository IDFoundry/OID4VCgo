package mdocdcapi

import (
	"crypto/sha256"
	"fmt"
	"net/url"

	"github.com/fxamacker/cbor/v2"
	"github.com/idfoundry/oid4vcgo/internal/strictcbor"
	"github.com/idfoundry/oid4vcgo/internal/weborigin"
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

// decMode decodes what a wallet receives: a duplicate map key is an
// error, and nesting and sizes are bounded.
var decMode = func() strictcbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
		// A struct field matches only its exact key: "DocType" isn't
		// "docType".
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
		MaxNestedLevels:   16,
		MaxArrayElements:  1024,
		MaxMapPairs:       1024,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("mdocdcapi: build CBOR decoder: %v", err))
	}
	return strictcbor.Wrap(mode)
}()

// encryptedResponseDecMode decodes an EncryptedResponse as decMode
// does, but refuses members Annex C.3 doesn't define and any tag: it
// holds only a text string and two byte strings, so either means it
// isn't one, and a tag decMode would drop could make another text
// read as "dcapi".
var encryptedResponseDecMode = func() strictcbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
		MaxNestedLevels:   4,
		MaxArrayElements:  16, // the library's least; toarray takes exactly two
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		TagsMd:            cbor.TagsForbidden,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("mdocdcapi: build CBOR decoder: %v", err))
	}
	return strictcbor.Wrap(mode)
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
// or user info — the form the browser gives the mdoc. It's the wallet's
// check of the origin its platform reports, which the session
// transcript binds as given; a Verifier's origins are checked to be
// spelled as the browser gives them (weborigin.Check) too.
func checkOrigin(origin string) error {
	u, err := url.Parse(origin)
	switch {
	case err != nil:
		return fmt.Errorf("mdocdcapi: origin %q isn't a URL: %w", origin, err)
	case u.Scheme == "" || u.Host == "":
		return fmt.Errorf("mdocdcapi: origin %q needs a scheme and a host", origin)
	case weborigin.Extra(origin, u) != "":
		return fmt.Errorf("mdocdcapi: origin %q has %s: an origin is a scheme, host and optional port only", origin, weborigin.Extra(origin, u))
	}
	return nil
}
