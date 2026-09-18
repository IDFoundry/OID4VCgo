package oid4vpmdoc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// handoverAndSessionTranscript unwraps sessionTranscriptBytes and
// returns its own Handover element, after checking the shape every
// worked-example/nil-thumbprint test below needs: a 3-element
// SessionTranscript with null DeviceEngagementBytes/EReaderKeyBytes
// and a 2-element Handover naming wantHandoverType.
func handoverAndSessionTranscript(t *testing.T, sessionTranscriptBytes []byte, wantHandoverType string) []any {
	t.Helper()
	var sessionTranscript []any
	if err := unwrapTag24(sessionTranscriptBytes, &sessionTranscript); err != nil {
		t.Fatalf("unwrap SessionTranscriptBytes: %v", err)
	}
	if len(sessionTranscript) != 3 {
		t.Fatalf("SessionTranscript has %d elements, want 3", len(sessionTranscript))
	}
	if sessionTranscript[0] != nil || sessionTranscript[1] != nil {
		t.Errorf("SessionTranscript[0]/[1] = %v/%v, want nil/nil (DeviceEngagementBytes/EReaderKeyBytes)", sessionTranscript[0], sessionTranscript[1])
	}
	handover, ok := sessionTranscript[2].([]any)
	if !ok || len(handover) != 2 {
		t.Fatalf("SessionTranscript[2] (Handover) = %v, want a 2-element array", sessionTranscript[2])
	}
	if handover[0] != wantHandoverType {
		t.Errorf("Handover[0] = %v, want %q", handover[0], wantHandoverType)
	}
	return handover
}

// assertHandoverSessionTranscript checks sessionTranscriptBytes's own
// Handover hash matches sha256(wantInfoBytes) — the piece
// TestBuildSessionTranscriptBytesMatchesWorkedExample and
// TestBuildDCAPISessionTranscriptBytesMatchesWorkedExample share,
// since their own worked examples differ only in HandoverInfo's own
// shape and the resulting hash.
func assertHandoverSessionTranscript(t *testing.T, sessionTranscriptBytes []byte, wantHandoverType string, wantInfoBytes []byte) {
	t.Helper()
	handover := handoverAndSessionTranscript(t, sessionTranscriptBytes, wantHandoverType)
	wantHashArr := sha256.Sum256(wantInfoBytes)
	gotHash, ok := handover[1].([]byte)
	if !ok || !bytes.Equal(gotHash, wantHashArr[:]) {
		t.Errorf("Handover[1] (%sInfoHash) = %x, want %x", wantHandoverType, gotHash, wantHashArr)
	}
}

// assertHandoverHash32Bytes checks sessionTranscriptBytes's own
// Handover hash is present and 32 bytes long, without checking its
// exact value — the shape every "...NilThumbprintWhenUnencrypted"
// test below needs: a nil jwkThumbprint still bakes into a valid
// 32-byte SHA-256 hash inside HandoverInfo.
func assertHandoverHash32Bytes(t *testing.T, sessionTranscriptBytes []byte, wantHandoverType string) {
	t.Helper()
	handover := handoverAndSessionTranscript(t, sessionTranscriptBytes, wantHandoverType)
	if hash, ok := handover[1].([]byte); !ok || len(hash) != 32 {
		t.Errorf("Handover[1] = %v, want a 32-byte hash", handover[1])
	}
}

// mustDecodeHex decodes hexStr (a worked example's own published hex
// dump, not retyped by hand), failing the test on error.
func mustDecodeHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

// exampleJWKThumbprint is the RFC 7638 JWK Thumbprint both Appendix
// B.2.6.1's and Appendix B.2.6.2's own published worked examples
// happen to reuse verbatim.
func exampleJWKThumbprint(t *testing.T) []byte {
	t.Helper()
	thumbprint := mustDecodeHex(t, "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047")
	if len(thumbprint) != 32 {
		t.Fatalf("jwkThumbprint length = %d, want 32", len(thumbprint))
	}
	return thumbprint
}

// rejectsMissingFields runs one subtest per entry in cases, each
// mutating a copy of valid and asserting build rejects the result —
// the shape both TestBuildSessionTranscriptBytesRejectsMissingFields
// and TestBuildDCAPISessionTranscriptBytesRejectsMissingFields need,
// generic over their own distinct Params types.
func rejectsMissingFields[P any](t *testing.T, buildName string, valid P, cases map[string]func(*P), build func(P) ([]byte, error)) {
	t.Helper()
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := valid
			mutate(&p)
			if _, err := build(p); err == nil {
				t.Fatalf("%s(%s) = nil error, want error", buildName, name)
			}
		})
	}
}

// TestBuildSessionTranscriptBytesMatchesWorkedExample checks
// BuildSessionTranscriptBytes's own OpenID4VPHandoverInfo encoding
// against Appendix B.2.6.1's own worked hex example byte-for-byte
// (the client_id/nonce/jwkThumbprint/response_uri values below are
// exactly that example's own — extracted by parsing its own published
// hex dump, not retyped by hand).
func TestBuildSessionTranscriptBytesMatchesWorkedExample(t *testing.T) {
	wantInfoBytes := mustDecodeHex(t, "847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767426b786a7831726463397564527276654b7653734a49713830617"+"66c58654c4868477771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365")
	jwkThumbprint := exampleJWKThumbprint(t)

	sessionTranscriptBytes, err := BuildSessionTranscriptBytes(HandoverParams{
		ClientID:                        "x509_san_dns:example.com",
		Nonce:                           "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
		ResponseURI:                     "https://example.com/response",
		ResponseEncryptionJWKThumbprint: jwkThumbprint,
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	assertHandoverSessionTranscript(t, sessionTranscriptBytes, "OpenID4VPHandover", wantInfoBytes)
}

func TestBuildSessionTranscriptBytesRejectsMissingFields(t *testing.T) {
	valid := HandoverParams{ClientID: "x509_hash:abc", Nonce: "n-1", ResponseURI: "https://verifier.example.com/response"}
	cases := map[string]func(*HandoverParams){
		"missing client_id":    func(p *HandoverParams) { p.ClientID = "" },
		"missing nonce":        func(p *HandoverParams) { p.Nonce = "" },
		"missing response_uri": func(p *HandoverParams) { p.ResponseURI = "" },
	}
	rejectsMissingFields(t, "BuildSessionTranscriptBytes", valid, cases, BuildSessionTranscriptBytes)
}

func TestBuildSessionTranscriptBytesNilThumbprintWhenUnencrypted(t *testing.T) {
	sessionTranscriptBytes, err := BuildSessionTranscriptBytes(HandoverParams{
		ClientID: "x509_hash:abc", Nonce: "n-1", ResponseURI: "https://verifier.example.com/response",
		ResponseIsUnencrypted: true,
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	assertHandoverHash32Bytes(t, sessionTranscriptBytes, "OpenID4VPHandover")
}

// TestBuildSessionTranscriptBytesRejectsMissingThumbprint is the
// regression test for a real bug found in a repo-wide security
// review: a caller that simply forgot to set
// ResponseEncryptionJWKThumbprint (the easiest mistake to make, since
// nothing else about this call signals it's missing) used to get a
// silently-accepted SessionTranscript with a nil jwkThumbprint binding
// instead of an error — weakening the anti-relay binding for exactly
// the case (an encrypted response) the doc comment says it's
// mandatory. Omitting both the thumbprint and the explicit
// ResponseIsUnencrypted opt-out must now fail.
func TestBuildSessionTranscriptBytesRejectsMissingThumbprint(t *testing.T) {
	_, err := BuildSessionTranscriptBytes(HandoverParams{
		ClientID: "x509_hash:abc", Nonce: "n-1", ResponseURI: "https://verifier.example.com/response",
	})
	if err == nil {
		t.Fatal("BuildSessionTranscriptBytes = nil error, want error (thumbprint missing, ResponseIsUnencrypted not set)")
	}
}

// TestBuildDCAPISessionTranscriptBytesMatchesWorkedExample checks
// BuildDCAPISessionTranscriptBytes's own OpenID4VPDCAPIHandoverInfo
// encoding against Appendix B.2.6.2's own worked hex example
// byte-for-byte (the origin/nonce/jwkThumbprint values below are
// exactly that example's own — extracted by parsing its own published
// hex dump, not retyped by hand).
func TestBuildDCAPISessionTranscriptBytesMatchesWorkedExample(t *testing.T) {
	wantInfoBytes := mustDecodeHex(t, "837368747470733a2f2f6578616d706c652e636f6d782b6578633767426b786a7831726463397564527276654b7653734a4971383061766c58654c4868477771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047")
	jwkThumbprint := exampleJWKThumbprint(t)

	sessionTranscriptBytes, err := BuildDCAPISessionTranscriptBytes(DCAPIHandoverParams{
		Origin:                          "https://example.com",
		Nonce:                           "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
		ResponseEncryptionJWKThumbprint: jwkThumbprint,
	})
	if err != nil {
		t.Fatalf("BuildDCAPISessionTranscriptBytes: %v", err)
	}
	assertHandoverSessionTranscript(t, sessionTranscriptBytes, "OpenID4VPDCAPIHandover", wantInfoBytes)
}

func TestBuildDCAPISessionTranscriptBytesRejectsMissingFields(t *testing.T) {
	valid := DCAPIHandoverParams{Origin: "https://verifier.example.com", Nonce: "n-1"}
	cases := map[string]func(*DCAPIHandoverParams){
		"missing origin": func(p *DCAPIHandoverParams) { p.Origin = "" },
		"missing nonce":  func(p *DCAPIHandoverParams) { p.Nonce = "" },
	}
	rejectsMissingFields(t, "BuildDCAPISessionTranscriptBytes", valid, cases, BuildDCAPISessionTranscriptBytes)
}

// TestBuildDCAPISessionTranscriptBytesNilThumbprintWhenUnencrypted
// mirrors §Appendix B.2.6.2's own "If the Response Mode is dc_api,
// the third element MUST be null" — the unencrypted dc_api Response
// Mode this repo's verifier/wallet packages never produce (HAIP 1.0
// §5.2 mandates dc_api.jwt), but the builder still accepts.
func TestBuildDCAPISessionTranscriptBytesNilThumbprintWhenUnencrypted(t *testing.T) {
	sessionTranscriptBytes, err := BuildDCAPISessionTranscriptBytes(DCAPIHandoverParams{
		Origin: "https://verifier.example.com", Nonce: "n-1",
		ResponseIsUnencrypted: true,
	})
	if err != nil {
		t.Fatalf("BuildDCAPISessionTranscriptBytes: %v", err)
	}
	assertHandoverHash32Bytes(t, sessionTranscriptBytes, "OpenID4VPDCAPIHandover")
}

// TestBuildDCAPISessionTranscriptBytesRejectsMissingThumbprint mirrors
// TestBuildSessionTranscriptBytesRejectsMissingThumbprint for the
// DC API builder — see that test's own doc comment for the bug this
// is the regression test for.
func TestBuildDCAPISessionTranscriptBytesRejectsMissingThumbprint(t *testing.T) {
	_, err := BuildDCAPISessionTranscriptBytes(DCAPIHandoverParams{
		Origin: "https://verifier.example.com", Nonce: "n-1",
	})
	if err == nil {
		t.Fatal("BuildDCAPISessionTranscriptBytes = nil error, want error (thumbprint missing, ResponseIsUnencrypted not set)")
	}
}

func unwrapTag24(data []byte, v any) error {
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Number != tag24 {
		return fmt.Errorf("expected CBOR tag %d, got %d", tag24, tag.Number)
	}
	inner, ok := tag.Content.([]byte)
	if !ok {
		return fmt.Errorf("tag %d content is not a byte string", tag24)
	}
	return cbor.Unmarshal(inner, v)
}
