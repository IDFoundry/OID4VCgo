package oid4vpmdoc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestBuildSessionTranscriptBytesMatchesWorkedExample checks
// BuildSessionTranscriptBytes's own OpenID4VPHandoverInfo encoding
// against Appendix B.2.6.1's own worked hex example byte-for-byte
// (the client_id/nonce/jwkThumbprint/response_uri values below are
// exactly that example's own — extracted by parsing its own published
// hex dump, not retyped by hand).
func TestBuildSessionTranscriptBytesMatchesWorkedExample(t *testing.T) {
	wantInfoBytes, err := hex.DecodeString(
		"847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578" +
			"633767426b786a7831726463397564527276654b7653734a49713830617" +
			"66c58654c4868477771744158204283ec927ae0f208daaa2d026a814f2b" +
			"22dca52cf85ffa8f3f8626c6bd669047781c68747470733a2f2f6578616" +
			"d706c652e636f6d2f726573706f6e7365")
	if err != nil {
		t.Fatalf("decode worked example hex: %v", err)
	}
	jwkThumbprint, err := hex.DecodeString("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047")
	if err != nil {
		t.Fatalf("decode jwk thumbprint hex: %v", err)
	}
	if len(jwkThumbprint) != 32 {
		t.Fatalf("jwkThumbprint length = %d, want 32", len(jwkThumbprint))
	}

	sessionTranscriptBytes, err := BuildSessionTranscriptBytes(HandoverParams{
		ClientID:                        "x509_san_dns:example.com",
		Nonce:                           "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
		ResponseURI:                     "https://example.com/response",
		ResponseEncryptionJWKThumbprint: jwkThumbprint,
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}

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
	if handover[0] != "OpenID4VPHandover" {
		t.Errorf("Handover[0] = %v, want %q", handover[0], "OpenID4VPHandover")
	}

	wantHashArr := sha256.Sum256(wantInfoBytes)
	gotHash, ok := handover[1].([]byte)
	if !ok || !bytes.Equal(gotHash, wantHashArr[:]) {
		t.Errorf("Handover[1] (OpenID4VPHandoverInfoHash) = %x, want %x", gotHash, wantHashArr)
	}
}

func TestBuildSessionTranscriptBytesRejectsMissingFields(t *testing.T) {
	valid := HandoverParams{ClientID: "x509_hash:abc", Nonce: "n-1", ResponseURI: "https://verifier.example.com/response"}
	cases := map[string]func(*HandoverParams){
		"missing client_id":    func(p *HandoverParams) { p.ClientID = "" },
		"missing nonce":        func(p *HandoverParams) { p.Nonce = "" },
		"missing response_uri": func(p *HandoverParams) { p.ResponseURI = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := valid
			mutate(&p)
			if _, err := BuildSessionTranscriptBytes(p); err == nil {
				t.Fatalf("BuildSessionTranscriptBytes(%s) = nil error, want error", name)
			}
		})
	}
}

func TestBuildSessionTranscriptBytesNilThumbprintWhenUnencrypted(t *testing.T) {
	sessionTranscriptBytes, err := BuildSessionTranscriptBytes(HandoverParams{
		ClientID: "x509_hash:abc", Nonce: "n-1", ResponseURI: "https://verifier.example.com/response",
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	var sessionTranscript []any
	if err := unwrapTag24(sessionTranscriptBytes, &sessionTranscript); err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	handover := sessionTranscript[2].([]any)
	if handover[0] != "OpenID4VPHandover" {
		t.Fatalf("Handover[0] = %v", handover[0])
	}
	// Sanity: still produces a 32-byte hash even with a nil jwkThumbprint
	// baked into OpenID4VPHandoverInfo.
	if hash, ok := handover[1].([]byte); !ok || len(hash) != 32 {
		t.Errorf("Handover[1] = %v, want a 32-byte hash", handover[1])
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
