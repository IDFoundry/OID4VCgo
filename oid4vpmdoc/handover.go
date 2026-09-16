package oid4vpmdoc

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// tag24 is CBOR tag 24, "encoded CBOR data item" (RFC 8949 §3.4.5.1) —
// ISO/IEC 18013-5 §9.1.5.1's own SessionTranscriptBytes is
// #6.24(bstr .cbor SessionTranscript).
const tag24 = 24

func wrapTag24(v any) ([]byte, error) {
	inner, err := cbor.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal tag 24 content: %w", err)
	}
	wrapped, err := cbor.Marshal(cbor.Tag{Number: tag24, Content: inner})
	if err != nil {
		return nil, fmt.Errorf("marshal tag 24: %w", err)
	}
	return wrapped, nil
}

// buildHandoverSessionTranscriptBytes wraps handoverType/info (either
// flow's own [...]HandoverInfo array) into
// [handoverType, sha256(CBOR(info))] and then into the full
// [null, null, Handover] SessionTranscript, tag-24-wrapped —
// the one piece both BuildSessionTranscriptBytes and
// BuildDCAPISessionTranscriptBytes share, since their own
// HandoverInfo shapes (and the calling code's own field validation)
// are the only thing that actually differs between the two flows.
func buildHandoverSessionTranscriptBytes(handoverType string, info []any) ([]byte, error) {
	infoBytes, err := cbor.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("marshal %sInfo: %w", handoverType, err)
	}
	sum := sha256.Sum256(infoBytes)

	handover := []any{handoverType, sum[:]}
	sessionTranscript := []any{nil, nil, handover}
	sessionTranscriptBytes, err := wrapTag24(sessionTranscript)
	if err != nil {
		return nil, err
	}
	return sessionTranscriptBytes, nil
}

// HandoverParams is the input to BuildSessionTranscriptBytes — the
// Authorization Request fields Appendix B.2.6.1's own
// OpenID4VPHandoverInfo array needs. "Unless otherwise stated, the
// values of client_id, nonce, redirect_uri, and response_uri request
// parameters referenced above MUST be obtained from the Authorization
// Request query parameters if the request is unsigned, or from the
// signed Request Object if the request is signed" — verifier's own
// redirect-flow requests are always signed (HAIP §5.1), so these come
// from the Request Object's own claims.
type HandoverParams struct {
	// ClientID is the Authorization Request's own "client_id"
	// (Client Identifier Prefix included). REQUIRED.
	ClientID string

	// Nonce is the Authorization Request's own "nonce". REQUIRED.
	Nonce string

	// ResponseURI is whichever of "redirect_uri"/"response_uri" the
	// Authorization Request carried. REQUIRED. This repo's own
	// verifier package always uses "response_uri" (direct_post.jwt,
	// HAIP §5.1's own mandatory response encryption).
	ResponseURI string

	// ResponseEncryptionJWKThumbprint is the RFC 7638 SHA-256 JWK
	// Thumbprint, as raw bytes (NOT base64url text — a CBOR bstr,
	// per Appendix B.2.6.1's own "jwkThumbprint = bstr"), of the
	// Verifier's own public key used to encrypt the response.
	// REQUIRED whenever the response is encrypted — direct_post.jwt,
	// this package's only supported response mode, always encrypts —
	// so this is effectively always required in practice; nil is
	// legal only for an unencrypted response, which this repo's own
	// verifier/wallet packages never produce.
	ResponseEncryptionJWKThumbprint []byte
}

// BuildSessionTranscriptBytes builds SessionTranscriptBytes (ISO/IEC
// 18013-5 §9.1.5.1's own #6.24(bstr .cbor SessionTranscript)) for the
// OID4VP redirect flow (Appendix B.2.6.1): DeviceEngagementBytes and
// EReaderKeyBytes are both CBOR null, and Handover is the
// OpenID4VPHandover structure —
// ["OpenID4VPHandover", sha256(CBOR(OpenID4VPHandoverInfo))] where
// OpenID4VPHandoverInfo = [client_id, nonce, jwkThumbprint,
// response_uri]. Verified byte-for-byte against Appendix B.2.6.1's
// own worked hex example.
func BuildSessionTranscriptBytes(p HandoverParams) ([]byte, error) {
	if p.ClientID == "" {
		return nil, fmt.Errorf("oid4vpmdoc: build session transcript: client_id is required")
	}
	if p.Nonce == "" {
		return nil, fmt.Errorf("oid4vpmdoc: build session transcript: nonce is required")
	}
	if p.ResponseURI == "" {
		return nil, fmt.Errorf("oid4vpmdoc: build session transcript: response_uri is required")
	}

	var jwkThumbprint any
	if p.ResponseEncryptionJWKThumbprint != nil {
		jwkThumbprint = p.ResponseEncryptionJWKThumbprint
	}
	info := []any{p.ClientID, p.Nonce, jwkThumbprint, p.ResponseURI}
	sessionTranscriptBytes, err := buildHandoverSessionTranscriptBytes("OpenID4VPHandover", info)
	if err != nil {
		return nil, fmt.Errorf("oid4vpmdoc: build session transcript: %w", err)
	}
	return sessionTranscriptBytes, nil
}

// DCAPIHandoverParams is the input to BuildDCAPISessionTranscriptBytes
// — the DC API request fields Appendix B.2.6.2's own
// OpenID4VPDCAPIHandoverInfo array needs.
type DCAPIHandoverParams struct {
	// Origin is the Verifier's own Origin (Appendix A.2), as
	// authenticated by the user agent/platform delivering the request
	// — NOT prefixed with "origin:" (that prefix is only for the
	// response's own audience value, e.g. a Key Binding JWT's "aud";
	// see Appendix A.4). REQUIRED.
	Origin string

	// Nonce is the request's own "nonce" parameter. REQUIRED.
	Nonce string

	// ResponseEncryptionJWKThumbprint is the RFC 7638 SHA-256 JWK
	// Thumbprint, as raw bytes, of the Verifier's own public key used
	// to encrypt the response — REQUIRED for the dc_api.jwt Response
	// Mode (this repo's own verifier/wallet packages' only supported
	// one, HAIP 1.0 §5.2's own mandate), nil only for the unencrypted
	// dc_api Response Mode ("If the Response Mode is dc_api, the third
	// element MUST be null").
	ResponseEncryptionJWKThumbprint []byte
}

// BuildDCAPISessionTranscriptBytes builds SessionTranscriptBytes for
// OpenID4VP over the Digital Credentials API (Appendix B.2.6.2):
// DeviceEngagementBytes and EReaderKeyBytes are both CBOR null, and
// Handover is the OpenID4VPDCAPIHandover structure —
// ["OpenID4VPDCAPIHandover", sha256(CBOR(OpenID4VPDCAPIHandoverInfo))]
// where OpenID4VPDCAPIHandoverInfo = [origin, nonce, jwkThumbprint].
// Verified byte-for-byte against Appendix B.2.6.2's own worked hex
// example. BuildSessionTranscriptBytes is this function's redirect-flow
// counterpart (Appendix B.2.6.1) — the two Handover structures aren't
// interchangeable: a Presentation built for one flow will fail
// DeviceSigned verification under the other.
func BuildDCAPISessionTranscriptBytes(p DCAPIHandoverParams) ([]byte, error) {
	if p.Origin == "" {
		return nil, fmt.Errorf("oid4vpmdoc: build dc api session transcript: origin is required")
	}
	if p.Nonce == "" {
		return nil, fmt.Errorf("oid4vpmdoc: build dc api session transcript: nonce is required")
	}

	var jwkThumbprint any
	if p.ResponseEncryptionJWKThumbprint != nil {
		jwkThumbprint = p.ResponseEncryptionJWKThumbprint
	}
	info := []any{p.Origin, p.Nonce, jwkThumbprint}
	sessionTranscriptBytes, err := buildHandoverSessionTranscriptBytes("OpenID4VPDCAPIHandover", info)
	if err != nil {
		return nil, fmt.Errorf("oid4vpmdoc: build dc api session transcript: %w", err)
	}
	return sessionTranscriptBytes, nil
}
