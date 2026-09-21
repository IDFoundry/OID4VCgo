package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/idfoundry/oid4vcgo/internal/ecdsafixed"
)

// Alg identifies a JWS signature algorithm this package supports.
type Alg string

const (
	// ES256 is ECDSA using P-256 and SHA-256 (RFC 7518 §3.4).
	ES256 Alg = "ES256"

	// EdDSA is pure EdDSA over Ed25519 (RFC 8037 §3.1) — the digest
	// parameter Sign/Verify take is the raw signing input, not a
	// pre-hash, since Ed25519 signs the message itself.
	EdDSA Alg = "EdDSA"
)

// IsSupported reports whether alg is one Sign/Verify actually
// implement — the same set signBytes/verifyBytes switch on. Every
// jose.Alg-typed configuration field across this module
// (verifier.Config.SigningAlg, wallet.Config.ProofSigningAlg,
// issuer.SDJWTSigner.Alg) is otherwise only checked for non-empty at
// construction time, not against this set: jose.Alg can't be
// exported for a caller to get real compile-time enum closure (an
// internal package), and oid4vci.ES256/EdDSA — the untyped string
// constants that work around that — are assignable from any string,
// so they give no protection against a typo or the wrong constant
// either. IsSupported lets each of those construction-time checks
// catch that case explicitly instead of only discovering it the first
// time Sign/Verify actually runs.
func IsSupported(alg Alg) bool {
	switch alg {
	case ES256, EdDSA:
		return true
	default:
		return false
	}
}

var b64 = base64.RawURLEncoding

// MaxCompactBytes bounds how large a compact JWS Verify/DecodeUnverified
// will attempt to parse, to avoid doing unbounded base64url-decode and
// JSON-unmarshal work on attacker-supplied input before any signature
// has been checked (Verify) — or without one ever being checked at all
// (DecodeUnverified, whose whole point is reading claims before the
// verifying key is even known). Matches this repo's own existing
// "bounded external response" convention
// (wallet/pre_authorized_code.go's own maxTokenResponseBytes) rather
// than inventing a new number. A caller whose accepted input can
// legitimately scale beyond it (e.g. a Status List Token, whose
// payload embeds a population-sized compressed bit array) should call
// VerifyMax/DecodeUnverifiedMax with its own configured ceiling
// instead.
const MaxCompactBytes = 1 << 16 // 64 KiB

// Sign builds a compact-serialized JWS —
// base64url(header).base64url(payload).base64url(signature) — over
// payload, using signer under alg. header must not set "alg"; Sign
// always sets it from alg, overwriting anything header supplies.
// signer's public key type must match alg: a P-256 *ecdsa.PublicKey for
// ES256, an ed25519.PublicKey for EdDSA.
func Sign(alg Alg, signer crypto.Signer, header map[string]any, payload []byte) (string, error) {
	h := make(map[string]any, len(header)+1)
	for k, v := range header {
		h[k] = v
	}
	h["alg"] = string(alg)

	headerJSON, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("jose: marshal header: %w", err)
	}
	signingInput := b64.EncodeToString(headerJSON) + "." + b64.EncodeToString(payload)

	sig, err := signBytes(alg, signer, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.EncodeToString(sig), nil
}

func signBytes(alg Alg, signer crypto.Signer, signingInput []byte) ([]byte, error) {
	switch alg {
	case ES256:
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("jose: ES256 requires a P-256 signer")
		}
		digest := sha256.Sum256(signingInput)
		der, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("jose: sign: %w", err)
		}
		return ecdsafixed.ToFixed(der, 32)
	case EdDSA:
		if _, ok := signer.Public().(ed25519.PublicKey); !ok {
			return nil, errors.New("jose: EdDSA requires an Ed25519 signer")
		}
		// crypto.Hash(0) signals "sign the message itself" — the only
		// contract ed25519.PrivateKey.Sign accepts (RFC 8032 pure
		// EdDSA has no pre-hash step).
		sig, err := signer.Sign(rand.Reader, signingInput, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("jose: sign: %w", err)
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("jose: unsupported algorithm %q", alg)
	}
}

// Verify parses and verifies a compact JWS, checking that its "alg"
// header matches alg and that its signature validates under pub. It
// returns the decoded header and payload. It rejects a compact string
// larger than MaxCompactBytes; use VerifyMax for a caller that needs a
// different ceiling.
//
// alg must come from the caller — resolved independently of this
// token's own header, e.g. from a trust-anchored certificate's own key
// type — never read back out of the very header being verified. That,
// plus verifyBytes' own per-algorithm type check on pub, is what
// prevents an algorithm-confusion attack: a caller that instead let
// the token's own "alg" claim pick which verification path to run
// would let an attacker choose a weaker algorithm for a key that was
// only ever vetted under a stronger one.
func Verify(alg Alg, pub crypto.PublicKey, compact string) (header map[string]any, payload []byte, err error) {
	return VerifyMax(alg, pub, compact, MaxCompactBytes)
}

// VerifyMax is Verify with an explicit size ceiling, in bytes, instead
// of MaxCompactBytes.
func VerifyMax(alg Alg, pub crypto.PublicKey, compact string, maxBytes int) (header map[string]any, payload []byte, err error) {
	if len(compact) > maxBytes {
		return nil, nil, fmt.Errorf("jose: compact JWS is %d bytes, exceeds the %d byte limit", len(compact), maxBytes)
	}
	h, encPayload, encSig, err := split(compact)
	if err != nil {
		return nil, nil, err
	}
	header, err = decodeHeader(h)
	if err != nil {
		return nil, nil, err
	}
	if hdrAlg, _ := header["alg"].(string); hdrAlg != string(alg) {
		return nil, nil, fmt.Errorf("jose: header alg %q does not match expected %q", hdrAlg, alg)
	}
	payload, err = b64.DecodeString(encPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("jose: decode payload: %w", err)
	}
	sig, err := b64.DecodeString(encSig)
	if err != nil {
		return nil, nil, fmt.Errorf("jose: decode signature: %w", err)
	}
	signingInput := []byte(h + "." + encPayload)
	if err := verifyBytes(alg, pub, signingInput, sig); err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}

// DecodeUnverified decodes a compact JWS's header and payload without
// checking its signature — for a caller that needs to read claims (an
// "iss", a "kid", an x5c chain) in order to resolve which key to verify
// with in the first place. Verify (or a direct call to Verify once the
// key is known) must still be used before the payload is trusted. It
// rejects a compact string larger than MaxCompactBytes; use
// DecodeUnverifiedMax for a caller that needs a different ceiling.
func DecodeUnverified(compact string) (header map[string]any, payload []byte, err error) {
	return DecodeUnverifiedMax(compact, MaxCompactBytes)
}

// DecodeUnverifiedMax is DecodeUnverified with an explicit size
// ceiling, in bytes, instead of MaxCompactBytes.
func DecodeUnverifiedMax(compact string, maxBytes int) (header map[string]any, payload []byte, err error) {
	if len(compact) > maxBytes {
		return nil, nil, fmt.Errorf("jose: compact JWS is %d bytes, exceeds the %d byte limit", len(compact), maxBytes)
	}
	h, encPayload, _, err := split(compact)
	if err != nil {
		return nil, nil, err
	}
	header, err = decodeHeader(h)
	if err != nil {
		return nil, nil, err
	}
	payload, err = b64.DecodeString(encPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("jose: decode payload: %w", err)
	}
	return header, payload, nil
}

func split(compact string) (header, payload, sig string, err error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("jose: not a compact JWS (expected 3 parts, got %d)", len(parts))
	}
	return parts[0], parts[1], parts[2], nil
}

func decodeHeader(encHeader string) (map[string]any, error) {
	raw, err := b64.DecodeString(encHeader)
	if err != nil {
		return nil, fmt.Errorf("jose: decode header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("jose: unmarshal header: %w", err)
	}
	// "crit" (RFC 7515 §4.1.11) names header parameters a receiver
	// MUST understand and process, rejecting the JWS otherwise. This
	// package recognizes no critical extension at all — no HAIP/
	// OID4VCI/OID4VP profile it implements ever requires one, and no
	// signer in this repo ever sets "crit" — so any non-empty "crit"
	// on an incoming JWS is, by construction, naming something this
	// package doesn't understand, and rejection is unconditional
	// rather than needing a caller-supplied "understood" set.
	if crit, ok := header["crit"]; ok {
		if arr, ok := crit.([]any); !ok || len(arr) > 0 {
			return nil, fmt.Errorf("jose: JWS names a critical header extension this package does not understand: %v", crit)
		}
	}
	return header, nil
}

func verifyBytes(alg Alg, pub crypto.PublicKey, signingInput, sig []byte) error {
	switch alg {
	case ES256:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != elliptic.P256() {
			return errors.New("jose: ES256 requires a P-256 public key")
		}
		der, err := ecdsafixed.ToDER(sig, 32)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(signingInput)
		if !ecdsa.VerifyASN1(ecPub, digest[:], der) {
			return errors.New("jose: ES256 signature verification failed")
		}
		return nil
	case EdDSA:
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("jose: EdDSA requires an Ed25519 public key")
		}
		if !ed25519.Verify(edPub, signingInput, sig) {
			return errors.New("jose: EdDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("jose: unsupported algorithm %q", alg)
	}
}
