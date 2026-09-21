package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
	"github.com/idfoundry/oid4vcgo/internal/ecdsafixed"
)

// Alg identifies a COSE algorithm this package supports, by its IANA
// COSE Algorithms registry value (RFC 9053) — HMAC256 (mac0.go) is
// also one of these, drawn from the same registry as the signature
// algorithms below.
type Alg int64

const (
	// ES256 is ECDSA using P-256 and SHA-256 (RFC 9053 §2.1).
	ES256 Alg = -7

	// EdDSA is pure EdDSA over Ed25519 (RFC 9053 §2.2) — the digest
	// parameter Sign/Verify take is the raw signing input, not a
	// pre-hash, since Ed25519 signs the message itself.
	EdDSA Alg = -8
)

// IsSupportedSigningAlg reports whether alg is one Sign1/Verify
// actually implement for signing — the same set they switch on.
// Named distinctly from a plain IsSupported since Alg's own doc
// comment includes HMAC256 (mac0.go) too, a MAC algorithm this
// function deliberately excludes: it answers "is this usable as a
// Sign1 signing algorithm," not "is this any algorithm this package
// knows about at all." Mirrors internal/jose.IsSupported's own role —
// see that function's own doc comment for why a construction-time
// check like MdocSigner.validate's needs this instead of relying on
// Sign1/Verify's own switch to catch an unsupported value.
func IsSupportedSigningAlg(alg Alg) bool {
	switch alg {
	case ES256, EdDSA:
		return true
	default:
		return false
	}
}

// RFC 9052 §3.1 common header parameter labels, plus RFC 9360 §2's
// x5chain and RFC 9596's typ — the only ones this package models.
const (
	labelAlg     = 1
	labelKID     = 4
	labelTyp     = 16
	labelX5Chain = 33
)

// Headers holds the COSE header parameters this package knows about.
// Sign and Verify pass protected and unprotected buckets separately,
// since which bucket a given parameter belongs in is meaningful (mdoc's
// IssuerAuth carries "alg" protected and "x5chain" unprotected).
type Headers struct {
	// Alg is header label 1. Sign always sets this in the protected
	// bucket itself, overwriting whatever the caller supplied there.
	Alg Alg

	// KID is header label 4, or nil if absent.
	KID []byte

	// Typ is header label 16 (RFC 9596), a content-type string
	// identifying the type of the signed payload — e.g.
	// "application/statuslist+cwt". Empty if absent. RFC 9596 also
	// permits an integer CoAP Content-Format ID; this package only
	// models the text-string form.
	Typ string

	// X5Chain is header label 33 (RFC 9360 §2): the signer's
	// certificate followed by any intermediates, leaf first. nil if
	// absent. A single-certificate chain is encoded as a bare byte
	// string on the wire, matching RFC 9360's own encoding rule.
	X5Chain [][]byte
}

func (h Headers) toMap() map[int]interface{} {
	m := make(map[int]interface{})
	if h.Alg != 0 {
		m[labelAlg] = int64(h.Alg)
	}
	if h.KID != nil {
		m[labelKID] = h.KID
	}
	if h.Typ != "" {
		m[labelTyp] = h.Typ
	}
	switch len(h.X5Chain) {
	case 0:
	case 1:
		m[labelX5Chain] = h.X5Chain[0]
	default:
		m[labelX5Chain] = h.X5Chain
	}
	return m
}

func headersFromMap(m map[int]interface{}) (Headers, error) {
	var h Headers
	if v, ok := m[labelAlg]; ok {
		i, err := toInt64(v)
		if err != nil {
			return Headers{}, fmt.Errorf("cose: alg header: %w", err)
		}
		h.Alg = Alg(i)
	}
	if v, ok := m[labelKID]; ok {
		b, ok := v.([]byte)
		if !ok {
			return Headers{}, errors.New("cose: kid header is not a byte string")
		}
		h.KID = b
	}
	if v, ok := m[labelTyp]; ok {
		s, ok := v.(string)
		if !ok {
			return Headers{}, errors.New("cose: typ header is not a text string")
		}
		h.Typ = s
	}
	if v, ok := m[labelX5Chain]; ok {
		chain, err := x5ChainFromValue(v)
		if err != nil {
			return Headers{}, err
		}
		h.X5Chain = chain
	}
	return h, nil
}

func x5ChainFromValue(v interface{}) ([][]byte, error) {
	switch vv := v.(type) {
	case []byte:
		return [][]byte{vv}, nil
	case []interface{}:
		chain := make([][]byte, len(vv))
		for i, item := range vv {
			b, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("cose: x5chain entry %d is not a byte string", i)
			}
			chain[i] = b
		}
		return chain, nil
	default:
		return nil, fmt.Errorf("cose: x5chain header has unexpected type %T", v)
	}
}

func toInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case uint64:
		// A header value this large can't be a real registered COSE
		// algorithm (RFC 9053's registry tops out in the low
		// thousands), and this is untrusted input — DecodeUnverified
		// reads it before any signature check — so reject it outright
		// rather than silently wrapping it into a negative int64.
		if n > math.MaxInt64 {
			return 0, fmt.Errorf("integer %d overflows int64", n)
		}
		return int64(n), nil
	default:
		return 0, fmt.Errorf("expected an integer, got %T", v)
	}
}

// rawSign1 is the wire shape of an untagged COSE_Sign1 (RFC 9052 §4.2):
// [protected: bstr .cbor header_map, unprotected: header_map, payload:
// bstr, signature: bstr].
type rawSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int]interface{}
	Payload     []byte
	Signature   []byte
}

// sigStructure is RFC 9052 §4.4's Sig_structure for a COSE_Sign1: the
// actual bytes a signature is computed and verified over.
type sigStructure struct {
	_             struct{} `cbor:",toarray"`
	Context       string
	BodyProtected []byte
	ExternalAAD   []byte
	Payload       []byte
}

// MaxBytes bounds how large a COSE_Sign1/COSE_Sign1_Tagged/COSE_Mac0
// structure Verify/VerifyDetached/DecodeUnverified/VerifyTagged/
// DecodeUnverifiedTagged/VerifyMAC will attempt to parse, to avoid
// doing unbounded CBOR-unmarshal work on attacker-supplied bytes
// before any signature/MAC has been checked (Verify/VerifyMAC) — or
// without one ever being checked at all (DecodeUnverified/
// DecodeUnverifiedTagged, whose whole point is reading headers, e.g.
// an x5chain, before the verifying key is even known). Matches
// internal/jose.MaxCompactBytes's own value and reasoning, ported here
// once a real caller (verifier.verifyMdocPresentation/wallet's own
// mdoc match path, both calling DecodeUnverified on wallet-controlled
// bytes) needed the identical protection this package never had — a
// gap found in a repo-wide security review. A caller whose accepted
// input can legitimately scale beyond it should call one of this
// package's own *Max variants with its own configured ceiling instead.
const MaxBytes = 1 << 16 // 64 KiB

var encMode = mustEncMode()

func mustEncMode() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("cose: build canonical CBOR encoder: %v", err))
	}
	return mode
}

// Sign builds an untagged COSE_Sign1 structure (RFC 9052 §4.2) over
// payload, using signer under alg. protected and unprotected carry any
// extra header parameters this package models; Sign always sets Alg in
// the protected bucket, overwriting whatever protected.Alg was set to.
// externalAAD is authenticated but not transported (§4.3) — pass nil if
// the caller has none. payload must not be nil (COSE's detached-payload
// form isn't supported).
func Sign(alg Alg, signer crypto.Signer, protected, unprotected Headers, payload, externalAAD []byte) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("cose: payload must not be nil")
	}
	return signSign1(alg, signer, protected, unprotected, payload, externalAAD, payload)
}

// SignDetached is Sign, but for a detached payload (RFC 9052 §4.2): the
// wire COSE_Sign1's payload field is CBOR null, and detachedPayload is
// never embedded — the caller must convey it out of band. mdoc's
// DeviceSignature (ISO/IEC 18013-5 §12.4.6) uses this form.
func SignDetached(alg Alg, signer crypto.Signer, protected, unprotected Headers, detachedPayload, externalAAD []byte) ([]byte, error) {
	if detachedPayload == nil {
		return nil, errors.New("cose: detachedPayload must not be nil")
	}
	return signSign1(alg, signer, protected, unprotected, nil, externalAAD, detachedPayload)
}

// signSign1 is Sign/SignDetached's shared core. wirePayload is what's
// embedded in the wire COSE_Sign1's payload field (the payload itself,
// or nil for a detached signature); sigPayload is always the actual
// payload bytes, used to compute Sig_structure regardless of whether
// it ends up embedded.
func signSign1(alg Alg, signer crypto.Signer, protected, unprotected Headers, wirePayload, externalAAD, sigPayload []byte) ([]byte, error) {
	protected.Alg = alg
	protectedBytes, err := encMode.Marshal(protected.toMap())
	if err != nil {
		return nil, fmt.Errorf("cose: marshal protected headers: %w", err)
	}

	toSign, err := encMode.Marshal(sigStructure{
		Context:       "Signature1",
		BodyProtected: protectedBytes,
		ExternalAAD:   nonNil(externalAAD),
		Payload:       sigPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("cose: marshal Sig_structure: %w", err)
	}

	sig, err := signBytes(alg, signer, toSign)
	if err != nil {
		return nil, err
	}

	sign1, err := encMode.Marshal(rawSign1{
		Protected:   protectedBytes,
		Unprotected: unprotected.toMap(),
		Payload:     wirePayload,
		Signature:   sig,
	})
	if err != nil {
		return nil, fmt.Errorf("cose: marshal COSE_Sign1: %w", err)
	}
	return sign1, nil
}

// Verify parses and verifies an untagged COSE_Sign1 structure, checking
// that its protected "alg" header matches alg and that its signature
// validates under pub. It returns the decoded protected and unprotected
// headers and the payload. It rejects a sign1 larger than MaxBytes; use
// VerifyMax for a caller that needs a different ceiling.
func Verify(alg Alg, pub crypto.PublicKey, sign1, externalAAD []byte) (protected, unprotected Headers, payload []byte, err error) {
	return VerifyMax(alg, pub, sign1, externalAAD, MaxBytes)
}

// VerifyMax is Verify with an explicit size ceiling, in bytes, instead
// of MaxBytes.
func VerifyMax(alg Alg, pub crypto.PublicKey, sign1, externalAAD []byte, maxBytes int) (protected, unprotected Headers, payload []byte, err error) {
	raw, err := decodeRaw(sign1, maxBytes)
	if err != nil {
		return Headers{}, Headers{}, nil, err
	}
	if raw.Payload == nil {
		return Headers{}, Headers{}, nil, errors.New("cose: COSE_Sign1 has a detached (null) payload; use VerifyDetached")
	}
	protected, unprotected, err = verifySign1(alg, pub, raw, externalAAD, raw.Payload)
	if err != nil {
		return Headers{}, Headers{}, nil, err
	}
	return protected, unprotected, raw.Payload, nil
}

// VerifyDetached is Verify, but expects sign1 to have a detached
// (null) payload (see SignDetached) — the caller supplies the same
// detachedPayload bytes used to produce it. It rejects a sign1 larger
// than MaxBytes; use VerifyDetachedMax for a caller that needs a
// different ceiling.
func VerifyDetached(alg Alg, pub crypto.PublicKey, sign1, detachedPayload, externalAAD []byte) (protected, unprotected Headers, err error) {
	return VerifyDetachedMax(alg, pub, sign1, detachedPayload, externalAAD, MaxBytes)
}

// VerifyDetachedMax is VerifyDetached with an explicit size ceiling, in
// bytes, instead of MaxBytes.
func VerifyDetachedMax(alg Alg, pub crypto.PublicKey, sign1, detachedPayload, externalAAD []byte, maxBytes int) (protected, unprotected Headers, err error) {
	raw, err := decodeRaw(sign1, maxBytes)
	if err != nil {
		return Headers{}, Headers{}, err
	}
	if raw.Payload != nil {
		return Headers{}, Headers{}, errors.New("cose: COSE_Sign1 has an embedded payload; use Verify")
	}
	return verifySign1(alg, pub, raw, externalAAD, detachedPayload)
}

// verifySign1 is Verify/VerifyDetached's shared core: sigPayload is
// always the actual payload bytes Sig_structure is computed over,
// whether they came embedded in raw or were supplied out of band.
func verifySign1(alg Alg, pub crypto.PublicKey, raw rawSign1, externalAAD, sigPayload []byte) (protected, unprotected Headers, err error) {
	protected, unprotected, err = raw.headers()
	if err != nil {
		return Headers{}, Headers{}, err
	}
	if protected.Alg != alg {
		return Headers{}, Headers{}, fmt.Errorf("cose: protected alg %d does not match expected %d", protected.Alg, alg)
	}

	toVerify, err := encMode.Marshal(sigStructure{
		Context:       "Signature1",
		BodyProtected: raw.Protected,
		ExternalAAD:   nonNil(externalAAD),
		Payload:       sigPayload,
	})
	if err != nil {
		return Headers{}, Headers{}, fmt.Errorf("cose: marshal Sig_structure: %w", err)
	}
	if err := verifyBytes(alg, pub, toVerify, raw.Signature); err != nil {
		return Headers{}, Headers{}, err
	}
	return protected, unprotected, nil
}

// DecodeUnverified decodes an untagged COSE_Sign1's headers and payload
// without checking its signature — for a caller that needs to read the
// unprotected x5chain (or another header) to resolve which key to
// verify with in the first place. Verify (or a direct call to Verify
// once the key is known) must still be used before the payload is
// trusted. It rejects a sign1 larger than MaxBytes; use
// DecodeUnverifiedMax for a caller that needs a different ceiling.
func DecodeUnverified(sign1 []byte) (protected, unprotected Headers, payload []byte, err error) {
	return DecodeUnverifiedMax(sign1, MaxBytes)
}

// DecodeUnverifiedMax is DecodeUnverified with an explicit size
// ceiling, in bytes, instead of MaxBytes.
func DecodeUnverifiedMax(sign1 []byte, maxBytes int) (protected, unprotected Headers, payload []byte, err error) {
	raw, err := decodeRaw(sign1, maxBytes)
	if err != nil {
		return Headers{}, Headers{}, nil, err
	}
	protected, unprotected, err = raw.headers()
	if err != nil {
		return Headers{}, Headers{}, nil, err
	}
	return protected, unprotected, raw.Payload, nil
}

func decodeRaw(sign1 []byte, maxBytes int) (rawSign1, error) {
	if len(sign1) > maxBytes {
		return rawSign1{}, fmt.Errorf("cose: COSE_Sign1 is %d bytes, exceeds the %d byte limit", len(sign1), maxBytes)
	}
	var raw rawSign1
	if err := cbor.Unmarshal(sign1, &raw); err != nil {
		return rawSign1{}, fmt.Errorf("cose: unmarshal COSE_Sign1: %w", err)
	}
	return raw, nil
}

// sign1Tag is COSE_Sign1_Tagged's own tag number (RFC 9052 §4.2:
// COSE_Sign1_Tagged = #6.18(COSE_Sign1)).
const sign1Tag = 18

// SignTagged is Sign, but wraps the result as COSE_Sign1_Tagged
// (#6.18(COSE_Sign1)) instead of a bare untagged array — for a context
// that doesn't otherwise establish the bytes are a COSE_Sign1.
func SignTagged(alg Alg, signer crypto.Signer, protected, unprotected Headers, payload, externalAAD []byte) ([]byte, error) {
	untagged, err := Sign(alg, signer, protected, unprotected, payload, externalAAD)
	if err != nil {
		return nil, err
	}
	tagged, err := cbor.Marshal(cbor.RawTag{Number: sign1Tag, Content: cbor.RawMessage(untagged)})
	if err != nil {
		return nil, fmt.Errorf("cose: wrap tag %d: %w", sign1Tag, err)
	}
	return tagged, nil
}

// VerifyTagged is Verify, but expects sign1 to be COSE_Sign1_Tagged
// (see SignTagged) rather than a bare untagged array. It rejects a
// sign1 larger than MaxBytes; use VerifyTaggedMax for a caller that
// needs a different ceiling.
func VerifyTagged(alg Alg, pub crypto.PublicKey, sign1, externalAAD []byte) (protected, unprotected Headers, payload []byte, err error) {
	return VerifyTaggedMax(alg, pub, sign1, externalAAD, MaxBytes)
}

// VerifyTaggedMax is VerifyTagged with an explicit size ceiling, in
// bytes, instead of MaxBytes.
func VerifyTaggedMax(alg Alg, pub crypto.PublicKey, sign1, externalAAD []byte, maxBytes int) (protected, unprotected Headers, payload []byte, err error) {
	untagged, err := stripSign1Tag(sign1, maxBytes)
	if err != nil {
		return Headers{}, Headers{}, nil, err
	}
	return VerifyMax(alg, pub, untagged, externalAAD, maxBytes)
}

// DecodeUnverifiedTagged is DecodeUnverified, but for
// COSE_Sign1_Tagged input (see SignTagged). It rejects a sign1 larger
// than MaxBytes; use DecodeUnverifiedTaggedMax for a caller that needs
// a different ceiling.
func DecodeUnverifiedTagged(sign1 []byte) (protected, unprotected Headers, payload []byte, err error) {
	return DecodeUnverifiedTaggedMax(sign1, MaxBytes)
}

// DecodeUnverifiedTaggedMax is DecodeUnverifiedTagged with an explicit
// size ceiling, in bytes, instead of MaxBytes.
func DecodeUnverifiedTaggedMax(sign1 []byte, maxBytes int) (protected, unprotected Headers, payload []byte, err error) {
	untagged, err := stripSign1Tag(sign1, maxBytes)
	if err != nil {
		return Headers{}, Headers{}, nil, err
	}
	return DecodeUnverifiedMax(untagged, maxBytes)
}

func stripSign1Tag(sign1 []byte, maxBytes int) ([]byte, error) {
	if len(sign1) > maxBytes {
		return nil, fmt.Errorf("cose: COSE_Sign1_Tagged is %d bytes, exceeds the %d byte limit", len(sign1), maxBytes)
	}
	var raw cbor.RawTag
	if err := cbor.Unmarshal(sign1, &raw); err != nil {
		return nil, fmt.Errorf("cose: unmarshal COSE_Sign1_Tagged: %w", err)
	}
	if raw.Number != sign1Tag {
		return nil, fmt.Errorf("cose: expected CBOR tag %d, got %d", sign1Tag, raw.Number)
	}
	return raw.Content, nil
}

func (raw rawSign1) headers() (protected, unprotected Headers, err error) {
	var protectedMap map[int]interface{}
	if err := cbor.Unmarshal(raw.Protected, &protectedMap); err != nil {
		return Headers{}, Headers{}, fmt.Errorf("cose: unmarshal protected headers: %w", err)
	}
	protected, err = headersFromMap(protectedMap)
	if err != nil {
		return Headers{}, Headers{}, err
	}
	unprotected, err = headersFromMap(raw.Unprotected)
	if err != nil {
		return Headers{}, Headers{}, err
	}
	return protected, unprotected, nil
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func signBytes(alg Alg, signer crypto.Signer, toSign []byte) ([]byte, error) {
	switch alg {
	case ES256:
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("cose: ES256 requires a P-256 signer")
		}
		digest := sha256.Sum256(toSign)
		der, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("cose: sign: %w", err)
		}
		return ecdsafixed.ToFixed(der, 32)
	case EdDSA:
		if _, ok := signer.Public().(ed25519.PublicKey); !ok {
			return nil, errors.New("cose: EdDSA requires an Ed25519 signer")
		}
		// crypto.Hash(0) signals "sign the message itself" — the only
		// contract ed25519.PrivateKey.Sign accepts (RFC 8032 pure
		// EdDSA has no pre-hash step).
		sig, err := signer.Sign(rand.Reader, toSign, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("cose: sign: %w", err)
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("cose: unsupported algorithm %d", alg)
	}
}

func verifyBytes(alg Alg, pub crypto.PublicKey, toVerify, sig []byte) error {
	switch alg {
	case ES256:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != elliptic.P256() {
			return errors.New("cose: ES256 requires a P-256 public key")
		}
		der, err := ecdsafixed.ToDER(sig, 32)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(toVerify)
		if !ecdsa.VerifyASN1(ecPub, digest[:], der) {
			return errors.New("cose: ES256 signature verification failed")
		}
		return nil
	case EdDSA:
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("cose: EdDSA requires an Ed25519 public key")
		}
		if !ed25519.Verify(edPub, toVerify, sig) {
			return errors.New("cose: EdDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("cose: unsupported algorithm %d", alg)
	}
}
