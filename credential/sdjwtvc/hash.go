package sdjwtvc

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/idfoundry/oid4vcgo/internal/b64url"
)

// b64 is RFC 7515 §2 base64url: any byte outside its alphabet, line
// breaks included, and non-zero trailing bits (RFC 4648 §3.5) are
// refused, so one value has one encoding.
var b64 b64url.Encoding

// HashAlg identifies the hash algorithm used for Disclosure digests
// (RFC 9901 §4.1.1). Values are the "Hash Name String" from the IANA
// Named Information Hash Algorithm Registry that §4.1.1 requires.
type HashAlg string

const (
	// SHA256 is the default and the only hash algorithm every base
	// SD-JWT implementation MUST support (RFC 9901 §4.1.1).
	SHA256 HashAlg = "sha-256"
	SHA384 HashAlg = "sha-384"
	SHA512 HashAlg = "sha-512"
)

// DefaultHashAlg is used when a payload omits _sd_alg (RFC 9901 §4.1.1).
const DefaultHashAlg = SHA256

func newHash(alg HashAlg) (hash.Hash, error) {
	switch alg {
	case SHA256:
		return sha256.New(), nil
	case SHA384:
		return sha512.New384(), nil
	case SHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("sdjwtvc: unsupported hash algorithm %q", alg)
	}
}

// hashString computes the base64url digest of s under alg. Used both
// for a Disclosure's digest (RFC 9901 §4.2.3, where s is the
// base64url-encoded Disclosure — "the digest MUST be computed over the
// US-ASCII bytes of the base64url-encoded value that is the
// Disclosure") and for a Key Binding JWT's sd_hash (§4.3.1, where s is
// the concatenated Issuer-signed JWT and presented Disclosures) — both
// are "hash these US-ASCII bytes" with no other difference.
func hashString(alg HashAlg, s string) (string, error) {
	h, err := newHash(alg)
	if err != nil {
		return "", err
	}
	h.Write([]byte(s))
	return b64.EncodeToString(h.Sum(nil)), nil
}

// PayloadHashAlg is the hash algorithm an Issuer-signed JWT's payload
// declares in "_sd_alg", or fallback when it has none (RFC 9901
// §4.1.1: "the value MUST be a case-sensitive string"). A non-string
// _sd_alg is an error, not the fallback: it would otherwise resolve the
// disclosures under an algorithm the issuer didn't declare.
func PayloadHashAlg(payload map[string]any, fallback HashAlg) (HashAlg, error) {
	raw, present := payload["_sd_alg"]
	if !present {
		return fallback, nil
	}
	declared, ok := raw.(string)
	if !ok || declared == "" {
		return "", fmt.Errorf("sdjwtvc: _sd_alg must be a non-empty string, got %T", raw)
	}
	return HashAlg(declared), nil
}
