package cose

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// HMAC256 is "HMAC 256/256" (HMAC using SHA-256, truncated to 256
// bits — i.e. not truncated at all) (RFC 9053 §3.1) — the only MAC
// algorithm this package supports, since it's the only one mdoc's
// DeviceMac (ISO/IEC 18013-5 §12.4.5) uses.
const HMAC256 Alg = 5

// rawMac0 is the wire shape of an untagged COSE_Mac0 (RFC 9052 §6.2):
// [protected: bstr .cbor header_map, unprotected: header_map, payload:
// bstr, tag: bstr].
type rawMac0 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int]interface{}
	Payload     []byte
	Tag         []byte
}

// macStructure is RFC 9052 §6.3's MAC_structure for a COSE_Mac0: the
// actual bytes a MAC is computed and verified over.
type macStructure struct {
	_             struct{} `cbor:",toarray"`
	Context       string
	BodyProtected []byte
	ExternalAAD   []byte
	Payload       []byte
}

// ComputeMAC computes an untagged COSE_Mac0 (RFC 9052 §6.2)
// authentication tag over a detached payload, using key directly as
// the raw HMAC key — deriving that key (mdoc's EMacKey, via ECDH and
// HKDF) is out of scope for this package, the same "resolving trust is
// the caller's job" split Sign draws. The wire COSE_Mac0's payload
// field is always CBOR null; detachedPayload is never embedded, since
// that's the only form mdoc's DeviceMac uses. protected always carries
// Alg set to HMAC256, overwriting whatever protected.Alg was set to.
func ComputeMAC(key []byte, protected, unprotected Headers, detachedPayload, externalAAD []byte) ([]byte, error) {
	if detachedPayload == nil {
		return nil, errors.New("cose: detachedPayload must not be nil")
	}
	protected.Alg = HMAC256
	protectedBytes, err := encMode.Marshal(protected.toMap())
	if err != nil {
		return nil, fmt.Errorf("cose: marshal protected headers: %w", err)
	}

	toMAC, err := encMode.Marshal(macStructure{
		Context:       "MAC0",
		BodyProtected: protectedBytes,
		ExternalAAD:   nonNil(externalAAD),
		Payload:       detachedPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("cose: marshal MAC_structure: %w", err)
	}

	mac0, err := encMode.Marshal(rawMac0{
		Protected:   protectedBytes,
		Unprotected: unprotected.toMap(),
		Payload:     nil,
		Tag:         computeHMAC(key, toMAC),
	})
	if err != nil {
		return nil, fmt.Errorf("cose: marshal COSE_Mac0: %w", err)
	}
	return mac0, nil
}

// VerifyMAC recomputes mac0's COSE_Mac0 tag over detachedPayload under
// key and checks it matches in constant time, checking that its
// protected "alg" header is HMAC256 along the way. It rejects a mac0
// larger than MaxBytes; use VerifyMACMax for a caller that needs a
// different ceiling.
func VerifyMAC(key []byte, mac0, detachedPayload, externalAAD []byte) (protected, unprotected Headers, err error) {
	return VerifyMACMax(key, mac0, detachedPayload, externalAAD, MaxBytes)
}

// VerifyMACMax is VerifyMAC with an explicit size ceiling, in bytes,
// instead of MaxBytes.
func VerifyMACMax(key []byte, mac0, detachedPayload, externalAAD []byte, maxBytes int) (protected, unprotected Headers, err error) {
	if len(mac0) > maxBytes {
		return Headers{}, Headers{}, fmt.Errorf("cose: COSE_Mac0 is %d bytes, exceeds the %d byte limit", len(mac0), maxBytes)
	}
	var raw rawMac0
	if unmarshalErr := cbor.Unmarshal(mac0, &raw); unmarshalErr != nil {
		return Headers{}, Headers{}, fmt.Errorf("cose: unmarshal COSE_Mac0: %w", unmarshalErr)
	}
	if raw.Payload != nil {
		return Headers{}, Headers{}, errors.New("cose: COSE_Mac0 has an embedded payload, which this package never produces")
	}

	var protectedMap map[int]interface{}
	if unmarshalErr := cbor.Unmarshal(raw.Protected, &protectedMap); unmarshalErr != nil {
		return Headers{}, Headers{}, fmt.Errorf("cose: unmarshal protected headers: %w", unmarshalErr)
	}
	protected, err = headersFromMap(protectedMap)
	if err != nil {
		return Headers{}, Headers{}, err
	}
	if protected.Alg != HMAC256 {
		return Headers{}, Headers{}, fmt.Errorf("cose: protected alg %d does not match expected %d", protected.Alg, HMAC256)
	}
	unprotected, err = headersFromMap(raw.Unprotected)
	if err != nil {
		return Headers{}, Headers{}, err
	}

	toMAC, err := encMode.Marshal(macStructure{
		Context:       "MAC0",
		BodyProtected: raw.Protected,
		ExternalAAD:   nonNil(externalAAD),
		Payload:       detachedPayload,
	})
	if err != nil {
		return Headers{}, Headers{}, fmt.Errorf("cose: marshal MAC_structure: %w", err)
	}
	if !hmac.Equal(computeHMAC(key, toMAC), raw.Tag) {
		return Headers{}, Headers{}, errors.New("cose: COSE_Mac0 tag verification failed")
	}
	return protected, unprotected, nil
}

func computeHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
