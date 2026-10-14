package statuslist

import (
	"encoding/base64"
	"fmt"
)

// StatusList is the JSON-encoded Status List structure (draft-14
// §4.2): a bit-packed, ZLIB-compressed array of Referenced Token
// statuses.
type StatusList struct {
	Bits Bits `json:"bits"`

	// Lst is the base64url-encoded compressed byte array (draft-14
	// §4.1). Build it with New rather than by hand.
	Lst string `json:"lst"`

	AggregationURI string `json:"aggregation_uri,omitempty"`
}

// New packs and compresses statuses into a StatusList (draft-14 §4.1).
// statuses[i] is the status of the Referenced Token at index i.
func New(bits Bits, statuses []uint8, aggregationURI string) (StatusList, error) {
	packed, err := Pack(bits, statuses)
	if err != nil {
		return StatusList{}, err
	}
	compressed, err := compress(packed)
	if err != nil {
		return StatusList{}, err
	}
	return StatusList{
		Bits:           bits,
		Lst:            base64.RawURLEncoding.EncodeToString(compressed),
		AggregationURI: aggregationURI,
	}, nil
}

// Decoded is a StatusList with its byte array already decompressed,
// for checking more than one index without repeating decompression.
type Decoded struct {
	Bits   Bits
	Packed []byte
}

// Decode base64url-decodes and decompresses sl's Lst (draft-14 §8.3
// step 5).
func (sl StatusList) Decode() (Decoded, error) {
	if !sl.Bits.valid() {
		return Decoded{}, fmt.Errorf("statuslist: invalid bits value %d (must be 1, 2, 4 or 8)", sl.Bits)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sl.Lst)
	if err != nil {
		return Decoded{}, fmt.Errorf("statuslist: decode lst: %w", err)
	}
	packed, err := decompress(raw)
	if err != nil {
		return Decoded{}, err
	}
	return Decoded{Bits: sl.Bits, Packed: packed}, nil
}

// Status returns the status at idx.
func (d Decoded) Status(idx int) (uint8, error) {
	return Unpack(d.Bits, d.Packed, idx)
}

// Status returns the status at idx (draft-14 §8.3 steps 5-6),
// decompressing sl only as far as the byte holding it, in constant
// memory: a list whose
// compressed form is small can inflate to far more than the one entry
// needs (a 173 KB token to 128 MiB), so reading the whole list to check
// one Referenced Token would let a status list cost its reader that
// much memory. Prefer Decode when checking more than one index, to
// avoid repeating the decompression.
func (sl StatusList) Status(idx int) (uint8, error) {
	if !sl.Bits.valid() {
		return 0, fmt.Errorf("statuslist: invalid bits value %d (must be 1, 2, 4 or 8)", sl.Bits)
	}
	if idx < 0 {
		return 0, fmt.Errorf("statuslist: negative index %d", idx)
	}
	byteIdx := idx / sl.Bits.perByte()
	if byteIdx >= maxDecompressedSize {
		return 0, fmt.Errorf("statuslist: index %d is out of bounds", idx)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sl.Lst)
	if err != nil {
		return 0, fmt.Errorf("statuslist: decode lst: %w", err)
	}
	b, ok, err := decompressedByte(raw, byteIdx)
	switch {
	case err != nil:
		return 0, err
	case !ok:
		return 0, fmt.Errorf("statuslist: index %d is out of bounds", idx)
	}
	return (b >> (uint(idx%sl.Bits.perByte()) * uint(sl.Bits))) & sl.Bits.mask(), nil
}
