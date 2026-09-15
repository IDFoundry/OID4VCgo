package jwe

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// concatKDF implements the Concat KDF (NIST SP 800-56A §5.8.1) as
// profiled by RFC 7518 §4.6.2 for ECDH-ES Direct Key Agreement: z is
// the ECDH shared secret, enc is the AlgorithmID ("the octets of the
// ASCII representation of the enc Header Parameter value", per §4.6.2,
// for Direct Key Agreement specifically), and keyLen is the number of
// output bytes to derive. PartyUInfo/PartyVInfo (apu/apv) are always
// empty — see the package doc comment for why.
//
// This only ever performs a single SHA-256 round: reps =
// ceil(keydatalen / hashlen) is 1 for every keyLen this package's own
// Enc values need (16/24/32 bytes, against a 32-byte SHA-256 output),
// so the multi-round case NIST SP 800-56A defines is deliberately not
// implemented — it would be unreachable with this package's own Enc
// set, and adding it untested is worse than not having it.
func concatKDF(z []byte, enc string, keyLen int) ([]byte, error) {
	if keyLen > sha256.Size {
		return nil, fmt.Errorf("jwe: concat kdf: requested key length %d exceeds one round (%d); multi-round Concat KDF is not implemented", keyLen, sha256.Size)
	}

	otherInfo := new(bytes.Buffer)
	writeLengthPrefixed(otherInfo, []byte(enc)) // AlgorithmID
	writeLengthPrefixed(otherInfo, nil)         // PartyUInfo (apu absent)
	writeLengthPrefixed(otherInfo, nil)         // PartyVInfo (apv absent)
	// SuppPubInfo: keydatalen, in bits, as a fixed 4-byte big-endian
	// integer (not itself length-prefixed — SP 800-56A gives it a
	// known, fixed size).
	var suppPubInfo [4]byte
	binary.BigEndian.PutUint32(suppPubInfo[:], uint32(keyLen)*8) //nolint:gosec // keyLen is one of 16/24/32, never near overflow
	otherInfo.Write(suppPubInfo[:])
	// SuppPrivInfo is the empty octet string.

	h := sha256.New()
	h.Write([]byte{0, 0, 0, 1}) // reps == 1, so the counter is always 1.
	h.Write(z)
	h.Write(otherInfo.Bytes())
	return h.Sum(nil)[:keyLen], nil
}

func writeLengthPrefixed(buf *bytes.Buffer, data []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data))) //nolint:gosec // data is always a short protocol identifier, never near overflow
	buf.Write(length[:])
	buf.Write(data)
}
