package ecdsafixed

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// signature is the ASN.1 DER structure Go's crypto.Signer produces for
// an ECDSA key.
type signature struct {
	R, S *big.Int
}

// ToFixed converts a DER-encoded ECDSA signature to size-byte-per-value
// big-endian R||S form.
func ToFixed(der []byte, size int) ([]byte, error) {
	var sig signature
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("ecdsafixed: parse ECDSA signature: %w", err)
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// ToDER converts a fixed-width big-endian R||S ECDSA signature (2*size
// bytes) to ASN.1 DER form.
func ToDER(fixed []byte, size int) ([]byte, error) {
	if len(fixed) != 2*size {
		return nil, fmt.Errorf("ecdsafixed: signature has length %d, want %d", len(fixed), 2*size)
	}
	r := new(big.Int).SetBytes(fixed[:size])
	s := new(big.Int).SetBytes(fixed[size:])
	return asn1.Marshal(signature{R: r, S: s})
}
