package sdjwtvc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// integrityDigestSizes are the digest lengths of the hash algorithms an
// integrity metadata string names (W3C Subresource Integrity §3.5).
var integrityDigestSizes = map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}

// validateIntegrity checks s is an integrity metadata string, as
// vct#integrity, extends#integrity and uri#integrity must be (SD-JWT VC
// draft-13 §7, W3C Subresource Integrity §3.5): one or more
// whitespace-separated sha256-, sha384- or sha512- expressions, each
// the base64 of a digest of that algorithm's length, optionally
// followed by "?" and options.
func validateIntegrity(s string) error {
	exprs := strings.Fields(s)
	if len(exprs) == 0 {
		return errors.New("an integrity metadata string has at least one hash expression")
	}
	for _, expr := range exprs {
		expr, _, _ = strings.Cut(expr, "?")
		alg, value, ok := strings.Cut(expr, "-")
		size, known := integrityDigestSizes[alg]
		if !ok || !known {
			return fmt.Errorf("integrity %q: want sha256-, sha384- or sha512- and a base64 digest", expr)
		}
		digest, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			digest, err = base64.RawStdEncoding.DecodeString(value)
		}
		if err != nil || len(digest) != size {
			return fmt.Errorf("integrity %q: not the base64 of a %d-byte %s digest", expr, size, alg)
		}
	}
	return nil
}
