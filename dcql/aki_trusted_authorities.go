package dcql

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// AKITrustedAuthorities builds the "aki" TrustedAuthoritiesQuery
// (§6.1.1.1, the type HAIP 1.0 §5 requires) naming cas: each value is a
// CA's Subject Key Identifier, base64url-encoded — what an issuer
// certificate that CA signed carries as its Authority Key Identifier,
// and what AKITrustedAuthoritiesChecker matches. A CA without a Subject
// Key Identifier can't be named this way and is an error.
func AKITrustedAuthorities(cas ...*x509.Certificate) (TrustedAuthoritiesQuery, error) {
	if len(cas) == 0 {
		return TrustedAuthoritiesQuery{}, errors.New("dcql: aki trusted authorities: at least one CA certificate is required")
	}
	values := make([]string, 0, len(cas))
	for _, ca := range cas {
		if ca == nil || len(ca.SubjectKeyId) == 0 {
			name := "<nil>"
			if ca != nil {
				name = ca.Subject.String()
			}
			return TrustedAuthoritiesQuery{}, fmt.Errorf("dcql: aki trusted authorities: CA %q has no Subject Key Identifier", name)
		}
		values = append(values, base64.RawURLEncoding.EncodeToString(ca.SubjectKeyId))
	}
	return TrustedAuthoritiesQuery{Type: TrustedAuthorityAKI, Values: values}, nil
}
