package certchain

import (
	"crypto/x509"
	"reflect"
)

// LeafPolicy is a leaf certificate policy: the chain-verified leaf and
// its verified paths (leaf first), as the library's LeafPolicy fields
// take them.
type LeafPolicy = func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

// nonSeparating are the code pointers of the library's exported leaf
// policies that can't tell one role's certificates from another's:
// the opt-outs that accept every leaf (verifier.AnyIssuerLeaf,
// registration.AnyRegistrarLeaf, ...) and the defaults that refuse
// only a certificate whose key usage clearly denotes another role
// (verifier.DefaultSDJWTIssuerLeafPolicy, ...), which accept two
// roles' certificates alike when neither carries an extended key
// usage. Each defining package adds its own in an init function, so
// the set is complete before any caller reads it, and is only read
// afterwards.
var nonSeparating = map[uintptr]struct{}{}

// RegisterNonSeparating records policy, an exported top-level function
// of the calling package, as one of the library's leaf policies that
// don't tell roles apart (see SeparatesRoles). Call it only from an
// init function.
func RegisterNonSeparating(policy LeafPolicy) {
	nonSeparating[reflect.ValueOf(policy).Pointer()] = struct{}{}
}

// SeparatesRoles reports whether policy may tell one role's
// certificates from another's under a trust anchor both share: false
// for nil and for the library's policies registered with
// RegisterNonSeparating, true for any other policy. It recognises a
// registered policy by its function's code pointer, so only the
// registered functions themselves (or a variable holding one): a
// closure or another function that wraps one isn't recognised, and
// counts as a policy that separates roles.
func SeparatesRoles(policy LeafPolicy) bool {
	if policy == nil {
		return false
	}
	_, registered := nonSeparating[reflect.ValueOf(policy).Pointer()]
	return !registered
}
