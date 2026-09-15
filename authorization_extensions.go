package oid4vci

import "github.com/idfoundry/fapigo/extension"

// IssuerStateExtension declares the issuer_state authorization
// parameter (OID4VCI 1.0 §4.1.1) to fapigo's own extension.Definition
// mechanism — a plain opaque string neither role here interprets, only
// passes through, so there is no Validate beyond the wire-shape/size
// checks extension.Set/a Registry already apply. 2048 bytes is
// generous headroom for a value the spec places no length limit on.
//
// This lives here, not in wallet or issuer, because both sides of the
// Authorization Code Flow need the exact same extension.Definition[string]
// value: wallet's own BuildAuthorizationRequest attaches it to an
// outbound client.BeginAuthorizationRequest via extension.Set, and a
// deployment pairing issuer with a real fapigo/server.Server registers
// it in that Server's own Config.Extensions so a Pushed Authorization
// Request carrying issuer_state isn't rejected as an unregistered
// parameter. Two independently-declared copies of this Definition
// would risk drifting apart (a different Cardinality or MaxBytes on
// each side is a real interop bug, not a cosmetic one) — the same
// "shared public value types only where semantics match" reasoning
// that moved CredentialOffer and friends here.
var IssuerStateExtension = extension.Definition[string]{
	Name:           "issuer_state",
	Cardinality:    extension.Single,
	AllowedSources: extension.SourcePlainParameter | extension.SourceRequestObject,
	MaxBytes:       2048,
}
