// Package haip is the OpenID4VC High Assurance Interoperability
// Profile (HAIP) 1.0 profile layer: recommendations that wire HAIP's
// own specific overrides on top of the protocol-generic role packages
// (issuer, and — once they exist — wallet/verifier), mirroring
// FAPIgo's own server.RecommendedLimits/RecommendedAlgorithms pattern.
//
// Every value here is traceable to a specific HAIP 1.0 section — see
// each function/constant's own doc comment for its citation. Nothing
// here is applied automatically: a caller decides to call
// RecommendedIssuerConfig (or one of its smaller pieces) and to keep
// using its result, the same deliberate opt-in FAPIgo's own presets
// require. Fields issuer.Config/issuer.CredentialConfiguration expose
// that HAIP itself has no specific value to recommend for (an Issuer's
// own identifier and endpoint URLs, a Credential Configuration's own
// Format/VCT/DocType/Scope, and every issuer.Limits duration — none of
// which OID4VCI or HAIP number) are deliberately left out rather than
// padded with an unlabeled guess.
//
// # Status
//
// RecommendedIssuerConfig covers what HAIP 1.0 §7 and §4.5.1 recommend
// for a Credential Configuration's own proof types; RecommendedWalletConfig
// covers HAIP 1.0 §7's same ES256 minimum, the one part of a
// wallet.Config it grounds a specific value for; RecommendedVerifierConfig
// covers HAIP 1.0 §7's ES256 minimum (the Request Object's own signing
// algorithm) and §5's explicit "MUST be supported by Verifiers" pair of
// JWE enc values, the two parts of a verifier.Config it grounds
// specific values for.
package haip
