package oid4vci

// Proof type identifiers (Appendix F). Only the two OID4VCIgo's
// credential formats actually use are defined here — di_vp (W3C VCDM)
// is out of scope; see SPECIFICATIONS.md.
const (
	// ProofTypeJWT is the "jwt" proof type (Appendix F.1): a JWT proves
	// possession of the key the issued Credential is bound to.
	ProofTypeJWT = "jwt"

	// ProofTypeAttestation is the "attestation" proof type (Appendix
	// F.3): a Key Attestation JWT conveys attested keys without itself
	// proving possession of any one of them.
	ProofTypeAttestation = "attestation"
)
