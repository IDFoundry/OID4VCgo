package oid4vci

// AuthorizationDetailsTypeOpenIDCredential is RFC 9396 §5.1.1's own
// authorization details type this specification defines for requesting
// Credential issuance.
const AuthorizationDetailsTypeOpenIDCredential = "openid_credential" //nolint:gosec // an RFC 9396 authorization details type value, not a credential

// AuthorizationDetail is one entry of an "authorization_details" array
// (RFC 9396 §2), for the "openid_credential" type this specification
// defines: §5.1.1's own Authorization/Token Request parameters, echoed
// back with CredentialIdentifiers added per §6.2's own Token Response
// parameter. This is the same wire shape both issuer (resolving
// credential_identifier-based Credential Requests against it, and
// minting fresh entries for ExchangePreAuthorizedCode's own Token
// Response) and wallet (parsing entries out of a Token Response, and
// presenting one of a matched entry's own CredentialIdentifiers values
// in a later Credential Request) need identically — the same "shared
// value types only where semantics match" split CredentialOffer and
// friends already live here for.
type AuthorizationDetail struct {
	// Type is REQUIRED (§5.1.1). This specification's own use of
	// authorization_details always sets it to
	// AuthorizationDetailsTypeOpenIDCredential; an entry with any other
	// Type is a coexisting authorization details type neither role here
	// interprets (§5.1.1's own "Additional authorization_details data
	// fields MAY be defined and used... never considered invalid due to
	// unknown fields") and should simply be skipped.
	Type string `json:"type"`

	// CredentialConfigurationID is REQUIRED (§5.1.1): which Credential
	// Configuration this authorization detail authorizes.
	CredentialConfigurationID string `json:"credential_configuration_id"`

	// CredentialIdentifiers is REQUIRED once an authorization detail is
	// echoed back in a Token Response (§6.2): every credential_identifier
	// value a Credential Request may later present against it. Absent
	// on the Authorization/Token Request's own outbound copy of this
	// same type — a Wallet never sets this itself, only an Authorization
	// Server does, once it decides to support this optional mechanism
	// at all (§6.2's own "MAY do so").
	CredentialIdentifiers []string `json:"credential_identifiers,omitempty"`
}
