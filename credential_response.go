package oid4vci

// IssuedCredential is one element of a Credential Response's
// "credentials" array (§8.3).
type IssuedCredential struct {
	// Credential is the issued Credential, encoded per its format's own
	// Credential Format Profile (Appendix A): the compact SD-JWT VC
	// string for credential/sdjwtvc's own CredentialFormat, or the
	// base64url-encoded CBOR IssuerSigned structure for
	// credential/mdoc's own CredentialFormat.
	Credential string `json:"credential"`
}

// CredentialResponse is a Credential Response (§8.3) for the immediate
// issuance case. The deferred-at-first-response case (transaction_id/
// interval, in place of credentials) is not modeled here — see each
// role package's own doc comment for whether/how that's handled.
type CredentialResponse struct {
	Credentials []IssuedCredential `json:"credentials"`

	// NotificationID is OPTIONAL: identifies this issuance flow for a
	// later Notification Request (§11.1). Absent unless the Credential
	// Issuer actually supports the Notification Endpoint.
	NotificationID string `json:"notification_id,omitempty"`
}
